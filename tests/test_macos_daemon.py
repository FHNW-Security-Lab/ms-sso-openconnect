"""Nonprivileged macOS helper regressions; never opens a VPN or installs files."""
import asyncio
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('macos_daemon_under_test', ROOT / 'frontends/osx/daemon/vpn_daemon.py')
daemon_module = importlib.util.module_from_spec(spec)
sys.path.insert(0, str(ROOT / 'frontends/osx/daemon'))
try:
    spec.loader.exec_module(daemon_module)
finally:
    sys.path.pop(0)


def connection(**options):
    params = {'address': 'vpn.example.test', 'protocol': 'anyconnect',
              'cookies': {'webvpn': 'private-session'}, 'connection_name': 'Example'}
    params.update(options)
    return params


class Process:
    def __init__(self, output=b'Connected as 10.0.0.1, using SSL\n', exit_status=None):
        self.stdout = io.BytesIO(output)
        self.exit_status = exit_status
        self.pid = 12345
        self.signals = []

    def poll(self):
        return self.exit_status

    def send_signal(self, signum):
        self.signals.append(signum)
        self.exit_status = 0

    def wait(self, timeout=None):
        return self.exit_status


class DaemonConnectionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.daemon = daemon_module.VPNDaemon()
        self.network = {}
        for name, value in [('new_session', 'a' * 32), ('bind_session', None),
                            ('session_ready', True), ('session_failure', None),
                            ('cleanup_session', None)]:
            patcher = patch.object(daemon_module.network_policy, name, return_value=value)
            self.network[name] = patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(daemon_module.os, 'access', return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    async def connect(self, params=None, process=None):
        process = process or Process()
        captured = {}

        def spawn(argv, **kwargs):
            captured.update(argv=argv, payload=kwargs['stdin'].read(), options=kwargs)
            return process

        with patch.object(daemon_module, 'find_openconnect', return_value='/fake/openconnect'), \
             patch.object(daemon_module, 'find_base_hipreport', return_value='/fake/hipreport'), \
             patch.object(daemon_module.os, 'access', return_value=True), \
             patch.object(daemon_module.subprocess, 'Popen', side_effect=spawn):
            result = await self.daemon._dispatch('connect', params or connection())
        return result, captured

    async def test_large_complete_cookie_header_is_private_and_not_logged(self):
        secret = 'secret-token-' + 'x' * 100000
        params = connection(cookies={'webvpn': secret, 'other': 'second',
                                      'SAMLResponse': 'assertion', '_gateway_ip': '192.0.2.1'})
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result, captured = await self.connect(params)
        self.assertTrue(result['success'])
        self.assertEqual(captured['payload'], ('cookie=webvpn=' + secret + '; other=second\n').encode())
        self.assertIn('--config=/dev/stdin', captured['argv'])
        self.assertEqual(captured['argv'][-2:], ['--', 'vpn.example.test'])
        self.assertNotIn(secret, ' '.join(captured['argv']) + stdout.getvalue() + stderr.getvalue())
        self.assertEqual(captured['options']['stdout'], subprocess.PIPE)
        self.assertTrue(captured['options']['stdin'].closed)
        self.assertIn('--script=' + daemon_module.NETWORK_WRAPPER_PATH, captured['argv'])
        self.assertEqual(captured['options']['env']['MS_SSO_NETWORK_SESSION'], 'a' * 32)

    async def test_output_marker_without_network_ack_is_never_connected(self):
        self.network['session_ready'].return_value = False
        process = Process()
        with patch.object(daemon_module, 'CONNECT_TIMEOUT', 0.02):
            result, _ = await self.connect(process=process)
        self.assertEqual(result['error_code'], 'network_setup_failed')
        self.assertEqual(process.signals, [signal.SIGTERM])
        self.network['cleanup_session'].assert_called_with('a' * 32)
        self.assertFalse((await self.daemon._dispatch('status', {}))['connected'])

    async def test_marker_before_network_script_waits_for_verified_ack(self):
        self.network['session_ready'].side_effect = [False, False, True]
        result, _ = await self.connect()
        self.assertTrue(result['success'])
        self.assertEqual(self.network['session_ready'].call_count, 3)

    async def test_disconnect_can_signal_during_network_verification(self):
        entered, release = threading.Event(), threading.Event()
        def verify(token):
            entered.set()
            release.wait(2)
            return True
        self.network['session_ready'].side_effect = verify
        process = Process()
        task = asyncio.create_task(self.connect(process=process))
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 1))
            disconnected = await asyncio.wait_for(self.daemon._dispatch('disconnect', {}), 0.5)
            self.assertTrue(disconnected['success'])
            self.assertEqual(process.signals, [signal.SIGTERM])
        finally:
            release.set()
            result, _ = await task
        self.assertEqual(result['error_code'], 'connection_cancelled')

    async def test_script_failure_stops_connection_without_waiting_for_marker(self):
        self.network['session_failure'].return_value = 'network_setup_failed'
        process = Process(b'Negotiating\n')
        result, _ = await self.connect(process=process)
        self.assertEqual(result['error_code'], 'network_setup_failed')
        self.assertEqual(process.signals, [signal.SIGTERM])

    async def test_failed_child_binding_stops_only_new_child(self):
        self.network['bind_session'].side_effect = daemon_module.network_policy.NetworkPolicyError('unsafe')
        process = Process()
        result, _ = await self.connect(process=process)
        self.assertEqual(result['error_code'], 'network_setup_failed')
        self.assertEqual(process.signals, [signal.SIGTERM])
        self.network['cleanup_session'].assert_called_once()

    async def test_unexpected_exit_restores_network_without_ui_polling(self):
        process = Process()
        result, _ = await self.connect(process=process)
        self.assertTrue(result['success'])
        process.exit_status = 1
        await asyncio.wait_for(self.daemon._process_watcher, 1)
        self.network['cleanup_session'].assert_called_once_with('a' * 32)
        self.assertIsNone(self.daemon._network_session)

    async def test_failed_network_cleanup_retains_token_for_retry(self):
        self.daemon._network_session = 'a' * 32
        self.network['cleanup_session'].side_effect = daemon_module.network_policy.NetworkPolicyError('conflict')
        result = await self.daemon._dispatch('disconnect', {})
        self.assertEqual(result['error_code'], 'network_cleanup_failed')
        self.assertEqual(self.daemon._network_session, 'a' * 32)
        self.network['cleanup_session'].side_effect = None
        self.assertTrue((await self.daemon._dispatch('disconnect', {}))['success'])
        self.assertIsNone(self.daemon._network_session)

    async def test_reconnect_script_failure_stops_an_established_connection(self):
        process = Process()
        result, _ = await self.connect(process=process)
        self.assertTrue(result['success'])
        self.network['session_failure'].return_value = 'network_setup_failed'
        await asyncio.wait_for(self.daemon._process_watcher, 2)
        self.assertEqual(process.signals, [signal.SIGTERM])
        self.network['cleanup_session'].assert_called_once()
        self.assertFalse((await self.daemon._dispatch('status', {}))['connected'])

    async def test_gateway_uses_prelogin_identity_and_mac_hip_options(self):
        params = connection(protocol='gp', username='login@example.test', gp_auth_interface='gateway',
                            gp_os_version='macOS 15.0', cached_usergroup='portal:portal-userauthcookie',
                            cookies={'portal-userauthcookie': 'wrong-portal', 'prelogin-cookie': 'gateway-secret',
                                     'saml-username': 'saml-identity', '_gateway_ip': '192.0.2.1'})
        result, captured = await self.connect(params)
        self.assertTrue(result['success'])
        self.assertEqual(captured['payload'], b'gateway-secret\n')
        for flag in ('--usergroup=gateway:prelogin-cookie', '--passwd-on-stdin', '--os=mac-intel',
                     '--useragent=PAN GlobalProtect', '--user=saml-identity', '--non-inter',
                     '--force-dpd=10', '--reconnect-timeout=300'):
            self.assertIn(flag, captured['argv'])
        self.assertIn('--csd-wrapper=' + daemon_module.HIP_WRAPPER_PATH, captured['argv'])
        self.assertEqual(captured['argv'][-1], 'vpn.example.test')
        self.assertEqual(captured['options']['env']['MS_SSO_GP_OS_VERSION'], 'macOS 15.0')

    async def test_portal_cookie_group_is_not_double_prefixed(self):
        params = connection(protocol='gp', cookies={'portal-userauthcookie': 'portal-secret'},
                            cached_usergroup='portal:portal-userauthcookie')
        result, captured = await self.connect(params)
        self.assertTrue(result['success'])
        self.assertIn('--usergroup=portal:portal-userauthcookie', captured['argv'])
        self.assertEqual(captured['payload'], b'portal-secret\n')

    async def test_gateway_never_falls_back_to_portal_cookie(self):
        with self.assertRaises(daemon_module.RPCError):
            await self.connect(connection(protocol='gp', gp_auth_interface='gateway',
                                          cookies={'portal-userauthcookie': 'not-a-gateway-cookie'}))

    async def test_invalid_arguments_never_spawn_a_process(self):
        variants = [{'address': '--script=/tmp/injected'}, {'address': 'vpn.example\n--script=x'},
                    {'address': 'https://user:secret@vpn.example'}, {'address': 'vpn.example:99999'},
                    {'protocol': 'gp --script=x'}, {'protocol': []}, {'no_dtls': 'yes'},
                    {'username': 'user\nsecret'}, {'cookies': {'webvpn': 'cookie\ninjected'}},
                    {'cookies': {'webvpn': 1}}, {'cached_usergroup': 'portal:portal:prelogin-cookie'},
                    {'gp_auth_interface': 'bad'}, {'extra': '--script=x'}]
        with patch.object(daemon_module.subprocess, 'Popen') as spawn:
            for variant in variants:
                with self.subTest(variant=variant), self.assertRaises(daemon_module.RPCError):
                    await self.daemon._dispatch('connect', connection(**variant))
            spawn.assert_not_called()

    async def test_exit_before_readiness_reports_no_process_output(self):
        process = Process(b'Cookie: private-session\nAuthentication failed for secret-user\n', exit_status=1)
        result, _ = await self.connect(process=process)
        self.assertEqual(result['error_code'], 'openconnect_exit')
        self.assertEqual(result['exit_status'], 1)
        self.assertTrue(result['retryable'])
        self.assertNotIn('private-session', json.dumps(result))
        self.assertNotIn('secret-user', json.dumps(result))
        self.assertIsNone(self.daemon._openconnect_proc)

    async def test_no_readiness_times_out_and_terminates_only_owned_process(self):
        process = Process(b'Negotiating portal\n')
        with patch.object(daemon_module, 'CONNECT_TIMEOUT', 0.02):
            result, _ = await self.connect(process=process)
        self.assertEqual(result['error_code'], 'openconnect_timeout')
        self.assertEqual(process.signals, [signal.SIGTERM])
        self.assertIsNone(self.daemon._openconnect_proc)

    async def test_delayed_readiness_does_not_block_ping_or_disconnect(self):
        process = Process(b'Negotiating portal\n')
        with patch.object(daemon_module, 'find_openconnect', return_value='/fake/openconnect'), \
             patch.object(daemon_module.subprocess, 'Popen', return_value=process):
            task = asyncio.create_task(self.daemon._dispatch('connect', connection()))
            await asyncio.sleep(0.02)
            self.assertFalse(task.done())
            status = await self.daemon._dispatch('status', {})
            self.assertFalse(status['connected'])
            self.assertTrue(status['connecting'])
            self.assertTrue((await self.daemon._dispatch('ping', {}))['pong'])
            self.assertTrue((await self.daemon._dispatch('disconnect', {}))['success'])
            result = await asyncio.wait_for(task, 1)
        self.assertEqual(result['error_code'], 'connection_cancelled')
        self.assertEqual(process.signals, [signal.SIGTERM])

    async def test_delayed_readiness_waits_for_actual_openconnect_marker(self):
        process = Process()
        read_fd, write_fd = os.pipe()
        process.stdout = os.fdopen(read_fd, 'rb')
        with patch.object(daemon_module, 'find_openconnect', return_value='/fake/openconnect'), \
             patch.object(daemon_module.subprocess, 'Popen', return_value=process):
            task = asyncio.create_task(self.daemon._dispatch('connect', connection()))
            try:
                os.write(write_fd, b'Negotiating portal\n')
                await asyncio.sleep(0.02)
                self.assertFalse(task.done())
                self.assertFalse((await self.daemon._dispatch('status', {}))['connected'])
                os.write(write_fd, b'Configured as 10.1.2.3, with SSL connected\n')
                self.assertTrue((await asyncio.wait_for(task, 1))['success'])
                self.assertTrue((await self.daemon._dispatch('status', {}))['connected'])
            finally:
                os.close(write_fd)
                await self.daemon._dispatch('disconnect', {})
                await task

    async def test_second_connect_during_pending_connection_is_rejected(self):
        process = Process(b'Negotiating\n')
        with patch.object(daemon_module, 'find_openconnect', return_value='/fake/openconnect'), \
             patch.object(daemon_module.subprocess, 'Popen', return_value=process) as spawn:
            first = asyncio.create_task(self.daemon._dispatch('connect', connection()))
            await asyncio.sleep(0.02)
            second = await self.daemon._dispatch('connect', connection())
            self.assertEqual(second['error_code'], 'already_connected')
            self.assertEqual(spawn.call_count, 1)
            await self.daemon._dispatch('disconnect', {})
            await first

    async def test_shutdown_signal_uses_normal_cleanup_without_exiting_inside_handler(self):
        self.daemon._signal_handler(signal.SIGTERM, None)
        self.assertTrue(self.daemon._stopping.is_set())
        self.assertFalse(self.daemon._running)
        result = await self.daemon._dispatch('connect', connection())
        self.assertEqual(result['error_code'], 'helper_stopping')

    async def test_missing_openconnect_is_a_permanent_configuration_error(self):
        with patch.object(daemon_module, 'find_openconnect', return_value=None):
            result = await self.daemon._dispatch('connect', connection())
        self.assertFalse(result['retryable'])
        self.assertEqual(result['error_code'], 'openconnect_missing')

    async def test_disconnect_timeout_retains_process_ownership(self):
        process = Process()
        process.send_signal = lambda value: process.signals.append(value)
        process.wait = lambda **kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired('openconnect', 10))
        self.daemon._openconnect_proc = process
        result = await self.daemon._dispatch('disconnect', {})
        self.assertEqual(result['error_code'], 'disconnect_in_progress')
        self.assertIs(self.daemon._openconnect_proc, process)
        self.assertEqual(process.signals, [signal.SIGTERM])


class DaemonSocketTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='msso-', dir='/tmp')
        self.path = str(Path(self.directory.name) / 'daemon.sock')
        self.daemon = daemon_module.VPNDaemon()
        await self.daemon._start_server(self.path)

    async def asyncTearDown(self):
        self.daemon._server.close()
        await self.daemon._server.wait_closed()
        self.directory.cleanup()

    async def exchange(self, payload):
        reader, writer = await asyncio.open_unix_connection(self.path)
        writer.write(payload)
        try:
            await writer.drain()
            return json.loads(await asyncio.wait_for(reader.readline(), 3))
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_large_sso_request_survives_default_asyncio_64k_limit(self):
        request = {'jsonrpc': '2.0', 'method': 'connect', 'params': connection(
            cookies={'webvpn': 'x' * 100000}), 'id': 3}
        with patch.object(daemon_module, 'find_openconnect', return_value=None):
            response = await self.exchange(json.dumps(request).encode() + b'\n')
        self.assertEqual(response['id'], 3)
        self.assertEqual(response['result']['error_code'], 'openconnect_missing')

    async def test_bad_json_request_shape_and_options_return_framed_errors(self):
        for payload, code in ((b'{invalid\n', -32700), (b'[]\n', -32600),
                              (b'{"jsonrpc":"2.0","method":"connect","params":[]}\n', -32602),
                              (b'{"jsonrpc":"2.0","method":"unknown","params":{}}\n', -32601)):
            with self.subTest(payload=payload):
                response = await self.exchange(payload)
                self.assertEqual(response['error']['code'], code)

    async def test_oversized_request_is_rejected(self):
        response = await self.exchange(b'x' * (daemon_module.MAX_MESSAGE_BYTES + 1) + b'\n')
        self.assertEqual(response['error']['code'], -32600)

    async def test_unprivileged_health_check_requires_matching_helper_version(self):
        self.assertTrue(await asyncio.to_thread(daemon_module.check_helper, self.path))
        async def old_ping(params):
            return {'pong': True, 'version': '1.0.0'}
        self.daemon._handle_ping = old_ping
        self.assertFalse(await asyncio.to_thread(daemon_module.check_helper, self.path))


class HipReportTests(unittest.TestCase):
    def test_custom_os_is_escaped_and_native_vendor_preserved(self):
        original = '<hip-report><os>Apple Mac OS X 15.0</os><os-vendor>Apple</os-vendor></hip-report>'
        result = subprocess.CompletedProcess([], 0, stdout=original, stderr='')
        output = io.StringIO()
        with patch.object(daemon_module, 'find_base_hipreport', return_value='/fake/hipreport'), \
             patch.object(daemon_module.subprocess, 'run', return_value=result) as run, \
             patch.dict(os.environ, {'MS_SSO_GP_OS_VERSION': 'macOS <custom> & version'}), \
             redirect_stdout(output):
            self.assertEqual(daemon_module.run_hip_report(['--client-os', 'Mac']), 0)
        self.assertIn('<os>macOS &lt;custom&gt; &amp; version</os>', output.getvalue())
        self.assertIn('<os-vendor>Apple</os-vendor>', output.getvalue())
        self.assertEqual(run.call_args.args[0], ['/fake/hipreport', '--client-os', 'Mac'])

    def test_auto_os_retains_detected_mac_report(self):
        original = '<os>Apple Mac OS X 15.0</os><os-vendor>Apple</os-vendor>'
        with patch.object(daemon_module, 'find_base_hipreport', return_value='/fake/hipreport'), \
             patch.object(daemon_module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, original, '')), \
             patch.dict(os.environ, {'MS_SSO_GP_OS_VERSION': 'auto'}), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(daemon_module.run_hip_report([]), 0)
        self.assertEqual(output.getvalue(), original)

    def test_hip_failure_does_not_echo_credentials(self):
        result = subprocess.CompletedProcess([], 1, stdout='cookie=secret', stderr='cookie=secret')
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(daemon_module, 'find_base_hipreport', return_value='/fake/hipreport'), \
             patch.object(daemon_module.subprocess, 'run', return_value=result), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(daemon_module.run_hip_report([]), 1)
        self.assertNotIn('secret', stdout.getvalue() + stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
