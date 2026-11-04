"""Standalone lifecycle regressions; no VPN credentials or privileged networking."""
import io
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'codebase'), str(ROOT / 'codebase/ui/src')]
import core.connect as connect


class Process:
    def __init__(self, output=b'', polls=2):
        self.stdout = io.BytesIO(output)
        self.remaining = polls
        self.stopped = False

    def poll(self):
        self.remaining -= 1
        return 0 if self.stopped or self.remaining < 0 else None

    def wait(self, timeout=None):
        return 0

    def terminate(self):
        self.stopped = True


class LifecycleTests(unittest.TestCase):
    def test_full_cookie_config_is_private_and_unlimited(self):
        header = connect.build_anyconnect_cookie_header({
            'webvpn': 'x' * 100000, 'other': 'session', 'SAMLResponse': 'assertion',
            '_gateway_ip': '10.1.2.3', 'bad': 'x\ninjected',
        })
        with connect._private_input(('cookie=' + header + '\n').encode()) as secret:
            self.assertEqual(secret.read(), ('cookie=' + header + '\n').encode())
        self.assertNotIn('assertion', header)
        self.assertNotIn('injected', header)
        self.assertIn('other=session', header)

    def test_gateway_artifact_and_missing_cookie(self):
        self.assertEqual(connect.select_gp_cookie({'prelogin-cookie': 'direct',
                                                  'portal-userauthcookie': 'portal'}, 'gateway'),
                         ('direct', 'gateway:prelogin-cookie'))
        with self.assertRaises(ValueError):
            connect.select_gp_cookie({'portal-userauthcookie': 'wrong'}, 'gateway')

    def test_output_redacts_complete_cookie_header(self):
        self.assertNotIn('secret', connect._redact_output('Set-Cookie: webvpn=secret; other=secret\n'))

    def test_malformed_state_does_not_claim_tunnel(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(connect, '_state_dir', return_value=Path(tmp)):
            (Path(tmp) / 'session.json').write_text('[]')
            self.assertEqual(connect._read_state(), {})
            self.assertFalse(connect.is_connected())

    def test_unrelated_tunnel_is_not_connected(self):
        with patch.object(connect, '_read_state', return_value={}), patch.object(connect, '_owned_pids') as owned:
            self.assertFalse(connect.is_connected())
            owned.assert_not_called()

    def test_graceful_disconnect_keeps_unrelated_processes(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(connect, '_state_dir', return_value=Path(tmp)), \
                patch.object(connect, '_read_state', return_value={'interface': 'msso0123456789'}), \
                patch.object(connect, '_signal_owned', return_value=True) as signal_owned, \
                patch.object(connect, '_owned_pids', return_value=[]):
            self.assertTrue(connect.disconnect())
            self.assertEqual(signal_owned.call_args.args[1], signal.SIGINT)
            self.assertTrue((Path(tmp) / 'stop').exists())

    def run_tunnel(self, protocol='anyconnect', cookies=None, **kwargs):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.object(connect, '_state_dir', return_value=Path(tmp)))
        self.enterContext(patch.object(connect, '_owned_pids', return_value=[]))
        self.enterContext(patch.object(connect, '_tunnel_ready', return_value=True))
        self.enterContext(patch.object(connect.os, 'geteuid', return_value=0))
        self.enterContext(patch.object(connect.time, 'sleep'))
        self.enterContext(patch.object(connect, 'get_gp_hip_report_wrapper', return_value=None))
        captured = {}
        process = Process(b'Connected\nportal-userauthcookie=renewed\n')
        def spawn(cmd, **opts):
            captured['command'] = cmd
            captured['secret'] = opts['stdin'].read()
            return process
        self.enterContext(patch.object(connect.subprocess, 'Popen', side_effect=spawn))
        result = connect.connect_vpn('vpn.example', protocol, cookies or {'webvpn': 'secret'}, **kwargs)
        return result, captured

    def test_connected_signal_precedes_clean_unexpected_exit(self):
        ready = Mock()
        result, captured = self.run_tunnel(connected_callback=ready)
        self.assertFalse(result, 'A server closing cleanly still requires reconnect')
        ready.assert_called_once_with()
        self.assertIn('--config=/dev/stdin', captured['command'])
        self.assertNotIn('secret', ' '.join(captured['command']))
        self.assertEqual(captured['secret'], b'cookie=webvpn=secret\n')

    def test_gp_uses_and_caches_federated_identity(self):
        with patch.object(connect, 'store_cookies') as store:
            result, captured = self.run_tunnel('gp', {'prelogin-cookie': 'secret',
                                                     'saml-username': 'normalized'},
                                               username='login@example', connection_name='work')
        self.assertIn('--user=normalized', captured['command'])
        self.assertEqual(captured['secret'], b'secret\n')
        self.assertEqual(store.call_args.args[1]['saml-username'], 'normalized')
        self.assertFalse(result)

    def test_cancel_before_launch_never_spawns(self):
        with patch.object(connect.subprocess, 'Popen') as spawn:
            self.assertTrue(connect.connect_vpn('vpn.example', 'gp', {}, cancel_callback=lambda: True))
        spawn.assert_not_called()

    def test_setup_timeout_is_failure_not_user_disconnect(self):
        with patch.object(connect, '_tunnel_ready', return_value=False), \
                patch.object(connect.time, 'monotonic', side_effect=[0, 1000]), \
                patch.object(connect, 'disconnect', return_value=True) as disconnect:
            # run_tunnel installs its readiness mock; override only timeout through callback.
            tmp = self.enterContext(tempfile.TemporaryDirectory())
            self.enterContext(patch.object(connect, '_state_dir', return_value=Path(tmp)))
            self.enterContext(patch.object(connect, '_owned_pids', return_value=[]))
            self.enterContext(patch.object(connect.os, 'geteuid', return_value=0))
            self.enterContext(patch.object(connect.subprocess, 'Popen', return_value=Process(polls=10)))
            self.assertFalse(connect.connect_vpn('vpn.example', 'anyconnect', {'webvpn': 'secret'}))
            disconnect.assert_called_once_with(use_pkexec=False, _mark_intent=False)


class WorkerTests(unittest.TestCase):
    def setUp(self):
        from vpn_ui.worker import VPNConnectWorker
        self.backend = Mock()
        self.backend.get_config.return_value = ('work', 'vpn.example', 'anyconnect', 'user', 'password', '')
        self.backend.get_connection.return_value = {}
        self.backend.get_stored_cookies.return_value = None
        self.backend.do_saml_auth.return_value = {'webvpn': 'session'}
        self.worker = VPNConnectWorker(self.backend, 'work')
        self.messages = []
        self.worker.finished.connect(lambda *args: self.messages.append(args))
        self.env = patch.dict(os.environ, {'MS_SSO_RECONNECT_DELAY_SECONDS': '0', 'MS_SSO_RECONNECT_MAX_ATTEMPTS': '3'})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_reconnect_is_bounded_after_session_expiry(self):
        self.backend.connect_vpn.return_value = False
        self.worker.run()
        self.assertEqual(self.backend.connect_vpn.call_count, 3)
        self.assertEqual(self.backend.do_saml_auth.call_count, 3)
        self.assertFalse(self.messages[-1][0])

    def test_explicit_disconnect_stops_reconnect(self):
        self.backend.connect_vpn.return_value = True
        self.worker.run()
        self.assertEqual(self.backend.connect_vpn.call_count, 1)
        self.assertEqual(self.messages[-1], (False, 'Disconnected'))

    def test_cancel_during_auth_never_launches_tunnel(self):
        def auth(**kwargs):
            self.worker.cancel()
            self.assertTrue(kwargs['cancel_callback']())
            return {'webvpn': 'session'}
        self.backend.do_saml_auth.side_effect = auth
        self.worker.run()
        self.backend.connect_vpn.assert_not_called()

    def test_push_auth_does_not_require_totp(self):
        self.backend.get_connection.return_value = {'mfa_preference': 'push'}
        self.backend.connect_vpn.return_value = True
        self.worker.run()
        self.assertEqual(self.backend.do_saml_auth.call_args.kwargs['mfa_preference'], 'push')
        self.assertEqual(self.backend.do_saml_auth.call_args.kwargs['totp_secret'], '')

    def test_presensitive_auth_failure_has_bounded_backoff(self):
        self.backend.do_saml_auth.side_effect = RuntimeError('temporary failure')
        self.worker.run()
        self.assertEqual(self.backend.do_saml_auth.call_count, 3)
        self.backend.connect_vpn.assert_not_called()

    def test_reconnect_disabled_profile_tries_once(self):
        self.backend.get_connection.return_value = {'auto_reconnect': False}
        self.backend.connect_vpn.return_value = False
        self.worker.run()
        self.assertEqual(self.backend.connect_vpn.call_count, 1)

    def test_unlimited_transport_reconnect_uses_exponential_backoff(self):
        self.backend.connect_vpn.side_effect = [False, False, False, False, True]
        waits = []
        self.worker._cancelled.wait = lambda delay: waits.append(delay) or False
        with patch.dict(os.environ, {'MS_SSO_RECONNECT_MAX_ATTEMPTS': '0',
                                     'MS_SSO_RECONNECT_DELAY_SECONDS': '5'}):
            self.worker.run()
        self.assertEqual(waits, [5, 10, 20, 40])
        self.assertEqual(self.backend.connect_vpn.call_count, 5)

    def test_stable_connection_resets_recovery_budget(self):
        now = [0]
        calls = [0]
        def connect_vpn(**kwargs):
            calls[0] += 1
            if calls[0] == 1:
                kwargs['connected_callback']()
                now[0] = 120
            return calls[0] == 4
        self.backend.connect_vpn.side_effect = connect_vpn
        with patch('vpn_ui.worker.time.monotonic', side_effect=lambda: now[0]):
            self.worker.run()
        self.assertEqual(calls[0], 4)

    def test_manual_cancel_interrupts_reconnect_backoff(self):
        self.backend.connect_vpn.return_value = False
        def wait(delay):
            self.worker.cancel()
            return True
        self.worker._cancelled.wait = wait
        self.worker.run()
        self.assertEqual(self.backend.connect_vpn.call_count, 1)
        self.assertEqual(self.messages[-1], (False, 'Cancelled'))

    def test_failed_session_cleanup_keeps_live_tunnel_visible(self):
        from vpn_ui.main import VPNApplication
        app = VPNApplication.__new__(VPNApplication)
        app._number_match_dialog = None
        app._worker_thread = None
        app._disconnecting = False
        app._current_connection = 'work'
        app.tray = Mock()
        app.notifications = Mock()
        app.backend = Mock()
        app.backend.is_connected.return_value = True
        app._on_connect_finished(False, 'VPN process did not stop')
        app.tray.set_status.assert_called_once_with('connected', 'work')
        app.backend.clear_active_connection.assert_not_called()
        self.assertEqual(app._current_connection, 'work')

    def test_failed_disconnect_does_not_claim_success_or_quit(self):
        from vpn_ui.main import VPNApplication
        app = VPNApplication.__new__(VPNApplication)
        app._number_match_dialog = None
        app._worker_thread = None
        app._quitting = True
        app._disconnecting = True
        app._current_connection = 'work'
        app.tray = Mock()
        app.notifications = Mock()
        app.backend = Mock()
        app.backend.is_connected.return_value = True
        app._on_disconnect_finished(False, 'Authorization declined')
        self.assertFalse(app._quitting)
        self.assertEqual(app._current_connection, 'work')
        app.backend.clear_active_connection.assert_not_called()
        app.notifications.error.assert_called_once_with('Authorization declined')


if __name__ == '__main__':
    unittest.main()
