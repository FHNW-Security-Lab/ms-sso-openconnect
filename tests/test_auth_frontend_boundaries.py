"""Frontend reconnect loops must not replay an uncertain password/MFA action."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "codebase"), str(ROOT / "codebase/ui/src")]
from vpn_ui.worker import VPNConnectWorker
from core import SamlSensitiveActionError

SPEC = importlib.util.spec_from_file_location("ms_sso_cli_test", ROOT / "ms-sso-openconnect.py")
cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cli)


class FrontendAuthBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"MS_SSO_RECONNECT_MAX_ATTEMPTS": "3",
                                          "MS_SSO_RECONNECT_DELAY_SECONDS": "0"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.backend = Mock()
        self.backend.get_config.return_value = ("work", "vpn.example.test", "anyconnect", "alice", "fixture", "")
        self.backend.get_connection.return_value = {"mfa_preference": "push"}
        self.backend.get_stored_cookies.return_value = None
        self.backend.connect_vpn.return_value = True

    def test_worker_auth_uncertainty_ends_activation_without_replay(self):
        self.backend.do_saml_auth.side_effect = SamlSensitiveActionError("password dispatch uncertain")
        worker = VPNConnectWorker(self.backend, "work")
        errors = []
        worker.error.connect(errors.append)
        worker.run()
        self.backend.do_saml_auth.assert_called_once()
        self.backend.connect_vpn.assert_not_called()
        self.assertEqual(errors, ["password dispatch uncertain"])

    def test_worker_empty_auth_result_is_not_replayed(self):
        self.backend.do_saml_auth.return_value = {}
        worker = VPNConnectWorker(self.backend, "work")
        worker.run()
        self.backend.do_saml_auth.assert_called_once()
        self.backend.connect_vpn.assert_not_called()

    def test_worker_gateway_auth_never_reuses_cached_prelogin(self):
        self.backend.get_config.return_value = ("work", "vpn.example.test", "gp", "alice", "fixture", "")
        self.backend.get_connection.return_value = {"gp_auth_interface": "gateway"}
        self.backend.get_stored_cookies.return_value = ({"prelogin-cookie": "old"}, "gateway:prelogin-cookie")
        self.backend.do_saml_auth.return_value = {"prelogin-cookie": "fresh", "saml-username": "gateway-alice"}
        worker = VPNConnectWorker(self.backend, "work")
        worker.run()
        self.backend.do_saml_auth.assert_called_once()
        self.backend.connect_vpn.assert_called_once()
        self.assertEqual(self.backend.connect_vpn.call_args.kwargs["cookies"]["prelogin-cookie"], "fresh")
        self.assertEqual(self.backend.connect_vpn.call_args.kwargs["gp_auth_interface"], "gateway")

    def test_cli_auth_uncertainty_ends_activation_without_replay(self):
        with patch.object(sys, "argv", ["ms-sso-openconnect", "work"]), \
             patch.object(cli, "get_config", return_value=self.backend.get_config.return_value), \
             patch.object(cli, "get_connection", return_value={"mfa_preference": "push"}), \
             patch.object(cli, "get_stored_cookies", return_value=None), \
             patch.object(cli, "connect_vpn") as connect, \
             patch.object(cli, "do_saml_auth_with_recovery", side_effect=SamlSensitiveActionError("password dispatch uncertain")) as auth, \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                cli.main()
        self.assertNotEqual(error.exception.code, 0)
        auth.assert_called_once()
        connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
