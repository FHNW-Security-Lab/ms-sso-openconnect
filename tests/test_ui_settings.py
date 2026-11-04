"""Profile editing and tray status regression tests (no real VPN/keyring)."""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'codebase'), str(ROOT / 'codebase/ui/src')]
from PyQt6.QtWidgets import QApplication, QMessageBox
from core import config
from vpn_ui.connection_form import ConnectionForm
from vpn_ui.tray import VPNTrayIcon
from vpn_ui.constants import STATUS_CONNECTING


class ProfilePersistenceTests(unittest.TestCase):
    def test_legacy_edit_preserves_advanced_options(self):
        old = dict(address='vpn', protocol='gp', username='u', password='p',
                   totp_secret='', gp_auth_interface='gateway', auto_reconnect=False)
        with patch.object(config, 'get_connections', return_value={'work': old}), \
             patch.object(config, '_save_connections', return_value=True) as save:
            self.assertTrue(config.save_connection('work', 'vpn', 'gp', 'u', 'p', ''))
            self.assertEqual(save.call_args.args[0]['work']['gp_auth_interface'], 'gateway')
            self.assertFalse(save.call_args.args[0]['work']['auto_reconnect'])

    def test_identity_edit_invalidates_cached_cookie(self):
        with patch.object(config, 'get_connections', return_value={'work': {'username': 'old'}}), \
             patch.object(config, '_save_connections', return_value=True), \
             patch('core.cookies.clear_cookies') as clear:
            self.assertTrue(config.save_connection('work', 'vpn', 'gp', 'new', 'p', ''))
            clear.assert_called_once_with('work')

    def test_failed_delete_keeps_cookie(self):
        with patch.object(config, 'get_connections', return_value={'work': {}}), \
             patch.object(config, '_save_connections', return_value=False), \
             patch('core.cookies.clear_cookies') as clear:
            self.assertFalse(config.delete_connection('work'))
            clear.assert_not_called()


class UiSettingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.backend = Mock()
        self.backend.get_connection.return_value = None
        self.backend.save_connection.return_value = True
        self.form = ConnectionForm(self.backend)

    def tearDown(self):
        self.form.deleteLater()
        self.app.processEvents()

    def test_password_widget_survives_form_construction(self):
        self.form.password_edit.setText('password')
        self.assertEqual(self.form.password_edit.text(), 'password')

    def test_push_profile_saves_without_totp(self):
        self.form.name_edit.setText('work')
        self.form.address_edit.setText('vpn.example.test')
        self.form.username_edit.setText('user@example.test')
        self.form.password_edit.setText('password')
        self.form.mfa_combo.setCurrentIndex(self.form.mfa_combo.findData('push'))
        with patch.object(QMessageBox, 'information'), patch.object(QMessageBox, 'warning') as warn:
            self.form._save()
        warn.assert_not_called()
        self.backend.generate_totp.assert_not_called()
        self.assertEqual(self.backend.save_connection.call_args.kwargs['mfa_preference'], 'push')

    def test_explicit_totp_requires_secret(self):
        self.form.load_connection('work', dict(address='vpn', username='u', password='p', mfa_preference='totp'))
        with patch.object(QMessageBox, 'warning') as warn:
            self.form._save()
        warn.assert_called_once()
        self.backend.save_connection.assert_not_called()

    def test_gp_options_roundtrip(self):
        self.form.load_connection('work', dict(protocol='gp', gp_auth_interface='gateway',
                                              gp_os_version='Custom Linux', auto_reconnect=False))
        self.assertEqual(self.form.gp_interface_combo.currentData(), 'gateway')
        self.assertTrue(self.form.gp_os_edit.isEnabled())
        self.assertEqual(self.form.gp_os_edit.text(), 'Custom Linux')
        self.assertFalse(self.form.reconnect_check.isChecked())

    def test_managed_poll_cannot_overwrite_authentication_or_retry(self):
        tray = VPNTrayIcon()
        tray.set_status(STATUS_CONNECTING, 'work')
        tray.set_managed(True)
        tray.set_progress('Waiting for sign-in')
        tray._poll_status()
        self.assertEqual(tray.get_status(), STATUS_CONNECTING)
        self.assertEqual(tray._status_action.text(), 'Waiting for sign-in')
        tray.deleteLater()


if __name__ == '__main__':
    unittest.main()
