#!/usr/bin/env python3
"""
NetworkManager VPN Auth Dialog for MS SSO OpenConnect

This dialog is called by NetworkManager when VPN secrets are needed.
It can either:
1. Look up saved credentials from keyring (shared with linux-ui)
2. Prompt the user for credentials via a GTK4 dialog
"""

import os
import sys
import argparse
import json
import importlib.util

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib


def find_vpn_core_module():
    """Find the ms-sso-openconnect.py module."""
    search_paths = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "ms-sso-openconnect.py"),
        "/usr/share/ms-sso-openconnect/ms-sso-openconnect.py",
        "/usr/lib/ms-sso-openconnect/ms-sso-openconnect.py",
        "/opt/ms-sso-vpn/ms-sso-openconnect.py",
    ]
    for path in search_paths:
        if os.path.exists(path):
            return path
    return None


def load_vpn_core():
    """Load the VPN core module."""
    module_path = find_vpn_core_module()
    if not module_path:
        return None

    spec = importlib.util.spec_from_file_location("vpn_core", module_path)
    vpn_core = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vpn_core)
    return vpn_core


class AuthDialog(Adw.ApplicationWindow):
    """GTK4/Adwaita authentication dialog."""

    def __init__(self, app, connection_name, gateway, username, reprompt=False):
        super().__init__(application=app, title="VPN Authentication")

        self.connection_name = connection_name
        self.gateway = gateway
        self.username = username
        self.reprompt = reprompt
        self.result = None

        self.set_default_size(400, 350)
        self.set_resizable(False)

        # Main content
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(24)
        box.set_margin_bottom(24)
        box.set_margin_start(24)
        box.set_margin_end(24)

        # Header
        header = Gtk.Label()
        header.set_markup(f"<b>VPN Authentication</b>\n<small>{gateway}</small>")
        header.set_justify(Gtk.Justification.CENTER)
        box.append(header)

        # Form
        form = Gtk.Grid()
        form.set_row_spacing(12)
        form.set_column_spacing(12)
        form.set_margin_top(24)

        # Username (read-only)
        lbl_user = Gtk.Label(label="Username:")
        lbl_user.set_halign(Gtk.Align.END)
        form.attach(lbl_user, 0, 0, 1, 1)

        self.entry_user = Gtk.Entry()
        self.entry_user.set_text(username or "")
        self.entry_user.set_editable(False)
        self.entry_user.set_hexpand(True)
        form.attach(self.entry_user, 1, 0, 1, 1)

        # Password
        lbl_pass = Gtk.Label(label="Password:")
        lbl_pass.set_halign(Gtk.Align.END)
        form.attach(lbl_pass, 0, 1, 1, 1)

        self.entry_password = Gtk.PasswordEntry()
        self.entry_password.set_show_peek_icon(True)
        self.entry_password.set_hexpand(True)
        form.attach(self.entry_password, 1, 1, 1, 1)

        # TOTP Secret
        lbl_totp = Gtk.Label(label="TOTP Secret:")
        lbl_totp.set_halign(Gtk.Align.END)
        form.attach(lbl_totp, 0, 2, 1, 1)

        self.entry_totp = Gtk.PasswordEntry()
        self.entry_totp.set_show_peek_icon(True)
        self.entry_totp.set_hexpand(True)
        form.attach(self.entry_totp, 1, 2, 1, 1)

        box.append(form)

        # Info label
        info = Gtk.Label()
        info.set_markup("<small>Credentials will be stored in your system keyring.</small>")
        info.set_margin_top(12)
        box.append(info)

        # Buttons
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        button_box.set_halign(Gtk.Align.END)
        button_box.set_margin_top(24)

        cancel_btn = Gtk.Button(label="Cancel")
        cancel_btn.connect("clicked", self._on_cancel)
        button_box.append(cancel_btn)

        connect_btn = Gtk.Button(label="Connect")
        connect_btn.add_css_class("suggested-action")
        connect_btn.connect("clicked", self._on_connect)
        button_box.append(connect_btn)

        box.append(button_box)

        self.set_content(box)

        # Connect Enter key
        self.entry_password.connect("activate", lambda w: self.entry_totp.grab_focus())
        self.entry_totp.connect("activate", lambda w: self._on_connect(None))

    def _on_cancel(self, button):
        """Cancel clicked."""
        self.result = None
        self.close()

    def _on_connect(self, button):
        """Connect clicked."""
        password = self.entry_password.get_text()
        totp_secret = self.entry_totp.get_text()

        if not password:
            dialog = Adw.MessageDialog(
                transient_for=self,
                heading="Missing Password",
                body="Please enter your password."
            )
            dialog.add_response("ok", "OK")
            dialog.present()
            return

        self.result = {
            'password': password,
            'totp-secret': totp_secret,
        }
        self.close()


class AuthApp(Adw.Application):
    """GTK4 Application for auth dialog."""

    def __init__(self, connection_name, gateway, username, reprompt=False):
        super().__init__(application_id='org.freedesktop.NetworkManager.ms-sso.auth')
        self.connection_name = connection_name
        self.gateway = gateway
        self.username = username
        self.reprompt = reprompt
        self.result = None

    def do_activate(self):
        dialog = AuthDialog(
            self,
            self.connection_name,
            self.gateway,
            self.username,
            self.reprompt
        )
        dialog.connect("close-request", self._on_dialog_close)
        dialog.present()

    def _on_dialog_close(self, dialog):
        self.result = dialog.result
        self.quit()
        return False


def output_secrets(secrets):
    """Output secrets to stdout in NetworkManager format."""
    for key, value in secrets.items():
        print(f"{key}={value}")
    print("--")
    sys.stdout.flush()


def lookup_keyring_secrets(gateway, username):
    """Look up secrets from the shared keyring."""
    vpn_core = load_vpn_core()
    if not vpn_core:
        return None

    try:
        connections = vpn_core.get_all_connections()
        for name, conn in connections.items():
            if conn.get('address') == gateway and conn.get('username') == username:
                return {
                    'password': conn.get('password', ''),
                    'totp-secret': conn.get('totp_secret', ''),
                }
    except Exception as e:
        print(f"Keyring lookup error: {e}", file=sys.stderr)

    return None


def main():
    parser = argparse.ArgumentParser(description='MS SSO OpenConnect Auth Dialog')
    parser.add_argument('-u', '--uuid', help='Connection UUID')
    parser.add_argument('-n', '--name', help='Connection name')
    parser.add_argument('-s', '--service', help='VPN service type')
    parser.add_argument('-i', '--allow-interaction', action='store_true',
                        help='Allow user interaction')
    parser.add_argument('-r', '--reprompt', action='store_true',
                        help='Reprompt for secrets')
    parser.add_argument('-t', '--hint', action='append', default=[],
                        help='Hints for secrets')
    parser.add_argument('--external-ui-mode', action='store_true',
                        help='External UI mode')

    args = parser.parse_args()

    # Read connection data from stdin
    vpn_data = {}
    for line in sys.stdin:
        line = line.strip()
        if line == 'DONE':
            break
        if '=' in line:
            key, value = line.split('=', 1)
            vpn_data[key] = value

    gateway = vpn_data.get('DATA_gateway', vpn_data.get('gateway', ''))
    username = vpn_data.get('DATA_username', vpn_data.get('username', ''))
    connection_name = args.name or gateway

    # Try keyring lookup first (unless reprompt)
    if not args.reprompt:
        secrets = lookup_keyring_secrets(gateway, username)
        if secrets and secrets.get('password'):
            output_secrets(secrets)
            return 0

    # Show dialog if allowed
    if not args.allow_interaction:
        print("Secrets required but interaction not allowed", file=sys.stderr)
        return 1

    # Run GTK dialog
    app = AuthApp(connection_name, gateway, username, args.reprompt)
    app.run([])

    if app.result:
        output_secrets(app.result)
        return 0
    else:
        return 1


if __name__ == '__main__':
    sys.exit(main())
