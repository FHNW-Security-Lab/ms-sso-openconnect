"""Connection form widget."""

from typing import Optional

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QWidget,
)

from core import save_connection, get_connection, generate_totp
from core.totp import validate_secret

from .constants import PROTOCOLS


class ConnectionForm(QWidget):
    """Widget for editing VPN connection details."""

    saved = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._editing_name: Optional[str] = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QFormLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Connection name
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("e.g., work, home, university")
        layout.addRow("Connection Name:", self.name_edit)

        # Server
        self.address_edit = QLineEdit()
        self.address_edit.setPlaceholderText("vpn.example.com")
        layout.addRow("Server Address:", self.address_edit)

        # Protocol
        self.protocol_combo = QComboBox()
        for proto_id, proto_info in PROTOCOLS.items():
            self.protocol_combo.addItem(proto_info["name"], proto_id)
        layout.addRow("Protocol:", self.protocol_combo)

        # Username
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("user@example.com")
        layout.addRow("Username:", self.username_edit)

        # Password with show/hide
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._password_visible = False
        self.toggle_password_btn = QPushButton("Show")
        self.toggle_password_btn.setFixedWidth(60)
        self.toggle_password_btn.clicked.connect(self._toggle_password)

        pw_layout = QHBoxLayout()
        pw_layout.addWidget(self.password_edit)
        pw_layout.addWidget(self.toggle_password_btn)
        layout.addRow("Password:", pw_layout)

        # TOTP secret with show/hide
        self.totp_edit = QLineEdit()
        self.totp_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.totp_edit.setPlaceholderText("Base32 secret from authenticator setup")
        self._totp_visible = False
        self.toggle_totp_btn = QPushButton("Show")
        self.toggle_totp_btn.setFixedWidth(60)
        self.toggle_totp_btn.clicked.connect(self._toggle_totp)

        totp_layout = QHBoxLayout()
        totp_layout.addWidget(self.totp_edit)
        totp_layout.addWidget(self.toggle_totp_btn)
        layout.addRow("TOTP Secret:", totp_layout)

        # TOTP test
        test_layout = QHBoxLayout()
        self.test_totp_btn = QPushButton("Test TOTP")
        self.test_totp_btn.clicked.connect(self._test_totp)
        self.totp_result_label = QLabel()
        test_layout.addWidget(self.test_totp_btn)
        test_layout.addWidget(self.totp_result_label)
        test_layout.addStretch()
        layout.addRow("", test_layout)

        # Buttons
        btn_layout = QHBoxLayout()
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear)
        self.save_btn = QPushButton("Save")
        self.save_btn.clicked.connect(self._save)
        btn_layout.addStretch()
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addWidget(self.save_btn)
        layout.addRow("", btn_layout)

    def _toggle_password(self):
        self._password_visible = not self._password_visible
        mode = QLineEdit.EchoMode.Normal if self._password_visible else QLineEdit.EchoMode.Password
        self.password_edit.setEchoMode(mode)
        self.toggle_password_btn.setText("Hide" if self._password_visible else "Show")

    def _toggle_totp(self):
        self._totp_visible = not self._totp_visible
        mode = QLineEdit.EchoMode.Normal if self._totp_visible else QLineEdit.EchoMode.Password
        self.totp_edit.setEchoMode(mode)
        self.toggle_totp_btn.setText("Hide" if self._totp_visible else "Show")

    def _test_totp(self):
        secret = self.totp_edit.text().strip().replace(" ", "").upper()
        if not secret:
            self.totp_result_label.setText("No secret entered")
            self.totp_result_label.setStyleSheet("color: orange;")
            return

        try:
            code = generate_totp(secret)
            self.totp_result_label.setText(f"Current code: {code}")
            self.totp_result_label.setStyleSheet("color: green;")
        except Exception as e:
            self.totp_result_label.setText(f"Invalid: {e}")
            self.totp_result_label.setStyleSheet("color: red;")

    def load_connection(self, name: str, conn: dict):
        """Load a connection for editing."""
        self._editing_name = name
        self.name_edit.setText(name)
        self.name_edit.setEnabled(False)
        self.address_edit.setText(conn.get("address", ""))

        protocol = conn.get("protocol", "anyconnect")
        idx = self.protocol_combo.findData(protocol)
        if idx >= 0:
            self.protocol_combo.setCurrentIndex(idx)

        self.username_edit.setText(conn.get("username", ""))
        self.password_edit.setText(conn.get("password", ""))
        self.totp_edit.setText(conn.get("totp_secret", ""))
        self.totp_result_label.clear()

    def new_connection(self):
        """Prepare form for new connection."""
        self._editing_name = None
        self.clear()
        self.name_edit.setEnabled(True)
        self.name_edit.setFocus()

    def clear(self):
        """Clear all fields."""
        self._editing_name = None
        self.name_edit.clear()
        self.name_edit.setEnabled(True)
        self.address_edit.clear()
        self.protocol_combo.setCurrentIndex(0)
        self.username_edit.clear()
        self.password_edit.clear()
        self.totp_edit.clear()
        self.totp_result_label.clear()

    def _save(self):
        name = self.name_edit.text().strip()
        address = self.address_edit.text().strip()
        protocol = self.protocol_combo.currentData()
        username = self.username_edit.text().strip()
        password = self.password_edit.text()
        totp_secret = self.totp_edit.text().strip().replace(" ", "").upper()

        # Validate
        errors = []
        if not name:
            errors.append("Connection name is required")
        if not address:
            errors.append("Server address is required")
        if not username:
            errors.append("Username is required")
        if not password:
            errors.append("Password is required")
        if not totp_secret:
            errors.append("TOTP secret is required")

        if errors:
            QMessageBox.warning(self, "Validation Error", "\n".join(errors))
            return

        if not validate_secret(totp_secret):
            QMessageBox.warning(self, "Invalid TOTP", "The TOTP secret is invalid.")
            return

        # Check for duplicate
        if self._editing_name is None:
            existing = get_connection(name)
            if existing:
                reply = QMessageBox.question(
                    self, "Connection Exists",
                    f"'{name}' already exists. Overwrite?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return

        if save_connection(name, address, protocol, username, password, totp_secret):
            QMessageBox.information(self, "Saved", f"Connection '{name}' saved.")
            self.saved.emit()
        else:
            QMessageBox.critical(self, "Error", f"Failed to save '{name}'")

    def get_current_name(self) -> Optional[str]:
        return self._editing_name