"""Connection form widget for adding/editing VPN connections."""

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

from vpn_ui.constants import PROTOCOLS
from vpn_ui.vpn_backend import VPNBackend


class ConnectionForm(QWidget):
    """Widget for editing VPN connection details."""

    # Signals
    saved = pyqtSignal()  # Emitted when a connection is saved

    def __init__(self, backend: VPNBackend, parent: Optional[QWidget] = None):
        """Initialize the connection form.

        Args:
            backend: VPN backend instance
            parent: Parent widget
        """
        super().__init__(parent)
        self.backend = backend
        self._editing_name: Optional[str] = None  # Name of connection being edited

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the form UI."""
        layout = QFormLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Connection name
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("e.g., work, home, university")
        layout.addRow("Connection Name:", self.name_edit)

        # Server address
        self.address_edit = QLineEdit()
        self.address_edit.setPlaceholderText("vpn.example.com")
        layout.addRow("Server Address:", self.address_edit)

        # Protocol selection
        self.protocol_combo = QComboBox()
        for proto_id, proto_info in PROTOCOLS.items():
            self.protocol_combo.addItem(proto_info["name"], proto_id)
        layout.addRow("Protocol:", self.protocol_combo)

        # Username
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("user@example.com")
        layout.addRow("Username:", self.username_edit)

        # Password
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow("Password:", self.password_edit)

        # Show/hide password button
        self._password_visible = False
        self.toggle_password_btn = QPushButton("Show")
        self.toggle_password_btn.setFixedWidth(60)
        self.toggle_password_btn.clicked.connect(self._toggle_password_visibility)

        password_layout = QHBoxLayout()
        password_layout.addWidget(self.password_edit)
        password_layout.addWidget(self.toggle_password_btn)

        # Replace the password row
        layout.removeRow(4)  # Remove the password row we just added
        layout.insertRow(4, "Password:", password_layout)

        # TOTP secret
        self.totp_edit = QLineEdit()
        self.totp_edit.setPlaceholderText("Base32 TOTP secret (from authenticator app setup)")
        layout.addRow("TOTP Secret:", self.totp_edit)

        # TOTP test section
        test_layout = QHBoxLayout()
        self.totp_test_btn = QPushButton("Test TOTP")
        self.totp_test_btn.clicked.connect(self._test_totp)
        self.totp_result_label = QLabel()
        test_layout.addWidget(self.totp_test_btn)
        test_layout.addWidget(self.totp_result_label)
        test_layout.addStretch()
        layout.addRow("", test_layout)

        # Buttons
        btn_layout = QHBoxLayout()
        self.save_btn = QPushButton("Save")
        self.save_btn.clicked.connect(self._save)
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear)
        btn_layout.addStretch()
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addWidget(self.save_btn)
        layout.addRow("", btn_layout)

    def _toggle_password_visibility(self) -> None:
        """Toggle password field visibility."""
        self._password_visible = not self._password_visible
        if self._password_visible:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle_password_btn.setText("Hide")
        else:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_password_btn.setText("Show")

    def load_connection(self, name: str, conn: dict) -> None:
        """Load a connection into the form for editing.

        Args:
            name: Connection name
            conn: Connection details dictionary
        """
        self._editing_name = name

        self.name_edit.setText(name)
        self.name_edit.setEnabled(False)  # Can't rename existing connections

        self.address_edit.setText(conn.get("address", ""))

        protocol = conn.get("protocol", "anyconnect")
        idx = self.protocol_combo.findData(protocol)
        if idx >= 0:
            self.protocol_combo.setCurrentIndex(idx)

        self.username_edit.setText(conn.get("username", ""))
        self.password_edit.setText(conn.get("password", ""))
        self.totp_edit.setText(conn.get("totp_secret", ""))

        self.totp_result_label.clear()

    def new_connection(self) -> None:
        """Prepare the form for a new connection."""
        self._editing_name = None
        self.clear()
        self.name_edit.setEnabled(True)
        self.name_edit.setFocus()

    def clear(self) -> None:
        """Clear all form fields."""
        self._editing_name = None
        self.name_edit.clear()
        self.name_edit.setEnabled(True)
        self.address_edit.clear()
        self.protocol_combo.setCurrentIndex(0)
        self.username_edit.clear()
        self.password_edit.clear()
        self.totp_edit.clear()
        self.totp_result_label.clear()

    def _test_totp(self) -> None:
        """Test the TOTP secret by generating a code."""
        secret = self.totp_edit.text().strip().replace(" ", "").upper()

        if not secret:
            self.totp_result_label.setText("No secret entered")
            self.totp_result_label.setStyleSheet("color: orange;")
            return

        try:
            code = self.backend.generate_totp(secret)
            self.totp_result_label.setText(f"Current code: {code}")
            self.totp_result_label.setStyleSheet("color: green;")
        except Exception as e:
            self.totp_result_label.setText(f"Invalid: {e}")
            self.totp_result_label.setStyleSheet("color: red;")

    def _save(self) -> None:
        """Save the connection."""
        name = self.name_edit.text().strip()
        address = self.address_edit.text().strip()
        protocol = self.protocol_combo.currentData()
        username = self.username_edit.text().strip()
        password = self.password_edit.text()
        totp_secret = self.totp_edit.text().strip().replace(" ", "").upper()

        # Validation
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
            QMessageBox.warning(
                self,
                "Validation Error",
                "\n".join(errors)
            )
            return

        # Validate TOTP secret
        try:
            self.backend.generate_totp(totp_secret)
        except Exception as e:
            QMessageBox.warning(
                self,
                "Invalid TOTP Secret",
                f"The TOTP secret is invalid:\n{e}\n\n"
                "Please enter a valid Base32-encoded secret."
            )
            return

        # Check for duplicate name when adding new connection
        if self._editing_name is None:
            existing = self.backend.get_connection(name)
            if existing:
                reply = QMessageBox.question(
                    self,
                    "Connection Exists",
                    f"A connection named '{name}' already exists.\n"
                    "Do you want to overwrite it?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return

        # Save
        success = self.backend.save_connection(
            name, address, protocol, username, password, totp_secret
        )

        if success:
            QMessageBox.information(
                self,
                "Saved",
                f"Connection '{name}' saved successfully"
            )
            self.saved.emit()
        else:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to save connection '{name}'"
            )

    def get_current_name(self) -> Optional[str]:
        """Get the name of the connection currently being edited.

        Returns:
            Connection name or None if creating new
        """
        return self._editing_name
