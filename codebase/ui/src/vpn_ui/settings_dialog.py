"""Settings dialog for managing VPN connections."""

import sys
from typing import Optional

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from vpn_ui.connection_form import ConnectionForm
from vpn_ui.constants import APP_NAME, PROTOCOLS

# Platform-specific autostart import
if sys.platform == "darwin":
    from vpn_ui.platform.autostart import is_autostart_enabled, set_autostart
else:
    from vpn_ui.platform.autostart import is_autostart_enabled, set_autostart


class SettingsDialog(QDialog):
    """Dialog for managing VPN connections."""

    # Signals
    connections_changed = pyqtSignal()  # Emitted when connections are modified

    def __init__(self, backend, parent: Optional[QWidget] = None):
        """Initialize the settings dialog.

        Args:
            backend: VPN backend instance
            parent: Parent widget
        """
        super().__init__(parent)
        self.backend = backend

        self.setWindowTitle(f"{APP_NAME} - Settings")
        self.setMinimumSize(700, 450)
        self.resize(800, 500)

        self._setup_ui()
        self._load_connections()

    def _setup_ui(self) -> None:
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)

        # Create tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        # Tab 1: Connections
        connections_tab = self._create_connections_tab()
        self.tab_widget.addTab(connections_tab, "Connections")

        # Tab 2: Application Settings
        app_settings_tab = self._create_app_settings_tab()
        self.tab_widget.addTab(app_settings_tab, "Application")

    def _create_connections_tab(self) -> QWidget:
        """Create the connections management tab.

        Returns:
            Widget containing connections UI
        """
        tab = QWidget()
        layout = QHBoxLayout(tab)

        # Create splitter for resizable panels
        splitter = QSplitter()

        # Left panel: connection list
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        # Header
        header = QLabel("<b>VPN Connections</b>")
        left_layout.addWidget(header)

        # Connection list
        self.connection_list = QListWidget()
        self.connection_list.currentItemChanged.connect(self._on_selection_changed)
        self.connection_list.setMinimumWidth(200)
        left_layout.addWidget(self.connection_list)

        # Buttons
        btn_layout = QHBoxLayout()
        self.add_btn = QPushButton("Add")
        self.add_btn.clicked.connect(self._on_add)
        self.delete_btn = QPushButton("Delete")
        self.delete_btn.clicked.connect(self._on_delete)
        self.delete_btn.setEnabled(False)
        btn_layout.addWidget(self.add_btn)
        btn_layout.addWidget(self.delete_btn)
        left_layout.addLayout(btn_layout)

        splitter.addWidget(left_widget)

        # Right panel: connection form
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)

        # Header (changes based on add/edit mode)
        self._form_header = QLabel("<b>Connection Details</b>")
        right_layout.addWidget(self._form_header)

        # Form
        self.form_widget = ConnectionForm(self.backend)
        self.form_widget.saved.connect(self._on_saved)
        right_layout.addWidget(self.form_widget)

        splitter.addWidget(right_widget)

        # Set initial splitter sizes (1:2 ratio)
        splitter.setSizes([250, 500])

        layout.addWidget(splitter)

        return tab

    def _create_app_settings_tab(self) -> QWidget:
        """Create the application settings tab.

        Returns:
            Widget containing application settings
        """
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Startup settings group
        startup_group = QGroupBox("Startup")
        startup_layout = QVBoxLayout(startup_group)

        self.autostart_checkbox = QCheckBox("Start automatically when you log in")
        self.autostart_checkbox.setToolTip(
            "Launch the application automatically when you log into your desktop.\n"
            "The VPN will NOT connect automatically - only the tray icon will appear."
        )
        self.autostart_checkbox.setChecked(is_autostart_enabled())
        self.autostart_checkbox.stateChanged.connect(self._on_autostart_changed)
        startup_layout.addWidget(self.autostart_checkbox)

        # Add note about behavior
        note_label = QLabel(
            "<i>Note: Only the application starts automatically. "
            "VPN connection must be initiated manually from the tray menu.</i>"
        )
        note_label.setWordWrap(True)
        note_label.setStyleSheet("color: gray; font-size: 11px;")
        startup_layout.addWidget(note_label)

        layout.addWidget(startup_group)

        # Add stretch to push everything to the top
        layout.addStretch()

        return tab

    def _on_autostart_changed(self, state: int) -> None:
        """Handle autostart checkbox state change.

        Args:
            state: Checkbox state (0=unchecked, 2=checked)
        """
        enabled = state == 2  # Qt.CheckState.Checked
        success = set_autostart(enabled)

        if not success:
            # Revert the checkbox if operation failed
            self.autostart_checkbox.blockSignals(True)
            self.autostart_checkbox.setChecked(not enabled)
            self.autostart_checkbox.blockSignals(False)

            if sys.platform == "darwin":
                path_hint = "~/Library/LaunchAgents/"
            else:
                path_hint = "~/.config/autostart/"

            QMessageBox.warning(
                self,
                "Error",
                f"Failed to {'enable' if enabled else 'disable'} autostart.\n\n"
                f"Please check file permissions for {path_hint}"
            )

    def _load_connections(self) -> None:
        """Load connections into the list."""
        self.connection_list.clear()
        connections = self.backend.get_connections()

        for name, details in connections.items():
            protocol = details.get("protocol", "anyconnect")
            protocol_info = PROTOCOLS.get(protocol, PROTOCOLS["anyconnect"])
            protocol_name = protocol_info["name"]

            item = QListWidgetItem(f"{name}")
            item.setToolTip(f"{protocol_name}\n{details.get('address', '')}")
            item.setData(256, name)  # Store name in item data
            self.connection_list.addItem(item)

        # Update form state
        if self.connection_list.count() == 0:
            self.form_widget.new_connection()
            self._form_header.setText("<b>Add New Connection</b>")

    def _on_selection_changed(
        self,
        current: Optional[QListWidgetItem],
        previous: Optional[QListWidgetItem]
    ) -> None:
        """Handle connection list selection change.

        Args:
            current: Currently selected item
            previous: Previously selected item
        """
        if current:
            name = current.data(256)  # Get stored name
            conn = self.backend.get_connection(name)
            if conn:
                self.form_widget.load_connection(name, conn)
                self._form_header.setText(f"<b>Edit Connection: {name}</b>")
                self.delete_btn.setEnabled(True)
        else:
            self.form_widget.clear()
            self._form_header.setText("<b>Connection Details</b>")
            self.delete_btn.setEnabled(False)

    def _on_add(self) -> None:
        """Handle Add button click."""
        self.connection_list.clearSelection()
        self.form_widget.new_connection()
        self._form_header.setText("<b>Add New Connection</b>")
        self.delete_btn.setEnabled(False)

    def _on_delete(self) -> None:
        """Handle Delete button click."""
        current = self.connection_list.currentItem()
        if not current:
            return

        name = current.data(256)

        reply = QMessageBox.question(
            self,
            "Delete Connection",
            f"Are you sure you want to delete connection '{name}'?\n\n"
            "This will also remove any cached session cookies.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            success = self.backend.delete_connection(name)
            if success:
                self._load_connections()
                self.connections_changed.emit()
            else:
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to delete connection '{name}'"
                )

    def _on_saved(self) -> None:
        """Handle form save signal."""
        # Reload connections list
        self._load_connections()

        # Select the saved connection
        saved_name = self.form_widget.get_current_name()
        if saved_name:
            for i in range(self.connection_list.count()):
                item = self.connection_list.item(i)
                if item and item.data(256) == saved_name:
                    self.connection_list.setCurrentItem(item)
                    break

        self.connections_changed.emit()

    def get_connections(self) -> dict:
        """Get all connections.

        Returns:
            Dictionary of connections
        """
        return self.backend.get_connections()
