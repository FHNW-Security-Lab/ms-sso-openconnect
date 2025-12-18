"""Settings dialog."""

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

from core import get_connections, delete_connection, PROTOCOLS

from .autostart import is_autostart_enabled, set_autostart
from .connection_form import ConnectionForm
from .constants import APP_NAME


class SettingsDialog(QDialog):
    """Dialog for managing VPN connections and settings."""

    connections_changed = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle(f"{APP_NAME} - Settings")
        self.setMinimumSize(700, 450)
        self.resize(800, 500)
        self._setup_ui()
        self._load_connections()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        tabs = QTabWidget()
        layout.addWidget(tabs)

        # Connections tab
        tabs.addTab(self._create_connections_tab(), "Connections")

        # Application tab
        tabs.addTab(self._create_app_tab(), "Application")

    def _create_connections_tab(self) -> QWidget:
        tab = QWidget()
        layout = QHBoxLayout(tab)

        splitter = QSplitter()

        # Left: connection list
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)

        left_layout.addWidget(QLabel("<b>VPN Connections</b>"))

        self.conn_list = QListWidget()
        self.conn_list.currentItemChanged.connect(self._on_selection_changed)
        self.conn_list.setMinimumWidth(200)
        left_layout.addWidget(self.conn_list)

        btn_layout = QHBoxLayout()
        self.add_btn = QPushButton("Add")
        self.add_btn.clicked.connect(self._on_add)
        self.delete_btn = QPushButton("Delete")
        self.delete_btn.clicked.connect(self._on_delete)
        self.delete_btn.setEnabled(False)
        btn_layout.addWidget(self.add_btn)
        btn_layout.addWidget(self.delete_btn)
        left_layout.addLayout(btn_layout)

        splitter.addWidget(left)

        # Right: connection form
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)

        self._form_header = QLabel("<b>Connection Details</b>")
        right_layout.addWidget(self._form_header)

        self.form = ConnectionForm()
        self.form.saved.connect(self._on_saved)
        right_layout.addWidget(self.form)

        splitter.addWidget(right)
        splitter.setSizes([250, 500])

        layout.addWidget(splitter)
        return tab

    def _create_app_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Startup group
        startup_group = QGroupBox("Startup")
        startup_layout = QVBoxLayout(startup_group)

        self.autostart_check = QCheckBox("Start automatically when you log in")
        self.autostart_check.setChecked(is_autostart_enabled())
        self.autostart_check.stateChanged.connect(self._on_autostart_changed)
        startup_layout.addWidget(self.autostart_check)

        note = QLabel(
            "<i>Note: Only the tray icon starts. VPN connects manually.</i>"
        )
        note.setStyleSheet("color: gray; font-size: 11px;")
        startup_layout.addWidget(note)

        layout.addWidget(startup_group)
        layout.addStretch()

        return tab

    def _load_connections(self):
        self.conn_list.clear()
        connections = get_connections()

        for name, details in connections.items():
            protocol = details.get("protocol", "anyconnect")
            proto_info = PROTOCOLS.get(protocol, PROTOCOLS["anyconnect"])

            item = QListWidgetItem(name)
            item.setToolTip(f"{proto_info['name']}\n{details.get('address', '')}")
            item.setData(256, name)
            self.conn_list.addItem(item)

        if self.conn_list.count() == 0:
            self.form.new_connection()
            self._form_header.setText("<b>Add New Connection</b>")

    def _on_selection_changed(self, current: Optional[QListWidgetItem], previous):
        if current:
            name = current.data(256)
            connections = get_connections()
            conn = connections.get(name)
            if conn:
                self.form.load_connection(name, conn)
                self._form_header.setText(f"<b>Edit: {name}</b>")
                self.delete_btn.setEnabled(True)
        else:
            self.form.clear()
            self._form_header.setText("<b>Connection Details</b>")
            self.delete_btn.setEnabled(False)

    def _on_add(self):
        self.conn_list.clearSelection()
        self.form.new_connection()
        self._form_header.setText("<b>Add New Connection</b>")
        self.delete_btn.setEnabled(False)

    def _on_delete(self):
        current = self.conn_list.currentItem()
        if not current:
            return

        name = current.data(256)
        reply = QMessageBox.question(
            self, "Delete Connection",
            f"Delete '{name}'? This also removes cached cookies.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            if delete_connection(name):
                self._load_connections()
                self.connections_changed.emit()
            else:
                QMessageBox.critical(self, "Error", f"Failed to delete '{name}'")

    def _on_saved(self):
        self._load_connections()

        saved_name = self.form.get_current_name()
        if saved_name:
            for i in range(self.conn_list.count()):
                item = self.conn_list.item(i)
                if item and item.data(256) == saved_name:
                    self.conn_list.setCurrentItem(item)
                    break

        self.connections_changed.emit()

    def _on_autostart_changed(self, state: int):
        enabled = state == 2
        if not set_autostart(enabled):
            self.autostart_check.blockSignals(True)
            self.autostart_check.setChecked(not enabled)
            self.autostart_check.blockSignals(False)
            QMessageBox.warning(
                self, "Error",
                f"Failed to {'enable' if enabled else 'disable'} autostart."
            )