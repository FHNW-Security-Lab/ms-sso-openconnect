"""Tests for VPN backend module."""

import pytest


class TestVPNBackend:
    """Tests for VPNBackend class."""

    def test_backend_import(self):
        """Test that backend can be imported."""
        from vpn_ui.vpn_backend import VPNBackend
        assert VPNBackend is not None

    def test_get_backend_singleton(self):
        """Test that get_backend returns singleton."""
        from vpn_ui.vpn_backend import get_backend

        backend1 = get_backend()
        backend2 = get_backend()
        assert backend1 is backend2


class TestConstants:
    """Tests for constants module."""

    def test_protocols_defined(self):
        """Test that protocols are defined."""
        from vpn_ui.constants import PROTOCOLS

        assert "anyconnect" in PROTOCOLS
        assert "gp" in PROTOCOLS

    def test_status_constants(self):
        """Test that status constants are defined."""
        from vpn_ui.constants import (
            STATUS_CONNECTED,
            STATUS_CONNECTING,
            STATUS_DISCONNECTED,
        )

        assert STATUS_CONNECTED == "connected"
        assert STATUS_CONNECTING == "connecting"
        assert STATUS_DISCONNECTED == "disconnected"
