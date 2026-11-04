#!/usr/bin/env python3

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "codebase"))

from core.platform_info import (  # noqa: E402
    DEFAULT_GP_OS_VERSION, get_gp_os_version, get_gp_client_os, _detect_os_version,
)


class GlobalProtectOsVersionTests(unittest.TestCase):
    def test_macos_reports_its_native_client_and_version(self):
        with patch.dict(os.environ, {"MS_SSO_GP_CLIENT_OS": ""}), patch(
            "core.platform_info.platform.system", return_value="Darwin"
        ), patch("core.platform_info.platform.mac_ver", return_value=("15.4", (), "")):
            self.assertEqual(get_gp_client_os(), "Mac")
            self.assertEqual(_detect_os_version(), "macOS 15.4")

    def test_explicit_client_os_override_wins(self):
        with patch.dict(os.environ, {"MS_SSO_GP_CLIENT_OS": "Windows"}):
            self.assertEqual(get_gp_client_os(), "Windows")

    @patch("core.platform_info._detect_os_version", return_value="Arch Linux")
    def test_empty_setting_detects_the_host_distribution(self, _detect):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MS_SSO_GP_OS_VERSION", None)
            self.assertEqual(get_gp_os_version(), "Arch Linux")

    @patch("core.platform_info._detect_os_version", return_value="NixOS 26.05")
    def test_auto_setting_detects_the_host_distribution(self, _detect):
        with patch.dict(os.environ, {"MS_SSO_GP_OS_VERSION": "auto"}):
            self.assertEqual(get_gp_os_version(), "NixOS 26.05")

    @patch("core.platform_info._detect_os_version")
    def test_explicit_compatibility_override_wins(self, detect):
        with patch.dict(
            os.environ,
            {"MS_SSO_GP_OS_VERSION": "Ubuntu 24.04 LTS"},
        ):
            self.assertEqual(get_gp_os_version(), "Ubuntu 24.04 LTS")
        detect.assert_not_called()

    @patch("core.platform_info._detect_os_version", return_value=None)
    def test_detection_failure_uses_safe_fallback(self, _detect):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MS_SSO_GP_OS_VERSION", None)
            self.assertEqual(get_gp_os_version(), DEFAULT_GP_OS_VERSION)


if __name__ == "__main__":
    unittest.main()
