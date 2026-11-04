"""Validate the standalone HIP wrapper without executing a real host probe."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("gp_hipreport", Path(__file__).resolve().parents[1] / "codebase/core/gp_hipreport.py")
hipreport = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hipreport)


class HipReportTests(unittest.TestCase):
    def test_reports_detected_distribution_without_frontend_environment(self):
        result = subprocess.CompletedProcess([], 0, "<host><os>old</os><os-vendor>old</os-vendor></host>", "")
        with patch.dict(os.environ, {}, clear=True), patch.object(hipreport, "_find_base_hipreport", return_value="/fixture/hipreport.sh"), patch.object(hipreport.subprocess, "run", return_value=result), patch.object(hipreport.platform, "freedesktop_os_release", return_value={"PRETTY_NAME": "Debian GNU/Linux 13"}), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(hipreport.main(), 0)
        self.assertIn("<os>Debian GNU/Linux 13</os>", output.getvalue())
        self.assertIn("<os-vendor>Linux</os-vendor>", output.getvalue())

    def test_override_is_xml_escaped_and_keeps_literal_backslashes(self):
        result = subprocess.CompletedProcess([], 0, "<host><os>old</os></host>", "")
        with patch.dict(os.environ, {"MS_SSO_GP_OS_VERSION": "Custom & OS \\1"}, clear=True), patch.object(hipreport, "_find_base_hipreport", return_value="/fixture/hipreport.sh"), patch.object(hipreport.subprocess, "run", return_value=result), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(hipreport.main(), 0)
        self.assertIn("<os>Custom &amp; OS \\1</os>", output.getvalue())

    def test_base_failure_is_preserved(self):
        result = subprocess.CompletedProcess([], 4, "failure output", "failure detail")
        with patch.object(hipreport, "_find_base_hipreport", return_value="/fixture/hipreport.sh"), patch.object(hipreport.subprocess, "run", return_value=result), contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(hipreport.main(), 4)
        self.assertEqual(output.getvalue(), "failure output")
        self.assertEqual(errors.getvalue(), "failure detail")

    def test_missing_base_is_actionable_error(self):
        with patch.object(hipreport, "_find_base_hipreport", return_value=None), contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(hipreport.main(), 127)
        self.assertIn("hipreport.sh", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
