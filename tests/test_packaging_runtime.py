"""Exercise Debian installer control flow without root, network, or host changes."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PACKAGING = ROOT / "frontends/linux/packaging"


class InstallerTests(unittest.TestCase):
    def run_installer(self, *, missing_driver=False, missing_browser=False, broken_browser=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            (runtime / "venv/bin").mkdir(parents=True)
            (runtime / "venv/pyvenv.cfg").write_text("include-system-site-packages = false\n")
            fake_python = runtime / "venv/bin/python"
            fake_python.write_text('''#!/usr/bin/python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ["TEST_ROOT"])
with (root / "calls").open("a") as output:
    output.write(json.dumps(sys.argv[1:]) + "\\n")
args = " ".join(sys.argv[1:])
if "from importlib.metadata" in args and os.environ["MISSING_DRIVER"] == "1":
    sys.exit(1)
if "chromium.launch" in args:
    if os.environ["BROKEN_BROWSER"] == "1":
        sys.exit(1)
    if os.environ["MISSING_BROWSER"] == "1" and not (root / "installed").exists():
        sys.exit(1)
if "-m playwright install chromium" in args:
    (root / "installed").touch()
''')
            fake_python.chmod(0o755)
            script = root / "postinst"
            script.write_text((PACKAGING / "debian/postinst").read_text().replace(
                'INSTALL_DIR="/opt/ms-sso-openconnect-ui"', f'INSTALL_DIR="{runtime}"'
            ))
            env = dict(os.environ, TEST_ROOT=str(root), MISSING_DRIVER=str(int(missing_driver)),
                       MISSING_BROWSER=str(int(missing_browser)), BROKEN_BROWSER=str(int(broken_browser)))
            result = subprocess.run(["bash", str(script), "configure"], env=env, capture_output=True, text=True)
            calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
            self.assertIn("include-system-site-packages = true", (runtime / "venv/pyvenv.cfg").read_text())
            return result, calls

    def test_upgrade_reuses_verified_driver_and_browser(self):
        result, calls = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any("install" in call for call in calls))
        self.assertTrue(any("core, vpn_ui" in " ".join(call) for call in calls))

    def test_missing_driver_and_browser_are_repaired(self):
        result, calls = self.run_installer(missing_driver=True, missing_browser=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(["-m", "pip", "install", "--upgrade", "playwright>=1.55,<2"], calls)
        self.assertIn(["-m", "playwright", "install", "chromium"], calls)
        self.assertEqual(sum("chromium.launch" in " ".join(call) for call in calls), 2)

    def test_browser_failure_is_not_silently_accepted(self):
        result, _ = self.run_installer(broken_browser=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Chromium cannot start", result.stderr)

    def test_launcher_imports_packaged_source_before_legacy_site_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "venv/bin").mkdir(parents=True)
            python = root / "venv/bin/python"
            python.write_text('#!/usr/bin/python3\nimport json, os, sys\nprint(json.dumps([os.environ["PYTHONPATH"], os.environ["PLAYWRIGHT_BROWSERS_PATH"], sys.argv[1:]]))\n')
            python.chmod(0o755)
            launcher = root / "launch"
            launcher.write_text((PACKAGING / "ms-sso-openconnect-ui").read_text().replace(
                'INSTALL_DIR=/opt/ms-sso-openconnect-ui', f'INSTALL_DIR="{root}"'))
            env = dict(os.environ)
            env.pop("PYTHONPATH", None)
            result = subprocess.run(["sh", str(launcher), "--test"], env=env, text=True, capture_output=True, check=True)
            paths, browsers, args = json.loads(result.stdout)
            self.assertEqual(paths, f"{root}/src:{root}")
            self.assertEqual(browsers, str(root / "browsers"))
            self.assertEqual(args, ["-m", "vpn_ui", "--test"])

    def test_privileged_openconnect_requires_admin(self):
        policy = ET.parse(PACKAGING / "polkit/org.openconnect.policy")
        actions = policy.findall("action")
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].findtext("defaults/allow_active"), "auth_admin_keep")


if __name__ == "__main__":
    unittest.main()
