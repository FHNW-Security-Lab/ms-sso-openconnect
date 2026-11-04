"""Installer lifecycle checks; never install or manage real services or apps."""

import ast
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "frontends/osx/scripts/build-macos.sh"


def ui_bundle_identifier():
    tree = ast.parse((ROOT / "codebase/ui/src/vpn_ui/constants.py").read_text())
    assignment = next(
        node for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "APP_ID"
                for target in node.targets)
    )
    return ast.literal_eval(assignment.value)


class MacOSInstallerMetadataTests(unittest.TestCase):
    def assert_ui_must_close(self, distribution):
        root = ET.fromstring(distribution)
        selected_packages = {
            package.attrib["id"]
            for choice in root.findall("choice")
            for package in choice.findall("pkg-ref")
        }
        payload_packages = {
            package.attrib["id"]
            for package in root.findall("pkg-ref")
            if (package.text or "").strip().endswith(".pkg")
        }
        self.assertTrue(selected_packages & payload_packages)
        required_apps = {
            app.attrib["id"]
            for package in root.findall("pkg-ref")
            if package.attrib["id"] in selected_packages & payload_packages
            for app in package.findall("must-close/app")
        }
        self.assertEqual(required_apps, {ui_bundle_identifier()})

    def test_generated_distribution_requires_installed_gui_to_close(self):
        # Execute only the builder's real metadata-generation stanza. No app
        # build, package build, installation, or process management is performed.
        stanza = re.search(
            r'^cat > "\$BUILD_DIR/Distribution\.xml" << DISTRIBUTION\n.*?\nDISTRIBUTION$',
            BUILDER.read_text(), re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(stanza, "Cannot locate the distribution-generation stanza")
        with tempfile.TemporaryDirectory(prefix="msso-installer-metadata-") as directory:
            env = dict(os.environ, BUILD_DIR=directory, VERSION="9.8.7", MIN_MACOS="15.0")
            subprocess.run(["bash", "-eu", "-c", stanza.group()], env=env, check=True)
            distribution = (Path(directory) / "Distribution.xml").read_text()
        self.assert_ui_must_close(distribution)
        root = ET.fromstring(distribution)
        self.assertTrue(any(package.attrib.get("version") == "9.8.7"
                            for package in root.findall("pkg-ref")))

    @unittest.skipUnless(os.environ.get("MS_SSO_TEST_PKG") and shutil.which("pkgutil"),
                         "Set MS_SSO_TEST_PKG to a built macOS .pkg")
    def test_built_installer_retains_gui_closure_requirement(self):
        package = str(Path(os.environ["MS_SSO_TEST_PKG"]).resolve())
        with tempfile.TemporaryDirectory(prefix="msso-installer-artifact-") as directory:
            expanded = Path(directory) / "expanded"
            subprocess.run(["pkgutil", "--expand", package, str(expanded)], check=True,
                           capture_output=True, text=True)
            self.assert_ui_must_close((expanded / "Distribution").read_text())


class MacOSInstallerShutdownTests(unittest.TestCase):
    def run_preinstall(self, present_checks, bootout_status=0):
        # Generate the actual packaged script, then isolate every external
        # command behind fakes. In particular, rm never touches installed files.
        stanza = re.search(
            r'^cat > "\$SCRIPTS_DIR/preinstall" << \'PREINSTALL\'\n.*?\nPREINSTALL$',
            BUILDER.read_text(), re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(stanza, "Cannot locate the preinstall-generation stanza")
        with tempfile.TemporaryDirectory(prefix="msso-installer-shutdown-") as directory:
            root = Path(directory)
            env = dict(os.environ, SCRIPTS_DIR=directory)
            subprocess.run(["/bin/bash", "-eu", "-c", stanza.group()], env=env,
                           check=True, capture_output=True, text=True)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            calls_path = root / "calls"
            checks_path = root / "checks"
            checks_path.write_text("0\n")
            commands = {
                "launchctl": '''#!/bin/bash
printf 'launchctl %s\\n' "$*" >> "$TEST_CALLS"
case "$1" in
    bootout) exit "$TEST_BOOTOUT_STATUS" ;;
    print)
        read -r checks < "$TEST_CHECKS"
        checks=$((checks + 1))
        printf '%s\\n' "$checks" > "$TEST_CHECKS"
        (( checks <= TEST_PRESENT_CHECKS ))
        ;;
    *) exit 99 ;;
esac
''',
                "sleep": '''#!/bin/bash
printf 'sleep %s\\n' "$*" >> "$TEST_CALLS"
''',
                "rm": '''#!/bin/bash
printf 'rm %s\\n' "$*" >> "$TEST_CALLS"
''',
            }
            for name, content in commands.items():
                command = fake_bin / name
                command.write_text(content)
                command.chmod(0o755)
            env.update(PATH=str(fake_bin), TEST_CALLS=str(calls_path),
                       TEST_CHECKS=str(checks_path),
                       TEST_PRESENT_CHECKS=str(present_checks),
                       TEST_BOOTOUT_STATUS=str(bootout_status))
            result = subprocess.run(["/bin/bash", str(root / "preinstall")],
                                    env=env, capture_output=True, text=True, timeout=5)
            calls = calls_path.read_text().splitlines()
        self.assertEqual(calls[0], "launchctl bootout system/com.github.ms-sso-openconnect.daemon")
        self.assertTrue(all(call in {
            "launchctl bootout system/com.github.ms-sso-openconnect.daemon",
            "launchctl print system/com.github.ms-sso-openconnect.daemon",
            "sleep 1",
            "rm -f /var/run/ms-sso-openconnect/daemon.sock",
            "rm -f /Library/PrivilegedHelperTools/ms-sso-openconnect-daemon",
        } for call in calls))
        return result, calls

    def assert_cleanup_completed(self, calls):
        self.assertEqual(calls[-2:], [
            "rm -f /var/run/ms-sso-openconnect/daemon.sock",
            "rm -f /Library/PrivilegedHelperTools/ms-sso-openconnect-daemon",
        ])

    def test_preinstall_waits_for_asynchronous_launchd_shutdown(self):
        plist = plistlib.loads((ROOT / "frontends/osx/daemon/com.github.ms-sso-openconnect.daemon.plist").read_bytes())
        # Simulate launchd removing the job just after its configured exit time.
        delayed_checks = plist["ExitTimeOut"] + 1
        result, calls = self.run_preinstall(present_checks=delayed_checks)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls.count("sleep 1"), delayed_checks)
        self.assertEqual(sum(call.startswith("launchctl print ") for call in calls),
                         delayed_checks + 1)
        self.assert_cleanup_completed(calls)

    def test_preinstall_accepts_already_absent_helper_without_waiting(self):
        result, calls = self.run_preinstall(present_checks=0, bootout_status=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("sleep 1", calls)
        self.assert_cleanup_completed(calls)

    def test_preinstall_accepts_shutdown_at_final_poll(self):
        result, calls = self.run_preinstall(present_checks=35)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls.count("sleep 1"), 35)
        self.assert_cleanup_completed(calls)

    def test_preinstall_fails_boundedly_without_cleanup_if_service_stays(self):
        result, calls = self.run_preinstall(present_checks=1000)
        self.assertEqual(result.returncode, 1)
        self.assertIn("previous VPN helper could not be stopped", result.stderr)
        self.assertEqual(calls.count("sleep 1"), 35)
        self.assertEqual(sum(call.startswith("launchctl print ") for call in calls), 36)
        self.assertFalse(any(call.startswith("rm ") for call in calls))


if __name__ == "__main__":
    unittest.main()
