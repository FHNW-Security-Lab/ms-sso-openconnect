"""Installer lifecycle metadata checks; never install or close an application."""

import ast
import os
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
