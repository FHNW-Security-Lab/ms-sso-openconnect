"""Opt-in smoke tests for an actual built Debian artifact (no installation)."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.environ.get("MS_SSO_TEST_DEB"), "Set MS_SSO_TEST_DEB to a built .deb")
class DebianArtifactTests(unittest.TestCase):
    def test_extracted_runtime_and_qt_form(self):
        package = str(Path(os.environ["MS_SSO_TEST_DEB"]).resolve())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["dpkg-deb", "-x", package, directory], check=True)
            self.assertFalse(list(root.rglob("*.pyc")))
            self.assertTrue(os.access(root / "usr/bin/ms-sso-openconnect-ui", os.X_OK))
            self.assertTrue(os.access(root / "usr/libexec/ms-sso-openconnect-gp-hipreport", os.X_OK))
            app_dir = root / "opt/ms-sso-openconnect-ui"
            version = subprocess.check_output(["dpkg-deb", "-f", package, "Version"], text=True).strip().rsplit("-", 1)[0]
            env = dict(os.environ, PYTHONPATH=f"{app_dir}/src:{app_dir}",
                       PYTHONDONTWRITEBYTECODE="1", QT_QPA_PLATFORM="offscreen",
                       EXPECTED_VERSION=version, EXPECTED_APP_DIR=str(app_dir))
            code = '''
import os
from pathlib import Path
from PyQt6.QtWidgets import QApplication
from vpn_ui.connection_form import ConnectionForm
from vpn_ui import __version__
from vpn_ui.constants import VERSION, get_icon
import core
import vpn_ui.main
assert Path(core.__file__).is_relative_to(os.environ["EXPECTED_APP_DIR"])
assert Path(vpn_ui.main.__file__).is_relative_to(os.environ["EXPECTED_APP_DIR"])
app = QApplication([])
assert __version__ == VERSION == os.environ["EXPECTED_VERSION"]
assert not get_icon("app-icon").isNull()
form = ConnectionForm(None)
assert form.protocol_combo.count() == 2
form.show()
app.processEvents()
form.close()
print("Debian source, Qt form, application imports, versions, and icon: OK")
'''
            subprocess.run(["/usr/bin/python3", "-c", code], env=env, timeout=30, check=True)


if __name__ == "__main__":
    unittest.main()
