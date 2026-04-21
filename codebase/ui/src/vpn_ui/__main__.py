"""Entry point for running the VPN UI as a module."""

import os
import sys
from pathlib import Path


def _point_playwright_at_bundled_browsers() -> None:
    """When running from a packaged macOS .app, point Playwright at the
    Chromium installed inside Contents/Resources/browsers/ by the build
    script. Without this, Playwright falls back to ~/.cache/ms-playwright
    and tries to download a fresh browser at first auth — which fails on
    fresh Macs without network / write access to that path.
    """
    if "PLAYWRIGHT_BROWSERS_PATH" in os.environ:
        return
    if not getattr(sys, "frozen", False) or sys.platform != "darwin":
        return

    # sys.executable is .../MS SSO OpenConnect.app/Contents/MacOS/<bin>
    contents = Path(sys.executable).resolve().parent.parent
    if contents.name != "Contents":
        return
    browsers = contents / "Resources" / "browsers"
    if browsers.is_dir():
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(browsers)


_point_playwright_at_bundled_browsers()

from vpn_ui.main import main  # noqa: E402

if __name__ == "__main__":
    main()
