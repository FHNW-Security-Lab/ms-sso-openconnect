# MS SSO OpenConnect UI (Shared Qt Code)

Shared Qt code used by both Linux and macOS frontends.

## Run for development

```bash
cd codebase/ui
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
playwright install chromium
python -m vpn_ui
```

## Frontend-specific packaging

- Linux packaging/build: `frontends/linux/`
- macOS packaging/build: `frontends/osx/`
