# Codebase

This directory defines the architectural boundary of the shared code used by all frontends.

## Shared Runtime

- `codebase/core/` is the shared runtime library:
  - SAML/MS login automation
  - credential and cookie storage
  - OpenConnect lifecycle handling
  - TOTP support

## CLI

- `ms-sso-openconnect.py` is the CLI entrypoint that consumes `codebase/core/`.
- `ms-sso-openconnect` is a bootstrap wrapper that prepares a local Python environment and launches the CLI.

## Frontend Contracts

All frontends must call into `codebase/core/` for auth/connect logic and must not duplicate protocol-specific logic.
