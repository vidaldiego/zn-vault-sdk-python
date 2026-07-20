# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

ZnVault Python SDK (`znvault`) is the official Python client library for ZnVault secrets management. It provides full coverage of the ZnVault REST API with type hints and Pydantic models.

### Relationship to ZnVault Server

This SDK is part of the ZnVault ecosystem. The parent directory (`../`) contains the main ZnVault server - see `../CLAUDE.md` for server documentation.

```
zn-vault/                    # Parent - Vault server
├── src/                     # Server source code
├── zn-vault-sdk-python/     # THIS REPO - Python SDK
├── zn-vault-sdk-node/       # Node.js SDK
├── zn-vault-sdk-swift/      # Swift SDK
├── zn-vault-sdk-jvm/        # Kotlin/Java SDK
├── zn-vault-agent/          # Agent for certificate/secret sync
├── znvault-cli/             # Admin CLI
└── vault-secrets-app/       # macOS app
```

## Development Commands

```bash
# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ --cov=znvault

# Type checking
mypy src/znvault

# Linting
ruff check src/

# Format code
ruff format src/
```

### Integration Test Setup

Integration tests require a running vault instance:

```bash
# Set environment variables
export ZNVAULT_BASE_URL=https://localhost:8443
export ZNVAULT_USERNAME=admin
export ZNVAULT_PASSWORD=your-password

# Run integration tests
./test-integration.sh
```

## Architecture

```
src/znvault/
├── __init__.py           # Main exports
├── client.py             # ZnVaultClient builder and configuration
├── http_client.py        # HTTP client with retries and auth
├── auth.py               # Authentication (JWT, API key)
├── secrets.py            # Secrets client
├── kms.py                # KMS client
├── users.py              # User management client
├── roles.py              # Role management client
├── tenants.py            # Tenant management client
├── policies.py           # ABAC policy client
├── audit.py              # Audit log client
├── health.py             # Health check client
├── models/               # Pydantic models
│   ├── secret.py
│   ├── kms.py
│   ├── user.py
│   └── ...
└── exceptions.py         # Exception classes
```

## Release Process

**Publishing is handled automatically by GitHub Actions CI/CD.**

### Steps to Release

1. Update version in `pyproject.toml`:
   ```toml
   [project]
   version = "X.Y.Z"
   ```

2. Commit the version bump:
   ```bash
   git add pyproject.toml
   git commit -m "chore(release): vX.Y.Z"
   ```

3. Create and push tag:
   ```bash
   git tag vX.Y.Z
   git push origin main
   git push origin vX.Y.Z
   ```

4. GitHub Actions automatically:
   - Runs tests
   - Builds the wheel and sdist
   - Publishes to PyPI using trusted publishing (OIDC)

### PyPI Package

- **Package:** `znvault`
- **Registry:** https://pypi.org/project/znvault/

### Verification

```bash
# Check published version
pip index versions znvault

# Install latest
pip install znvault
```

### CI/CD Configuration

The GitHub Actions workflow (`.github/workflows/publish.yml`) handles:
- Running tests on PRs
- Publishing to PyPI on version tags (`v*`)
- OIDC-based PyPI trusted publishing (no API token needed)

## Code Standards

- **Python**: 3.9+ with type hints
- **Type Checking**: mypy with strict mode
- **Linting**: ruff for code quality
- **Testing**: pytest for unit and integration tests
- **Models**: Pydantic for request/response validation
