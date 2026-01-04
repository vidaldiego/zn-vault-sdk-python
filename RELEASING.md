# Releasing

This SDK uses automated tag-based releases via GitHub Actions.

## How to Release

1. **Update version** in `pyproject.toml`:
   ```toml
   version = "X.Y.Z"
   ```

2. **Commit and push**:
   ```bash
   git add pyproject.toml
   git commit -m "chore: bump version to X.Y.Z"
   git push origin main
   ```

3. **Create and push tag**:
   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

GitHub Actions will automatically:
- Build the package
- Publish to PyPI

## GitHub Secrets Required

| Secret | Description |
|--------|-------------|
| `PYPI_API_TOKEN` | PyPI API token scoped to `znvault` project |

## Verifying Release

After pushing a tag, check:
1. [GitHub Actions](https://github.com/vidaldiego/zn-vault-sdk-python/actions) - workflow status
2. [PyPI](https://pypi.org/project/znvault/) - published version
