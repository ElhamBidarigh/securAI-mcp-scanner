# Releasing to PyPI

Publishing is triggered by pushing a version tag. It uses PyPI "trusted publishing", so no API token is stored anywhere.

## One-time setup

1. Create an account on pypi.org and turn on two-factor authentication.
2. On PyPI go to **Your account > Publishing** and add a **pending publisher** with:
   - PyPI project name: `securai-mcp-scanner`
   - Owner: `ElhamBidarigh`
   - Repository: `securAI-mcp-scanner`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
3. On GitHub go to **Settings > Environments > New environment**, name it `pypi`. Optionally add yourself as a required reviewer, so every release needs your click.

## Each release

1. Update the version in `pyproject.toml` and `mcp_trust_scanner/__init__.py`, and add an entry to `CHANGELOG.md`.
2. Commit and push to `main`, and wait for the tests to pass.
3. Tag and push the tag:
   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```
4. Watch the **Release to PyPI** workflow in the Actions tab. When it is green, check https://pypi.org/project/securai-mcp-scanner/ and try `pip install securai-mcp-scanner` in a fresh virtual environment.
5. Update the README install section to mention `pip install securai-mcp-scanner`.

A published version number can never be reused or replaced, so check the tests and the changelog before tagging.

## Local dry run

```bash
python -m pip install build twine
python -m build
python -m twine check dist/*
```
