# Changelog

All notable changes to this project are listed here. The format follows Keep a Changelog.

## [0.2.0]

### Added
- SARIF 2.1.0 output with `--sarif-out`, so findings can appear in the GitHub Security tab and on pull requests.
- A reusable GitHub Action (`action.yml`) that installs the scanner, scans a config file, uploads SARIF to Code Scanning and fails the job on a severity threshold.
- `--version` flag.
- `SECURITY.md` with a private vulnerability reporting process.
- PyPI packaging metadata and a tag-triggered release workflow (see `docs/RELEASING.md`).

### Changed
- Package metadata now follows current packaging standards (SPDX license expression, project URLs).

## [0.1.0]

- First public version: static config checks, tool description heuristics, optional live introspection, optional LLM judge, baseline pin and diff, Markdown and JSON reports.
