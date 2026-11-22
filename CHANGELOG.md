# Changelog

All notable changes to this project are listed here. The format follows Keep a Changelog.

## [Unreleased]

## [0.2.1]

### Security
- Reduce accidental credential exposure in reports using best-effort redaction and by omitting arbitrary launch arguments and tool-description evidence. Review reports before sharing; redaction cannot guarantee detection of every secret.
- Store hashes instead of raw connection fields in newly pinned baselines. Existing baseline files are not automatically rewritten and may still contain sensitive values. Hashes are not encryption.
- Parse URL hostnames and IP addresses to distinguish loopback endpoints from similarly named remote hosts.

### Changed
- README: install from PyPI documented, and links made absolute so they also work on the PyPI project page.
- Preserve server names, rule IDs and finding titles when masking values. Show selected recognizable package names and permission flags as evidence.
- Report authentication as unknown when it is not visible in configuration, and show per-server inspection status. The default human-readable report no longer displays a numerical security score; the legacy JSON score remains for compatibility.
- Use SARIF v2 fingerprints based on rule, server and finding subject. Existing code-scanning alerts may be treated as new after migration from v1.

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
