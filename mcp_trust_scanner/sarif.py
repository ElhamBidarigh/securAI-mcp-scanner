"""
SARIF 2.1.0 export.

SARIF is the standard format for static analysis results. GitHub Code Scanning
reads it, so findings show up in the repository's Security tab and on pull
requests. Use it with:

    mcp-trust-scanner scan .mcp.json --sarif-out results.sarif

and upload the file with github/codeql-action/upload-sarif (see the bundled
GitHub Action in action.yml, which does both steps for you).

Notes
  - Each finding id (CFG-001, TDX-002, ...) becomes one SARIF rule.
  - Config files have no meaningful line numbers for most findings, so the
    location is the line where the server is declared, or line 1 as a fallback.
  - Severity maps to SARIF level (critical and high become "error", medium
    "warning", low and info "note") and to the numeric security-severity that
    GitHub uses to label alerts Critical, High, Medium or Low.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from .models import Finding, ScanResult, Severity
from .redaction import sanitized_result

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/ElhamBidarigh/securAI-mcp-scanner"

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub bands: over 9.0 Critical, 7.0 to 8.9 High, 4.0 to 6.9 Medium, 0.1 to 3.9 Low.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.5",
    Severity.INFO: "1.0",
}

RULE_TITLES = {
    "CFG-001": "Server launches a shell with an inline command string",
    "CFG-002": "Install or launch pipes a remote download into a shell",
    "CFG-003": "Package is run without a pinned version",
    "CFG-004": "Credential stored in plaintext in the config",
    "CFG-005": "Permission-bypass flag in launch arguments",
    "CFG-006": "Very broad filesystem scope",
    "CFG-007": "Remote MCP server reachable over plain HTTP",
    "CFG-008": "Authentication is not visible in the supplied configuration",
    "TDX-001": "Instruction-override language in a tool description",
    "TDX-002": "Data-exfiltration instruction in a tool description",
    "TDX-003": "Tool description tries to hijack tool routing",
    "TDX-004": "Manufactured urgency or authority language aimed at the model",
    "TDX-005": "Hidden or invisible Unicode in a tool description",
    "TDX-006": "Markup or comment structure inside a tool description",
    "TDX-007": "Unusually long tool description",
    "DRIFT-001": "New tool appeared since the last baseline",
    "DRIFT-002": "Previously seen tool disappeared",
    "DRIFT-003": "Tool definition changed since the last baseline",
    "DRIFT-004": "Server connection or launch configuration changed",
    "LIVE-001": "Live introspection could not be completed",
    "LLM-000": "LLM judge could not run",
    "LLM-001": "LLM judge flagged a tool description",
}


def _artifact_uri(config_path: str) -> str:
    """Repo-relative, forward-slash path, which is what GitHub expects."""
    p = Path(config_path)
    try:
        if p.is_absolute():
            rel = Path(os.path.relpath(p, Path.cwd()))
            if not rel.as_posix().startswith(".."):  # keep the absolute path if it is outside the repo
                p = rel
    except ValueError:  # different drive on Windows
        pass
    return p.as_posix()  # pathlib already drops a leading "./"


def _server_line(text: str, server_name: str) -> int:
    m = re.search(r'"' + re.escape(server_name) + r'"\s*:', text)
    if not m:
        return 1
    return text.count("\n", 0, m.start()) + 1


def _fingerprint(f: Finding) -> str:
    raw = json.dumps([f.id, f.server_name, f.fingerprint_subject], ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def to_sarif(result: ScanResult, config_path: str, tool_version: str) -> dict:
    result = sanitized_result(result)
    uri = _artifact_uri(config_path)
    try:
        text = Path(config_path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        text = ""

    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    for f in result.findings:
        if f.id in rule_index:
            continue
        rule_index[f.id] = len(rules)
        title = RULE_TITLES.get(f.id, f.title)
        rule = {
            "id": f.id,
            "name": f.id.replace("-", ""),
            "shortDescription": {"text": title},
            "fullDescription": {"text": f.description or title},
            "defaultConfiguration": {"level": _LEVEL[f.severity]},
            "properties": {
                "tags": ["security", "mcp", f.category],
                "security-severity": _SECURITY_SEVERITY[f.severity],
            },
        }
        if f.recommendation:
            rule["help"] = {"text": f.recommendation}
        rules.append(rule)

    results = []
    for f in result.findings:
        message = f.title if not f.recommendation else f"{f.title}. {f.recommendation}"
        results.append({
            "ruleId": f.id,
            "ruleIndex": rule_index[f.id],
            "level": _LEVEL[f.severity],
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": _server_line(text, f.server_name)},
                }
            }],
            "partialFingerprints": {"mcpScannerFinding/v2": _fingerprint(f)},
            "properties": {
                "server": f.server_name,
                "category": f.category,
                "confidence": f.confidence,
                "security-severity": _SECURITY_SEVERITY[f.severity],
            },
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "SecurAI MCP Scanner",
                "version": tool_version,
                "informationUri": INFORMATION_URI,
                "rules": rules,
            }},
            "results": results,
        }],
    }


def to_sarif_json(result: ScanResult, config_path: str, tool_version: str) -> str:
    return json.dumps(to_sarif(result, config_path, tool_version), indent=2, ensure_ascii=False)
