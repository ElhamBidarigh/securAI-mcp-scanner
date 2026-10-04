"""
Baseline pin + diff ("rug pull" detection).

The idea: the first time you scan a server, you "pin" its tool
fingerprints (name + description + input schema, hashed). Every
subsequent scan compares against that pin. Anything that changed --
a new tool appearing, an existing tool's description silently rewritten,
an input schema growing new fields -- is flagged, because that's exactly
the trust-model gap CSA's July 2026 research note described: MCP config
approval is bound to a server's name, not its contents, so a server can
be approved once and then modified without triggering a new review.

Baselines are stored as plain JSON so they're easy to commit to a repo
and diff in a pull request (recommended workflow: check the .mcp-trust
baseline directory into git, review baseline changes like code changes).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Finding, Severity, ServerInfo


class BaselineError(Exception):
    pass


def baseline_path(baseline_dir: str, server_name: str) -> Path:
    safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in server_name)
    return Path(baseline_dir) / f"{safe_name}.json"


def save_baseline(baseline_dir: str, server: ServerInfo) -> Path:
    Path(baseline_dir).mkdir(parents=True, exist_ok=True)
    path = baseline_path(baseline_dir, server.name)
    data = {
        "server_name": server.name,
        "transport": server.transport,
        "command": server.command,
        "args": server.args,
        "url": server.url,
        "tools": {t.name: {"fingerprint": t.fingerprint(), "description": t.description} for t in server.tools},
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return path


def load_baseline(baseline_dir: str, server_name: str) -> dict[str, Any] | None:
    path = baseline_path(baseline_dir, server_name)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise BaselineError(f"Corrupt baseline file {path}: {e}") from e


def diff_against_baseline(server: ServerInfo, baseline_dir: str) -> list[Finding]:
    """Compares the current live/config tool set against a saved baseline.
    Returns [] (with no error) if there is no baseline yet -- the caller
    should then save one, since 'no baseline' just means 'first scan'."""
    baseline = load_baseline(baseline_dir, server.name)
    if baseline is None:
        return []

    findings: list[Finding] = []
    old_tools: dict[str, dict[str, Any]] = baseline.get("tools", {})
    current_names = {t.name for t in server.tools}
    old_names = set(old_tools.keys())

    for name in current_names - old_names:
        findings.append(
            Finding(
                id="DRIFT-001",
                title=f"New tool appeared since last baseline: '{name}'",
                severity=Severity.MEDIUM,
                category="drift",
                server_name=server.name,
                description=(
                    "This tool was not present in the last saved baseline for this server. "
                    "New tools aren't inherently bad, but every new tool is new attack surface "
                    "and should get the same review the original set got."
                ),
                recommendation="Review the new tool's description and permissions before trusting it; re-pin the baseline once approved.",
            )
        )

    for name in old_names - current_names:
        findings.append(
            Finding(
                id="DRIFT-002",
                title=f"Previously-seen tool disappeared: '{name}'",
                severity=Severity.LOW,
                category="drift",
                server_name=server.name,
                description=(
                    "A tool present in the last baseline is no longer advertised. Usually benign "
                    "(a removed feature), but confirm it wasn't replaced by something with a "
                    "similar but subtly different name (a classic typosquat-style swap)."
                ),
                recommendation="Confirm the removal was intentional; re-pin the baseline.",
            )
        )

    for tool in server.tools:
        old = old_tools.get(tool.name)
        if old is None:
            continue
        if old.get("fingerprint") != tool.fingerprint():
            findings.append(
                Finding(
                    id="DRIFT-003",
                    title=f"Tool definition changed since last baseline: '{tool.name}'",
                    severity=Severity.CRITICAL,
                    category="drift",
                    server_name=server.name,
                    description=(
                        f"'{tool.name}' was previously approved with a different description "
                        "and/or input schema. This is exactly the 'rug pull' pattern: a server "
                        "that behaves one way during review and differently afterward. Treat "
                        "this as an incident until proven otherwise."
                    ),
                    evidence=(
                        f"Old description: {old.get('description', '')[:200]!r}\n"
                        f"New description: {tool.description[:200]!r}"
                    ),
                    confidence="high",
                    recommendation=(
                        "Diff the old and new descriptions/schemas line by line. If the change "
                        "is legitimate, re-pin the baseline; if not, disable the server and "
                        "notify whoever else uses it."
                    ),
                )
            )

    return findings
