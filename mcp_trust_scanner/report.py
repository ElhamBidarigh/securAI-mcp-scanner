"""
Turns a ScanResult into a client-ready Markdown report and a machine-
readable JSON report. The Markdown report is deliberately structured
like a paid security assessment deliverable: executive summary first
(for a non-technical reader), then a findings table, then full detail,
then recommendations. See examples/sample_report.md for a filled-out
example you can hand to a prospective client as-is.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .models import ScanResult, Severity
from .redaction import sanitized_result

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

_RISK_LABELS = [
    (85, "Low risk"),
    (65, "Moderate risk"),
    (40, "High risk"),
    (0, "Critical risk"),
]


def _risk_label(score: int) -> str:
    for threshold, label in _RISK_LABELS:
        if score >= threshold:
            return label
    return "Critical risk"


def to_json(result: ScanResult) -> str:
    return json.dumps(sanitized_result(result).to_dict(), indent=2, ensure_ascii=False)


def to_markdown(
    result: ScanResult,
    client_name: str = "",
    consultant_name: str = "",
    consultant_contact: str = "",
) -> str:
    result = sanitized_result(result)
    counts = result.counts_by_severity()
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    lines: list[str] = []
    lines.append(f"# MCP Server Security Assessment")
    if client_name:
        lines.append(f"### Prepared for: {client_name}")
    lines.append(f"**Target:** {result.target_label}  ")
    lines.append(f"**Scan date:** {generated}  ")
    if consultant_name:
        lines.append(f"**Prepared by:** {consultant_name}" + (f" - {consultant_contact}" if consultant_contact else "") + "  ")
    lines.append(f"**Live introspection:** {'Yes' if result.live_introspection_used else 'No (static config review only)'}  ")
    lines.append(f"**LLM semantic review:** {'Yes' if result.llm_judge_used else 'No'}  ")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Executive summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"**{len(result.findings)} finding(s). A static scan cannot establish that a server is safe.**")
    lines.append("")
    lines.append(
        f"This assessment reviewed {len(result.servers)} MCP server "
        f"configuration(s){' and its live tool surface' if result.live_introspection_used else ''}, "
        "using the configuration and any provided tool descriptions. Live inspection, LLM "
        "review and baseline comparison only run when requested or a baseline is available. "
        "The scan does not establish runtime behavior or exploitability."
    )
    lines.append("")
    lines.append("| Severity | Count | Meaning |")
    lines.append("|---|---|---|")
    lines.append(f"| 🔴 Critical | {counts['critical']} | Urgent review; exploitability is not established by a static scan |")
    lines.append(f"| 🟠 High | {counts['high']} | Significant potential risk; review context |")
    lines.append(f"| 🟡 Medium | {counts['medium']} | Potential risk; review context |")
    lines.append(f"| 🔵 Low | {counts['low']} | Minor / defense-in-depth |")
    lines.append(f"| ⚪ Info | {counts['info']} | Context or scan limitation; review the finding |")
    lines.append("")

    if counts["critical"] > 0:
        lines.append(
            f"**{counts['critical']} critical finding(s) require action before this MCP setup "
            "should be considered trustworthy for production or client-facing use.**"
        )
        lines.append("")

    # Findings table (sorted by severity)
    lines.append("## Findings Summary")
    lines.append("")
    lines.append("| # | Severity | Server | Finding | Category |")
    lines.append("|---|---|---|---|---|")
    sorted_findings = sorted(result.findings, key=lambda f: (f.severity.order, f.server_name, f.id))
    for i, f in enumerate(sorted_findings, 1):
        emoji = _SEVERITY_EMOJI[f.severity]
        lines.append(f"| {i} | {emoji} {f.severity.value.title()} | {f.server_name} | {f.title} | {f.category} |")
    if not sorted_findings:
        lines.append("| - | - | - | No findings. | - |")
    lines.append("")

    # Server inventory
    lines.append("## Servers Reviewed")
    lines.append("")
    for s in result.servers:
        lines.append(f"### `{s.name}`")
        lines.append(f"- Transport: `{s.transport}`")
        lines.append(f"- Live inspection: {getattr(s, '_live_status', 'not recorded')}")
        lines.append(f"- LM review: {getattr(s, '_llm_status', 'not recorded')}")
        lines.append(f"- Baseline comparison: {getattr(s, '_baseline_status', 'not recorded')}")
        if s.command:
            lines.append(f"- Launch command: `{s.command} {' '.join(s.args)}`")
        if s.url:
            lines.append(f"- URL: `{s.url}`")
        lines.append(f"- Tools exposed: {len(s.tools)}" + (f" ({', '.join(t.name for t in s.tools)})" if s.tools else ""))
        lines.append("")

    # Detailed findings
    lines.append("## Detailed Findings")
    lines.append("")
    for i, f in enumerate(sorted_findings, 1):
        emoji = _SEVERITY_EMOJI[f.severity]
        lines.append(f"### {i}. {emoji} [{f.id}] {f.title}")
        lines.append("")
        lines.append(f"- **Severity:** {f.severity.value.title()}")
        lines.append(f"- **Server:** `{f.server_name}`")
        lines.append(f"- **Category:** {f.category}")
        lines.append(f"- **Confidence:** {f.confidence}")
        lines.append("")
        lines.append(f"**What we found:** {f.description}")
        lines.append("")
        if f.evidence:
            lines.append("**Evidence:**")
            lines.append("```")
            lines.append(f.evidence)
            lines.append("```")
            lines.append("")
        if f.recommendation:
            lines.append(f"**Recommendation:** {f.recommendation}")
            lines.append("")
        if f.references:
            lines.append(f"*References: {'; '.join(f.references)}*")
            lines.append("")
        lines.append("---")
        lines.append("")

    # Methodology
    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "This assessment was produced with SecurAI MCP Scanner. Available checks include: "
        "(1) static analysis of server launch configuration against known MCP risk patterns "
        "(command injection, unpinned supply-chain dependencies, plaintext secrets, "
        "overly broad filesystem/network access, missing transport security); "
        "(2) heuristic and, where enabled, LLM-based semantic review of supplied tool descriptions "
        "for prompt-injection / tool-poisoning language; and "
        "(3) baseline comparison against a prior scan to catch silent changes to tool behavior "
        "between reviews (\"rug pulls\"). "
        "Static findings are deterministic. Tool-description findings are pattern/AI-assisted "
        "and are marked with a confidence level - treat medium/low confidence findings as leads "
        "for manual review, not confirmed exploits."
    )
    lines.append("")

    return "\n".join(lines)
