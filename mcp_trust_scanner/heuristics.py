"""
Tool-description heuristics ("tool poisoning" / prompt-injection detection).

An MCP client's model sees the full `description` field of every tool,
even text the human user never looks at in a UI. That field is therefore
a live prompt-injection surface: a malicious or compromised server can
put attacker instructions there that an agent may follow.

These are pattern-based, deliberately over-inclusive, and MEDIUM/LOW
confidence by default -- their job is to flag things for a human (or the
optional LLM judge in llm_judge.py) to review, not to be a final verdict.
Rule IDs start with TDX- (Tool Description eXamination).
"""
from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterator

from .models import Finding, Severity, ServerInfo, ToolInfo

_INSTRUCTION_OVERRIDE_PATTERNS = [
    r"\bignore (all |any )?(previous|prior|above|earlier) instructions\b",
    r"\bdisregard (the |your )?(system|previous|prior) prompt\b",
    r"\byou must (always|never) (tell|inform|mention|reveal)\b",
    r"\bdo not (tell|inform|show|mention|reveal) the user\b",
    r"\bwithout (telling|informing|asking) the user\b",
    r"\bthis is (a |the )?(system|admin|developer) (message|instruction|override)\b",
    r"\bact as (if you (are|were)|an?) (unrestricted|jailbroken|dan)\b",
    r"\bnew instructions?:\s",
]

_EXFIL_PATTERNS = [
    r"\bsend (a copy of |the )?(the )?(result|output|response|data|contents?|file|conversation) to\b.{0,60}(http|www\.|@|ftp)",
    r"\b(email|POST|upload|exfiltrate) (this|the|all) (data|output|contents?) to\b",
    r"\bafter (running|completing) this,? (also )?(call|invoke|send)\b",
    r"\bcopy (the )?(conversation|api[_ -]?key|token|credentials?) (to|into)\b",
    r"\bsend\b.{0,40}\bto\b.{0,20}(https?://|www\.)",
]

_HIJACK_OTHER_TOOL_PATTERNS = [
    r"\bwhen(ever)? the user (asks|mentions|says).{0,40}\buse this tool instead\b",
    r"\balways (call|use|prefer) this tool (over|instead of|before) (any )?other\b",
    r"\bbefore (calling|using) any other tool,? (first )?call\b",
    r"\bthis tool (takes|has) priority over all other tools\b",
]

_URGENCY_AUTHORITY_PATTERNS = [
    r"\b(urgent|critical|important)[:!].{0,30}(do not|never|always)\b",
    r"\bfailure to comply\b",
    r"\byou are required to\b.{0,30}\bwithout (asking|confirmation)\b",
]

_ALL_PATTERN_GROUPS = {
    "TDX-001": ("Instruction-override language in a tool description", _INSTRUCTION_OVERRIDE_PATTERNS, Severity.HIGH),
    "TDX-002": ("Data-exfiltration instruction embedded in a tool description", _EXFIL_PATTERNS, Severity.CRITICAL),
    "TDX-003": ("Tool description tries to hijack routing away from other tools", _HIJACK_OTHER_TOOL_PATTERNS, Severity.HIGH),
    "TDX-004": ("Manufactured urgency/authority language aimed at the model", _URGENCY_AUTHORITY_PATTERNS, Severity.MEDIUM),
}


def _find_hidden_unicode(text: str) -> list[str]:
    """Zero-width / bidi-control / tag characters used to hide text from a UI
    while the model still reads it."""
    suspicious = []
    for ch in text:
        cat = unicodedata.category(ch)
        cp = ord(ch)
        if cat == "Cf" or (0xE0000 <= cp <= 0xE007F) or ch in ("\u200b", "\u200c", "\u200d", "\ufeff"):
            suspicious.append(f"U+{cp:04X}")
    return suspicious


def _find_html_comment_or_markup(text: str) -> list[str]:
    hits = []
    if re.search(r"<!--.*?-->", text, re.DOTALL):
        hits.append("HTML comment")
    if re.search(r"<(system|instructions?|admin)>", text, re.IGNORECASE):
        hits.append("fake system/instruction tag")
    return hits


def scan_tool_description(server: ServerInfo, tool: ToolInfo) -> Iterator[Finding]:
    text = tool.description or ""
    if not text.strip():
        return

    lowered = text.lower()

    for rule_id, (title, patterns, severity) in _ALL_PATTERN_GROUPS.items():
        for pattern in patterns:
            m = re.search(pattern, lowered)
            if m:
                snippet_start = max(0, m.start() - 40)
                snippet_end = min(len(text), m.end() + 40)
                yield Finding(
                    id=rule_id,
                    title=f"{title} (tool: {tool.name})",
                    severity=severity,
                    category="tool-description",
                    server_name=server.name,
                    description=(
                        "This tool's `description` field -- text the model reads on every "
                        "turn, whether or not it's shown in any UI -- contains language "
                        "matching a known prompt-injection / tool-poisoning pattern."
                    ),
                    evidence=f'...{text[snippet_start:snippet_end]}...',
                    confidence="medium",
                    recommendation=(
                        "Treat this tool as untrusted pending manual review. If you don't "
                        "control this server's source, do not enable it. If you do, remove "
                        "the flagged language -- a tool description should describe what the "
                        "tool does, not instruct the model on how to behave."
                    ),
                    references=["OWASP MCP Top 10, 2025", "Simon Willison, Tool Poisoning, Apr 2025"],
                )
                break  # one hit per pattern group per tool is enough signal

    hidden = _find_hidden_unicode(text)
    if hidden:
        yield Finding(
            id="TDX-005",
            title=f"Hidden/invisible Unicode characters in tool description (tool: {tool.name})",
            severity=Severity.HIGH,
            category="tool-description",
            server_name=server.name,
            description=(
                "The description contains zero-width or bidi-control characters. These render "
                "as nothing (or reordered text) in a UI but are still tokenized and read by the "
                "model -- a common way to hide an injected instruction in plain sight."
            ),
            evidence=f"{len(hidden)} hidden code point(s): {', '.join(hidden[:8])}",
            confidence="high",
            recommendation="Strip non-printing Unicode from any tool metadata before display or use.",
        )

    markup = _find_html_comment_or_markup(text)
    if markup:
        yield Finding(
            id="TDX-006",
            title=f"Markup/comment structure inside tool description (tool: {tool.name})",
            severity=Severity.MEDIUM,
            category="tool-description",
            server_name=server.name,
            description=(
                "The description embeds HTML-comment or fake system/instruction tags. Legitimate "
                "tool descriptions are plain prose; structured markup here is a common carrier for "
                "an injected instruction block."
            ),
            evidence=", ".join(markup),
            confidence="medium",
            recommendation="Review manually; strip markup from tool descriptions server-side.",
        )

    if len(text) > 2000:
        yield Finding(
            id="TDX-007",
            title=f"Unusually long tool description ({len(text)} chars) (tool: {tool.name})",
            severity=Severity.LOW,
            category="tool-description",
            server_name=server.name,
            description=(
                "Legitimate tool descriptions are typically a sentence or two. An unusually long "
                "description is low-signal on its own but raises the prior for a hidden payload -- "
                "review it manually."
            ),
            evidence=f"{len(text)} characters",
            confidence="low",
            recommendation="Read the full description manually; shorten to what's needed to route the tool correctly.",
        )


def run_heuristic_checks(server: ServerInfo) -> list[Finding]:
    findings: list[Finding] = []
    for tool in server.tools:
        findings.extend(scan_tool_description(server, tool))
    return findings
