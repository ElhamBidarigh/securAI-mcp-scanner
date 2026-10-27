"""Shared data models used across the scanner."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 40,
            Severity.HIGH: 20,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }[self]

    @property
    def order(self) -> int:
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }[self]


@dataclass
class Finding:
    """A single scan finding (one row of a report)."""

    id: str  # stable rule id, e.g. "CFG-001"
    title: str
    severity: Severity
    category: str  # "config" | "tool-description" | "drift" | "llm-judge"
    server_name: str
    description: str
    evidence: str = ""
    recommendation: str = ""
    confidence: str = "high"  # "high" | "medium" | "low" -- esp. for heuristic/LLM findings
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ToolInfo:
    """Normalized representation of one MCP tool, from config or live introspection."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable hash of the parts of a tool an attacker could silently change."""
        payload = json.dumps(
            {"name": self.name, "description": self.description, "input_schema": self.input_schema},
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class ServerInfo:
    """Normalized representation of one MCP server entry."""

    name: str
    transport: str  # "stdio" | "http" | "sse" | "unknown"
    command: Optional[str] = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: Optional[str] = None
    headers: dict[str, str] = field(default_factory=dict)
    tools: list[ToolInfo] = field(default_factory=list)
    source_path: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    scanned_at: str
    target_label: str
    servers: list[ServerInfo]
    findings: list[Finding]
    llm_judge_used: bool = False
    live_introspection_used: bool = False

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def risk_score(self) -> int:
        """0-100 heuristic security score; 100 means no weighted findings, not proof of safety."""
        raw = sum(f.severity.weight for f in self.findings)
        return max(0, 100 - raw) if raw <= 100 else 0

    def counts_by_severity(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanned_at": self.scanned_at,
            "target_label": self.target_label,
            "llm_judge_used": self.llm_judge_used,
            "live_introspection_used": self.live_introspection_used,
            "risk_score": self.risk_score(),
            "counts_by_severity": self.counts_by_severity(),
            "servers": [
                {
                    "name": s.name,
                    "transport": s.transport,
                    "command": s.command,
                    "url": s.url,
                    "tool_count": len(s.tools),
                    "tools": [
                        {"name": t.name, "description": t.description, "fingerprint": t.fingerprint()}
                        for t in s.tools
                    ],
                }
                for s in self.servers
            ],
            "findings": [f.to_dict() for f in self.findings],
        }
