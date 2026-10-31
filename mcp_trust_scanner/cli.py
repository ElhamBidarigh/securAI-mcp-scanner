"""
Command-line interface.

    mcp-trust-scanner scan CONFIG.json [options]

See README.md for full usage. Run `mcp-trust-scanner scan --help` for
the flag reference.
"""
from __future__ import annotations

import argparse
import os
import sys

from .baseline import diff_against_baseline, save_baseline, BaselineError
from .config_parser import parse_config_file, ConfigParseError
from .heuristics import run_heuristic_checks
from .models import Finding, ScanResult, Severity, ServerInfo
from .report import to_json, to_markdown
from .static_checks import run_static_checks

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _severity_at_or_above(threshold: str) -> list[Severity]:
    idx = [s.value for s in _SEVERITY_ORDER].index(threshold)
    return _SEVERITY_ORDER[: idx + 1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-trust-scanner",
        description="Security scanner for Model Context Protocol (MCP) server configs and live tool surfaces.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan one MCP config file.")
    scan.add_argument("config", help="Path to an MCP config JSON file (mcpServers / servers format).")
    scan.add_argument(
        "--live", action="store_true",
        help="Connect to each server and pull its real, current tool list (requires: pip install mcp). "
             "Without this flag, only tools already present in the config file are checked.",
    )
    scan.add_argument(
        "--live-timeout", type=float, default=20.0,
        help="Seconds to wait when connecting to each server in --live mode (default: 20).",
    )
    scan.add_argument(
        "--llm-judge", action="store_true",
        help="Send tool descriptions to an Anthropic model for a semantic second opinion "
             "(requires: pip install anthropic, and --api-key or ANTHROPIC_API_KEY).",
    )
    scan.add_argument("--api-key", default=None, help="Anthropic API key (or set ANTHROPIC_API_KEY).")
    scan.add_argument(
        "--baseline-dir", default=".mcp-trust/baselines",
        help="Directory holding pinned baselines for drift/rug-pull detection (default: .mcp-trust/baselines).",
    )
    scan.add_argument(
        "--pin", action="store_true",
        help="After scanning, save/update the baseline for every server scanned (do this once you've "
             "reviewed and approved the current state).",
    )
    scan.add_argument("--no-drift-check", action="store_true", help="Skip comparing against any saved baseline.")
    scan.add_argument("--out", default=None, help="Write the Markdown report to this path (also prints to stdout if omitted).")
    scan.add_argument("--json-out", default=None, help="Also write the machine-readable JSON report to this path.")
    scan.add_argument("--client-name", default="", help="Client/organization name to print on the report header.")
    scan.add_argument("--consultant-name", default="", help="Your name, printed on the report header.")
    scan.add_argument("--consultant-contact", default="", help="Your email/site, printed on the report header.")
    scan.add_argument(
        "--fail-on", default=None, choices=[s.value for s in _SEVERITY_ORDER],
        help="Exit with a non-zero status if any finding at or above this severity exists "
             "(useful in CI to block a merge/deploy on new critical/high findings).",
    )
    scan.add_argument("--quiet", action="store_true", help="Suppress the human-readable console summary.")

    return parser


def _scan_one_server(
    server: ServerInfo,
    args: argparse.Namespace,
) -> tuple[ServerInfo, list[Finding]]:
    findings: list[Finding] = []

    findings.extend(run_static_checks(server))

    if args.live:
        from .live_connector import fetch_live_tools, LiveConnectError

        try:
            live_tools = fetch_live_tools(server, timeout=args.live_timeout)
            server._live_completed = True
            server.tools = live_tools  # live data supersedes whatever the config claimed
        except LiveConnectError as e:
            findings.append(
                Finding(
                    id="LIVE-001",
                    title=f"Could not complete live introspection of '{server.name}'",
                    severity=Severity.INFO,
                    category="config",
                    server_name=server.name,
                    description=str(e),
                    recommendation="Confirm the server is running/reachable, then re-run with --live.",
                )
            )

    findings.extend(run_heuristic_checks(server))

    if args.llm_judge and server.tools:
        from .llm_judge import run_llm_judge, LLMJudgeError

        api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            findings.append(
                Finding(
                    id="LLM-000",
                    title="LLM judge requested but no API key available",
                    severity=Severity.INFO,
                    category="llm-judge",
                    server_name=server.name,
                    description="Pass --api-key or set ANTHROPIC_API_KEY to enable the semantic judge layer.",
                )
            )
        else:
            try:
                findings.extend(run_llm_judge(server, api_key))
                server._llm_completed = True
            except LLMJudgeError as e:
                findings.append(
                    Finding(
                        id="LLM-000",
                        title=f"LLM judge failed for '{server.name}'",
                        severity=Severity.INFO,
                        category="llm-judge",
                        server_name=server.name,
                        description=str(e),
                    )
                )

    if not args.no_drift_check:
        findings.extend(diff_against_baseline(server, args.baseline_dir))


    return server, findings


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        servers = parse_config_file(args.config)
    except ConfigParseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    all_findings: list[Finding] = []
    resolved_servers: list[ServerInfo] = []

    for server in servers:
        try:
            resolved, findings = _scan_one_server(server, args)
        except (BaselineError, OSError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        resolved_servers.append(resolved)
        all_findings.extend(findings)

    result = ScanResult(
        scanned_at=ScanResult.now_iso(),
        target_label=args.config,
        servers=resolved_servers,
        findings=all_findings,
        llm_judge_used=bool(args.llm_judge and all(getattr(s, "_llm_completed", False) for s in resolved_servers if s.tools)),
        live_introspection_used=bool(args.live and all(getattr(s, "_live_completed", False) for s in resolved_servers)),
    )

    incomplete = any(f.id in {"LIVE-001", "LLM-000"} for f in all_findings)
    gate_failed = args.fail_on and any(
        f.severity in set(_severity_at_or_above(args.fail_on)) for f in all_findings
    )
    if args.pin and not incomplete and not gate_failed:
        try:
            for server in resolved_servers:
                save_baseline(args.baseline_dir, server)
        except OSError as e:
            print(f"error: could not save baseline: {e}", file=sys.stderr)
            return 2

    md = to_markdown(
        result,
        client_name=args.client_name,
        consultant_name=args.consultant_name,
        consultant_contact=args.consultant_contact,
    )

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(md)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            f.write(to_json(result))
    if not args.out:
        print(md)

    if not args.quiet:
        counts = result.counts_by_severity()
        print(
            f"\n[mcp-trust-scanner] {len(resolved_servers)} server(s) scanned, "
            f"{len(all_findings)} finding(s) -- "
            f"critical={counts['critical']} high={counts['high']} medium={counts['medium']} "
            f"low={counts['low']} info={counts['info']} -- security score {result.security_score()}/100",
            file=sys.stderr,
        )
        if args.out:
            print(f"[mcp-trust-scanner] Markdown report written to {args.out}", file=sys.stderr)
        if args.json_out:
            print(f"[mcp-trust-scanner] JSON report written to {args.json_out}", file=sys.stderr)
        if args.pin and not incomplete and not gate_failed:
            print(f"[mcp-trust-scanner] Baseline(s) pinned to {args.baseline_dir}", file=sys.stderr)

    if incomplete:
        print("error: requested scan layers did not complete; baseline was not updated", file=sys.stderr)
        return 2
    if args.fail_on:
        threshold_set = set(_severity_at_or_above(args.fail_on))
        if any(f.severity in threshold_set for f in all_findings):
            return 1

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        if args.live_timeout <= 0:
            parser.error("--live-timeout must be greater than zero")
        try:
            return cmd_scan(args)
        except (OSError, BaselineError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
