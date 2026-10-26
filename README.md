# 🔌 SecurAI MCP Scanner

🇮🇷 [راهنمای فارسی](README.fa.md)

A security scanner for **MCP (Model Context Protocol)** server configurations and live tool surfaces - the protocol that connects AI agents (Claude, Cursor, VS Code, ChatGPT plugins, etc.) to external tools.

Part of the **[SecurAI toolkit](https://github.com/ElhamBidarigh/securai)** — this is the member of the family that covers the *agent/tool* layer, complementing the others' focus on AI-generated application code.

MCP adoption has outpaced its security tooling: independent 2026 audits have found large fractions of public MCP servers vulnerable to command injection and path traversal, with average security scores in the 30s out of 100. This tool gives you a repeatable, scriptable way to check a server before you trust it - and keep checking it, since a server can be clean today and silently different tomorrow.

## What it checks

1. **Server configuration (static, no connection needed)** - command injection via shell interpreters, unpinned supply-chain dependencies (`npx -y pkg` with no version), plaintext secrets in config files, overly broad filesystem access (`--allow-all`, root paths), missing transport security on remote servers (plain HTTP, no auth headers).
2. **Tool descriptions ("tool poisoning")** - every MCP tool has a `description` field the model reads on every turn, whether or not a human ever sees it. This is a live prompt-injection surface. The scanner pattern-matches for instruction-override language, data-exfiltration instructions, tool-routing hijacks, and hidden/invisible Unicode characters used to smuggle text past a UI.
3. **Drift / "rug pull" detection** - pin a baseline of a server's current tools (name + description + input schema, hashed). Every later scan diffs against it. A tool that silently changes behavior after approval - the core trust-model gap CSA's research flagged in 2026 — shows up as a critical finding instead of going unnoticed.

Optionally:
- **`--live`** connects to the real server (stdio / SSE / streamable-HTTP) via the official `mcp` SDK and pulls its actual, current tool list, rather than trusting what's written in a config file.
- **`--llm-judge`** sends flagged (and unflagged) tool descriptions to a Claude model for a semantic second opinion, to cut down regex false positives.

## Install

```bash
git clone https://github.com/ElhamBidarigh/securAI-mcp-scanner.git
cd securAI-mcp-scanner
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -e ".[all]"         # both --live and --llm-judge
# or:
pip install -e ".[live]"        # just live introspection
pip install -e ".[llm]"         # just the LLM judge
```

The core (`config_parser`, `static_checks`, `heuristics`, `baseline`, `report`) has **zero external dependencies** - it runs on stock Python 3.10+, so you can run a static scan on a client's machine without installing anything beyond Python itself.

## Quick start

```bash
python -m mcp_trust_scanner.cli scan examples/vulnerable_config.json
```

This scans an intentionally vulnerable demo config and prints a Markdown report to stdout. See [`examples/sample_report.md`](examples/sample_report.md) for a full example of the generated output.

## Usage

```bash
mcp-trust-scanner scan CONFIG.json [options]
```

| Flag | What it does |
|---|---|
| `--live` | Connect to each server and pull its real, current tool list (requires `pip install mcp`) |
| `--live-timeout SECONDS` | Timeout per server in `--live` mode (default: 20) |
| `--llm-judge` | Semantic review of tool descriptions via the Anthropic API (requires `pip install anthropic`) |
| `--api-key KEY` | Anthropic API key (or set `ANTHROPIC_API_KEY`) |
| `--baseline-dir DIR` | Where baselines are stored (default: `.mcp-trust/baselines`) |
| `--pin` | Save/update the baseline for every server scanned |
| `--no-drift-check` | Skip comparing against a saved baseline |
| `--out FILE.md` | Write the Markdown report to a file |
| `--json-out FILE.json` | Also write a machine-readable JSON report |
| `--client-name NAME` | Name printed on the report header |
| `--consultant-name NAME` | Your name, printed on the report header |
| `--consultant-contact C` | Your email/site, printed on the report header |
| `--fail-on SEVERITY` | Exit non-zero if any finding at/above this severity exists — useful in CI |
| `--quiet` | Suppress the console summary line |

### Typical config file locations

| Client | Config path |
|---|---|
| Claude Desktop (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop (Windows) | `%APPDATA%\Claude\claude_desktop_config.json` |
| Claude Code | `.mcp.json` in the project root, or `~/.claude.json` |
| Cursor | `.cursor/mcp.json` |
| VS Code | `.vscode/mcp.json` |

### Example: full client assessment

```bash
python -m mcp_trust_scanner.cli scan client_config.json \
  --live --llm-judge \
  --client-name "Client Org" \
  --consultant-name "Your Name" \
  --out report.md --json-out report.json
```

### Example: CI gate against rug pulls

```bash
# first run, after manual review: approve and pin the current state
python -m mcp_trust_scanner.cli scan .mcp.json --pin

# every subsequent run (e.g. in a pre-commit hook or GitHub Action):
python -m mcp_trust_scanner.cli scan .mcp.json --fail-on high
```

This fails the build if a tool's description/schema changed since the last approved baseline, or if any new high/critical config issue shows up.

## The full SecurAI toolkit

| Tool | Type | Link |
|---|---|---|
| 🛡️ Audit Tool | Self-assessment (browser) | [Live demo](https://elhambidarigh.github.io/securai/) |
| 🔬 Vuln Lab | Educational (PHP/MySQL) | [Repo](https://github.com/ElhamBidarigh/securAI-vuln-lab) |
| 🔐 JWT Analyzer | CLI (Python) | [Repo](https://github.com/ElhamBidarigh/jwt-analyzer) |
| 🔍 Active Scanner | Live URL scanner (PHP) | [Repo](https://github.com/ElhamBidarigh/securAI-active-scanner) |
| 🔌 MCP Scanner | CLI (Python) | You are here |

## Project layout

```
mcp_trust_scanner/
  config_parser.py    Parses Claude Desktop / Cursor / VS Code style MCP config files
  static_checks.py     8 config-level rules (CFG-001..CFG-008)
  heuristics.py         7 tool-description prompt-injection rules (TDX-001..TDX-007)
  live_connector.py     Live stdio/HTTP/SSE introspection via the official mcp SDK
  llm_judge.py           Optional semantic second-opinion layer via the Anthropic API
  baseline.py             Pin/diff logic for rug-pull detection
  report.py               Markdown + JSON report generation
  cli.py                   Command-line interface
examples/
  vulnerable_config.json  Intentionally vulnerable demo config
  sample_report.md        Full example report generated from it
  toy_server.py            Minimal real MCP server, used to test --live end-to-end
tests/
  test_scanner.py          18 unit tests covering the dependency-free core
```

## Running the tests

```bash
python -m unittest discover -s tests -v
```

## Contributing

Issues and PRs welcome - especially new detection rules (`CFG-*` for config patterns, `TDX-*` for tool-description patterns) backed by a real-world example.

## License

MIT - see [LICENSE](LICENSE).

## Author

Built by [Ellie Bidarigh](https://www.linkedin.com/in/elham-bidarigh/), a full-stack engineer moving into AI/agent security.
