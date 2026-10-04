"""
Structural (config-level) checks.

Each check function takes a ServerInfo and yields zero or more Finding
objects. These checks never need network access and never need an LLM --
they are pure pattern matching over the parsed config, so they always run
and are the foundation of every report (rule IDs starting with CFG-).
"""
from __future__ import annotations

import re
from collections.abc import Iterator

from .models import Finding, Severity, ServerInfo

_SHELL_INTERPRETERS = {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}
_SHELL_C_FLAGS = {"-c", "/c", "-command"}

_SECRET_KEY_PATTERN = re.compile(
    r"(api[_-]?key|secret|token|password|passwd|access[_-]?key|private[_-]?key)", re.IGNORECASE
)
_SECRET_VALUE_PATTERN = re.compile(
    r"^(sk-[a-zA-Z0-9]{10,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{12,}|[a-fA-F0-9]{32,}|ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,})"
)
_ENV_VAR_REF_PATTERN = re.compile(r"^\$\{?[A-Z_][A-Z0-9_]*\}?$")

_DANGEROUS_FLAGS = {
    "--allow-all",
    "--dangerously-skip-permissions",
    "--yolo",
    "--no-sandbox",
    "--disable-sandbox",
    "--allow-root",
    "--insecure",
    "--full-disk-access",
}

_BROAD_PATHS = {"/", "/home", "/root", "/etc", "c:\\", "c:/", "~", "$home", "%userprofile%"}

_AUTO_INSTALL_RUNNERS = {"npx", "uvx", "bunx", "pipx"}


def _iter_all_command_tokens(server: ServerInfo) -> list[str]:
    tokens = []
    if server.command:
        tokens.append(server.command)
    tokens.extend(server.args or [])
    return tokens


def check_command_injection_risk(server: ServerInfo) -> Iterator[Finding]:
    if server.transport != "stdio" or not server.command:
        return
    cmd_base = server.command.strip().split("/")[-1].lower()
    args_lower = [a.lower() for a in server.args]

    if cmd_base in _SHELL_INTERPRETERS and any(f in args_lower for f in _SHELL_C_FLAGS):
        joined = " ".join(server.args)
        yield Finding(
            id="CFG-001",
            title="Server launches a shell with an inline command string",
            severity=Severity.CRITICAL,
            category="config",
            server_name=server.name,
            description=(
                "The server is started via a shell interpreter (sh/bash/cmd/powershell) with "
                "-c / -Command, passing an inline command string instead of executing a fixed "
                "binary directly. If any part of that string is built from untrusted input "
                "(client-supplied args, a downloaded config, an env var an attacker can set), "
                "this is a direct command-injection path -- the exact pattern behind CVE-class "
                "MCP command-injection findings reported in 2026 audits."
            ),
            evidence=f"command={server.command!r} args={joined!r}",
            recommendation=(
                "Invoke the target binary directly (no shell) and pass arguments as an array, "
                "never as one interpolated string. If a shell is unavoidable, hard-code the full "
                "command and never interpolate variables into it."
            ),
            references=["NSA/CISA MCP Security Guidance, May 2026"],
        )

    # curl|bash / wget|sh style supply-chain execution
    joined_all = " ".join(_iter_all_command_tokens(server)).lower()
    if re.search(r"(curl|wget).{0,40}\|\s*(sh|bash)", joined_all):
        yield Finding(
            id="CFG-002",
            title="Install/launch pipes a remote download straight into a shell",
            severity=Severity.CRITICAL,
            category="config",
            server_name=server.name,
            description=(
                "The server's launch command pipes a network download directly into a shell "
                "(curl|bash pattern). Whoever controls that URL controls code execution on every "
                "machine that runs this MCP config, with no version pin and no integrity check."
            ),
            evidence=joined_all,
            recommendation=(
                "Vendor the install step separately: download, verify a checksum/signature, "
                "then run a pinned local binary. Never pipe a live download into a shell."
            ),
        )


def check_unpinned_dependency(server: ServerInfo) -> Iterator[Finding]:
    if server.transport != "stdio" or not server.command:
        return
    cmd_base = server.command.strip().lower()
    if cmd_base not in _AUTO_INSTALL_RUNNERS:
        return

    pkg_arg = None
    auto_yes = False
    for a in server.args:
        if a in ("-y", "--yes"):
            auto_yes = True
        elif not a.startswith("-") and pkg_arg is None:
            pkg_arg = a

    if pkg_arg and "@" not in pkg_arg.split("/")[-1]:
        # no version pin such as package@1.2.3
        yield Finding(
            id="CFG-003",
            title=f"Package '{pkg_arg}' is run without a pinned version",
            severity=Severity.HIGH if auto_yes else Severity.MEDIUM,
            category="config",
            server_name=server.name,
            description=(
                f"'{cmd_base}{' -y' if auto_yes else ''} {pkg_arg}' resolves to whatever the "
                "latest published version is at run time, with no version pin. If the package "
                "maintainer's account is compromised, or a malicious update is published, the "
                "next time this server starts it silently runs different code -- a supply-chain "
                "'rug pull' with no diff for you to review."
            ),
            evidence=f"{server.command} {' '.join(server.args)}",
            confidence="high",
            recommendation=(
                f"Pin an exact version: {pkg_arg}@<version>. Re-verify the pin after every "
                "deliberate upgrade, and treat an unexplained version bump as an incident."
            ),
        )


def check_secrets_in_config(server: ServerInfo) -> Iterator[Finding]:
    for key, value in (server.env or {}).items():
        if not isinstance(value, str):
            continue
        looks_like_secret_key = bool(_SECRET_KEY_PATTERN.search(key))
        looks_like_raw_secret_value = bool(_SECRET_VALUE_PATTERN.match(value.strip()))
        is_env_var_reference = bool(_ENV_VAR_REF_PATTERN.match(value.strip()))

        if is_env_var_reference:
            continue  # fine: config references an external env var, no literal secret on disk

        if looks_like_secret_key or looks_like_raw_secret_value:
            yield Finding(
                id="CFG-004",
                title=f"Credential-looking value stored in plaintext (env.{key})",
                severity=Severity.HIGH,
                category="config",
                server_name=server.name,
                description=(
                    f"The env var '{key}' holds what looks like a literal credential written "
                    "directly into the config file, rather than a reference to an external "
                    "secret store or shell env var. Config files are frequently committed to "
                    "git, synced to backups, or attached to bug reports -- any of which leaks "
                    "the credential."
                ),
                evidence=f"env.{key} = {value[:6]}{'*' * max(0, len(value) - 6)}",
                recommendation=(
                    "Reference an environment variable (e.g. \"${OPENAI_API_KEY}\") or a secrets "
                    "manager instead of a literal value; rotate this credential since it may "
                    "already be exposed."
                ),
            )


def check_dangerous_flags_and_broad_paths(server: ServerInfo) -> Iterator[Finding]:
    args_lower = {a.lower() for a in server.args}
    hit_flags = args_lower & _DANGEROUS_FLAGS
    if hit_flags:
        yield Finding(
            id="CFG-005",
            title="Server is launched with a permission-bypass flag",
            severity=Severity.CRITICAL,
            category="config",
            server_name=server.name,
            description=(
                f"Launch args include {sorted(hit_flags)}, which disables normal sandboxing or "
                "confirmation prompts. Combined with a compromised or poisoned tool, this removes "
                "the last human checkpoint before a destructive action runs."
            ),
            evidence=" ".join(server.args),
            recommendation="Remove the bypass flag; require explicit per-action confirmation for anything destructive.",
        )

    for a in server.args:
        norm = a.strip().lower()
        if norm in _BROAD_PATHS or (len(norm) <= 3 and norm.endswith(":\\")):
            yield Finding(
                id="CFG-006",
                title=f"Filesystem scope includes a very broad path ('{a}')",
                severity=Severity.HIGH,
                category="config",
                server_name=server.name,
                description=(
                    f"The server is granted access to '{a}', effectively the whole home "
                    "directory or drive rather than a specific project folder. A single "
                    "prompt-injected tool call can then read or overwrite anything on disk, "
                    "not just the intended project."
                ),
                evidence=" ".join(server.args),
                recommendation="Scope filesystem access to the smallest folder the server actually needs.",
            )


def check_remote_transport_security(server: ServerInfo) -> Iterator[Finding]:
    if server.transport not in ("http", "sse") or not server.url:
        return

    url = server.url.strip()
    is_localhost = re.search(r"://(localhost|127\.0\.0\.1|\[::1\])", url) is not None

    if url.startswith("http://") and not is_localhost:
        yield Finding(
            id="CFG-007",
            title="Remote MCP server is reachable over plain HTTP",
            severity=Severity.HIGH,
            category="config",
            server_name=server.name,
            description=(
                "The server URL uses http:// rather than https:// for a non-localhost host. "
                "Traffic -- including any auth token in headers -- can be read or modified by "
                "anyone on the network path (classic MITM), and this also opens the door to "
                "DNS-rebinding style SSRF against the client."
            ),
            evidence=url,
            recommendation="Use https:// with a valid certificate for any non-local MCP endpoint.",
        )

    if not is_localhost and not server.headers:
        yield Finding(
            id="CFG-008",
            title="Remote MCP server has no authentication headers configured",
            severity=Severity.HIGH,
            category="config",
            server_name=server.name,
            description=(
                "This is a remote (non-localhost) MCP endpoint with no Authorization/API-key "
                "header set in the client config. Either the server is unauthenticated (anyone "
                "who finds the URL can call its tools), or auth happens some other way this scan "
                "cannot see -- confirm which, because the former is a critical exposure."
            ),
            evidence=url,
            recommendation=(
                "Require a bearer token or mutual-TLS on the server side, and confirm the client "
                "config actually sends it."
            ),
        )


ALL_CHECKS = [
    check_command_injection_risk,
    check_unpinned_dependency,
    check_secrets_in_config,
    check_dangerous_flags_and_broad_paths,
    check_remote_transport_security,
]


def run_static_checks(server: ServerInfo) -> list[Finding]:
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        findings.extend(check(server))
    return findings
