"""Best-effort redaction before emitting reports; never treat it as DLP."""
from __future__ import annotations

import copy
import re
from urllib.parse import parse_qsl, unquote, urlsplit

_SECRET = re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|authorization|credential|private[_-]?key)")
_REFERENCE = re.compile(r"^\$\{?[A-Z_][A-Z0-9_]*\}?$")
_URL = re.compile(r"https?://[^\s`\"'<>]+", re.I)
_ASSIGNMENT = re.compile(r"(?i)(\b(?:api[_-]?key|token|secret|password|authorization|credential)\b\s*[=:]\s*['\"]?)([^\s,'\"}\]]+)")


def _url_values(value: str) -> set[str]:
    try:
        parsed = urlsplit(value)
        values = {v for _, v in parse_qsl(parsed.query, keep_blank_values=False)}
        if parsed.username:
            values.add(unquote(parsed.username))
        if parsed.password:
            values.add(unquote(parsed.password))
        if parsed.fragment:
            values.add(unquote(parsed.fragment))
        return values
    except ValueError:
        return set()


def _secrets(servers) -> set[str]:
    values: set[str] = set()
    for server in servers:
        # Env and headers may contain sensitive values even with innocuous names.
        values.update(v for v in (*server.env.values(), *server.headers.values()) if v and not _REFERENCE.fullmatch(v))
        tokens = server.args
        for i, arg in enumerate(tokens):
            if i and _SECRET.search(tokens[i - 1]) and not arg.startswith('-'):
                values.add(arg)
            if '=' in arg and _SECRET.search(arg.split('=', 1)[0]):
                values.add(arg.split('=', 1)[1])
            for match in _URL.finditer(arg):
                values.update(_url_values(match.group()))
        if server.url:
            values.update(_url_values(server.url))
    return {v for v in values if v and not _REFERENCE.fullmatch(v)}


def redact_text(text: str, secrets: set[str]) -> str:
    for value in sorted(secrets, key=len, reverse=True):
        text = text.replace(value, '[REDACTED]')
    text = _ASSIGNMENT.sub(r'\1[REDACTED]', text)
    # Omit all URL query/fragment and user info, even when key names are unknown.
    def clean_url(match):
        try:
            p = urlsplit(match.group())
            host = p.hostname or ''
            if ':' in host:
                host = '[' + host + ']'
            if p.port:
                host += ':' + str(p.port)
            return p.scheme + '://' + host + p.path + ('?[REDACTED]' if p.query else '') + ('#[REDACTED]' if p.fragment else '')
        except ValueError:
            return '[REDACTED URL]'
    return _URL.sub(clean_url, text)


def sanitized_result(result):
    safe = copy.deepcopy(result)
    secrets = _secrets(result.servers)
    for server in safe.servers:
        server.name = redact_text(server.name, secrets)
        server.command = redact_text(server.command, secrets) if server.command else server.command
        # Arbitrary argument strings can contain secrets that cannot be identified reliably.
        server.args = ['[OMITTED: launch arguments may contain secrets]'] if server.args else []
        server.url = redact_text(server.url, secrets) if server.url else server.url
        for tool in server.tools:
            tool._reported_fingerprint = tool.fingerprint()
            tool.name = redact_text(tool.name, secrets)
            # Arbitrary external metadata may contain credentials unknown to us.
            tool.description = '[OMITTED: untrusted tool metadata may contain secrets]'
    for finding in safe.findings:
        for field in ('title', 'server_name', 'description', 'evidence', 'recommendation'):
            setattr(finding, field, redact_text(getattr(finding, field), secrets))
        if finding.category in ('tool-description', 'llm-judge', 'drift') and finding.evidence:
            finding.evidence = '[OMITTED: untrusted metadata may contain secrets]'
        if finding.id in {'CFG-001', 'CFG-002', 'CFG-003', 'CFG-005', 'CFG-006'} and finding.evidence:
            finding.evidence = '[OMITTED: launch arguments may contain secrets]'
    safe.target_label = redact_text(safe.target_label, secrets)
    return safe
