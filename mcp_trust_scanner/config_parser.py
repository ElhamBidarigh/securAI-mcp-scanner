"""
Parses MCP server configuration files into normalized ServerInfo objects.

Supports the three JSON shapes that cover the vast majority of real-world
MCP configs:

  1. Claude Desktop / Claude Code style:
     {"mcpServers": {"name": {"command": "...", "args": [...], "env": {...}}}}

  2. VS Code style:
     {"servers": {"name": {"type": "stdio"|"http", "command"/"url": ...}}}

  3. A bare list of server objects:
     [{"name": "...", "command": "...", ...}, ...]

Unknown/extra keys are preserved on ServerInfo.raw so later checks can
still inspect them.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ServerInfo, ToolInfo


class ConfigParseError(Exception):
    pass


def _infer_transport(entry: dict[str, Any]) -> str:
    explicit = entry.get("type") or entry.get("transport")
    if explicit:
        explicit = str(explicit).lower()
        if explicit in ("stdio", "http", "sse"):
            return explicit
    if entry.get("url"):
        return "http"
    if entry.get("command"):
        return "stdio"
    return "unknown"


def _server_from_entry(name: str, entry: dict[str, Any], source_path: str) -> ServerInfo:
    if not isinstance(name, str) or not name.strip():
        raise ConfigParseError("Server names must be non-empty strings")
    if not isinstance(entry, dict):
        raise ConfigParseError(f"Server '{name}' must be a JSON object")
    for key in ("command", "url", "type", "transport"):
        if key in entry and not isinstance(entry[key], str):
            raise ConfigParseError(f"Server '{name}': {key} must be a string")
    for key in ("env", "headers"):
        value = entry.get(key, {})
        if not isinstance(value, dict) or any(not isinstance(v, str) for v in value.values()):
            raise ConfigParseError(f"Server '{name}': {key} must map strings to strings")
    args = entry.get("args", [])
    if not isinstance(args, list) or any(not isinstance(v, str) for v in args):
        raise ConfigParseError(f"Server '{name}': args must be an array of strings")
    raw_tools = entry.get("tools", [])
    if not isinstance(raw_tools, list):
        raise ConfigParseError(f"Server '{name}': tools must be an array")
    names = set()
    for tool in raw_tools:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not tool["name"].strip():
            raise ConfigParseError(f"Server '{name}': each tool needs a non-empty name")
        if tool["name"] in names:
            raise ConfigParseError(f"Server '{name}': duplicate tool name {tool['name']!r}")
        names.add(tool["name"])
        if not isinstance(tool.get("description", ""), str):
            raise ConfigParseError(f"Server '{name}': tool description must be a string")
        schema = tool.get("inputSchema", tool.get("input_schema", {}))
        if not isinstance(schema, dict):
            raise ConfigParseError(f"Server '{name}': input schema must be an object")
    transport = _infer_transport(entry)
    tools = []
    for t in entry.get("tools", []) or []:
        if isinstance(t, dict):
            tools.append(
                ToolInfo(
                    name=t.get("name", "<unnamed>"),
                    description=t.get("description", ""),
                    input_schema=t.get("inputSchema") or t.get("input_schema") or {},
                    raw=t,
                )
            )
    return ServerInfo(
        name=name,
        transport=transport,
        command=entry.get("command"),
        args=list(entry.get("args", []) or []),
        env=dict(entry.get("env", {}) or {}),
        url=entry.get("url"),
        headers=dict(entry.get("headers", {}) or {}),
        tools=tools,
        source_path=source_path,
        raw=entry,
    )


def parse_config_file(path: str) -> list[ServerInfo]:
    p = Path(path)
    if not p.exists():
        raise ConfigParseError(f"File not found: {path}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as e:
        raise ConfigParseError(f"Invalid JSON in {path}: {e}") from e

    servers: list[ServerInfo] = []

    if isinstance(data, dict) and "mcpServers" in data:
        entries = data["mcpServers"]
        if not isinstance(entries, dict):
            raise ConfigParseError("mcpServers must be an object")
        for name, entry in entries.items():
            servers.append(_server_from_entry(name, entry, str(p)))
    elif isinstance(data, dict) and "servers" in data:
        entries = data["servers"]
        if not isinstance(entries, dict):
            raise ConfigParseError("servers must be an object")
        for name, entry in entries.items():
            servers.append(_server_from_entry(name, entry, str(p)))
    elif isinstance(data, list):
        for i, entry in enumerate(data):
            name = entry.get("name", f"server_{i}") if isinstance(entry, dict) else f"server_{i}"
            servers.append(_server_from_entry(name, entry, str(p)))
    elif isinstance(data, dict):
        # Could be a single bare server object, or a dict-of-servers with no wrapper key.
        looks_like_single_server = any(k in data for k in ("command", "url", "args"))
        if looks_like_single_server:
            servers.append(_server_from_entry(data.get("name", p.stem), data, str(p)))
        else:
            for name, entry in data.items():
                if isinstance(entry, dict):
                    servers.append(_server_from_entry(name, entry, str(p)))
    else:
        raise ConfigParseError(f"Unrecognized MCP config shape in {path}")

    if not servers:
        raise ConfigParseError(f"No MCP server entries found in {path}")

    if len({s.name for s in servers}) != len(servers):
        raise ConfigParseError("Duplicate server names are not supported")
    return servers
