"""
Optional live introspection: actually connect to an MCP server (stdio,
SSE, or streamable-HTTP) and ask it for its real, current tool list.

This matters because a server's advertised tools can differ from what's
written in a config file (some servers register tools dynamically), and
because it's the only way to catch a "rug pull" -- a server that serves
one (clean) tool description during review and a different one later.

Requires the official `mcp` package: pip install mcp
This module is imported lazily by the CLI so config-only scans never
need the dependency installed.
"""
from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from typing import Optional

from .models import ServerInfo, ToolInfo

DEFAULT_TIMEOUT_SECONDS = 20


class LiveConnectError(Exception):
    pass


def _tool_info_from_sdk_tool(t) -> ToolInfo:
    """Builds a ToolInfo from whatever the installed `mcp` SDK's Tool object
    looks like. The SDK renamed `inputSchema` -> `input_schema` between
    major versions, so support both rather than pin an exact SDK version."""
    schema = getattr(t, "input_schema", None)
    if schema is None:
        schema = getattr(t, "inputSchema", None)
    return ToolInfo(
        name=t.name,
        description=getattr(t, "description", "") or "",
        input_schema=schema or {},
        raw=t.model_dump() if hasattr(t, "model_dump") else {},
    )


async def _fetch_tools_stdio(server: ServerInfo, timeout: float) -> list[ToolInfo]:
    try:
        from mcp import ClientSession
        from mcp.client.stdio import stdio_client, StdioServerParameters
    except ImportError as e:  # pragma: no cover
        raise LiveConnectError(
            "The 'mcp' package is not installed. Run: pip install mcp"
        ) from e

    if not server.command:
        raise LiveConnectError(f"Server '{server.name}' has no command to launch (stdio transport).")

    params = StdioServerParameters(command=server.command, args=server.args or [], env=server.env or None)

    async def _run() -> list[ToolInfo]:
        async with AsyncExitStack() as stack:
            read, write = await stack.enter_async_context(stdio_client(params))
            session: "ClientSession" = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            result = await session.list_tools()
            return [_tool_info_from_sdk_tool(t) for t in result.tools]

    return await asyncio.wait_for(_run(), timeout=timeout)


async def _fetch_tools_http(server: ServerInfo, timeout: float) -> list[ToolInfo]:
    try:
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
    except ImportError as e:  # pragma: no cover
        raise LiveConnectError(
            "The 'mcp' package is not installed. Run: pip install mcp"
        ) from e

    if not server.url:
        raise LiveConnectError(f"Server '{server.name}' has no url (http/sse transport).")

    http_client = None
    if server.headers:
        try:
            import httpx2

            http_client = httpx2.AsyncClient(headers=server.headers)
        except ImportError:
            pass

    async def _run() -> list[ToolInfo]:
        async with AsyncExitStack() as stack:
            kwargs = {"http_client": http_client} if http_client else {}
            read, write, *_rest = await stack.enter_async_context(
                streamable_http_client(server.url, **kwargs)
            )
            session: "ClientSession" = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            result = await session.list_tools()
            return [_tool_info_from_sdk_tool(t) for t in result.tools]

    try:
        return await asyncio.wait_for(_run(), timeout=timeout)
    finally:
        if http_client is not None:
            await http_client.aclose()


async def _fetch_tools_sse(server: ServerInfo, timeout: float) -> list[ToolInfo]:
    try:
        from mcp import ClientSession
        from mcp.client.sse import sse_client
    except ImportError as e:  # pragma: no cover
        raise LiveConnectError(
            "The 'mcp' package is not installed. Run: pip install mcp"
        ) from e

    if not server.url:
        raise LiveConnectError(f"Server '{server.name}' has no url (sse transport).")

    async def _run() -> list[ToolInfo]:
        async with AsyncExitStack() as stack:
            read, write = await stack.enter_async_context(
                sse_client(server.url, headers=server.headers or None)
            )
            session: "ClientSession" = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            result = await session.list_tools()
            return [_tool_info_from_sdk_tool(t) for t in result.tools]

    return await asyncio.wait_for(_run(), timeout=timeout)


def fetch_live_tools(
    server: ServerInfo, timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> list[ToolInfo]:
    """Synchronous wrapper. Connects to the server, lists tools, disconnects.

    Raises LiveConnectError with a human-readable message on any failure
    (missing dependency, connection refused, timeout, protocol error) so
    the caller can turn it into a Finding instead of crashing the whole scan.
    """
    try:
        if server.transport == "stdio":
            return asyncio.run(_fetch_tools_stdio(server, timeout))
        elif server.transport == "http":
            return asyncio.run(_fetch_tools_http(server, timeout))
        elif server.transport == "sse":
            return asyncio.run(_fetch_tools_sse(server, timeout))
        else:
            raise LiveConnectError(f"Unknown/unsupported transport '{server.transport}'.")
    except LiveConnectError:
        raise
    except asyncio.TimeoutError as e:
        raise LiveConnectError(f"Timed out after {timeout}s connecting to '{server.name}'.") from e
    except Exception as e:  # noqa: BLE001 - surface any SDK/transport error as a clean message
        raise LiveConnectError(f"Failed to introspect '{server.name}': {type(e).__name__}: {e}") from e
