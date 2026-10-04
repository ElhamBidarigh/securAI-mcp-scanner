"""
MCP Trust Scanner
==================

A security scanner for Model Context Protocol (MCP) server configurations
and live tool surfaces. Detects:

  - Structural / config-level risks (command injection, path traversal,
    unpinned dependencies, missing auth, secrets in plaintext, SSRF-prone
    URLs, overly broad filesystem/network access)
  - Tool-description-level risks (prompt injection payloads embedded in
    tool descriptions, "tool poisoning", instructions hidden from the UI
    but visible to the model)
  - Drift / "rug pull" risks (a previously-scanned server's tool
    definitions changing silently between scans)

Optionally uses the Anthropic API as a semantic second-opinion judge to
cut down false positives from the regex/heuristic layer.

Author: Ellie Bidarigh
"""

__version__ = "0.1.0"
