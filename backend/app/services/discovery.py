"""Static MCP server discovery.

Scans submitted source/config *content* for signs of MCP servers and clients.
We deliberately operate on provided text (not filesystem paths) so the scanner
cannot be tricked into reading arbitrary server files (no path traversal / LFI).

Discovery signals:
  1. MCP client/server config JSON: an "mcpServers" map (Claude Desktop / IDE
     style) declaring command/args/url for each server.
  2. SDK usage: imports/构造 of known MCP SDKs (Python `mcp`, TS `@modelcontextprotocol/sdk`).
  3. Endpoint hints: URLs ending in /mcp or /sse, stdio command patterns.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

_MAX_FILE_CHARS = 200_000  # bound per-file scan cost

_SDK_IMPORT_PATTERNS = [
    re.compile(r"@modelcontextprotocol/sdk"),
    re.compile(r"from\s+mcp(\.\w+)*\s+import"),
    re.compile(r"import\s+mcp\b"),
    re.compile(r"FastMCP\("),
    re.compile(r"new\s+McpServer\("),
    re.compile(r"Server\(\s*\{?\s*['\"]?name['\"]?"),
]

_ENDPOINT_PATTERNS = [
    re.compile(r"https?://[^\s'\"]+/(mcp|sse)\b", re.IGNORECASE),
]


@dataclass
class DiscoveredServer:
    name: str
    endpoint: str
    transport: str  # stdio|http|sse|unknown
    source_file: str
    raw: dict[str, Any]


def _try_parse_mcp_config(text: str) -> dict[str, Any] | None:
    """Return the mcpServers map if the text is JSON containing one."""
    text = text.strip()
    if "mcpServers" not in text:
        return None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(data, dict) and isinstance(data.get("mcpServers"), dict):
        return data["mcpServers"]
    return None


def _server_from_config_entry(name: str, entry: dict, source_file: str) -> DiscoveredServer:
    if "url" in entry:
        url = str(entry["url"])
        transport = "sse" if url.rstrip("/").endswith("/sse") else "http"
        endpoint = url
    elif "command" in entry:
        transport = "stdio"
        args = entry.get("args", [])
        args_str = " ".join(str(a) for a in args) if isinstance(args, list) else str(args)
        endpoint = f"stdio: {entry['command']} {args_str}".strip()
    else:
        transport = "unknown"
        endpoint = json.dumps(entry)[:1024]
    return DiscoveredServer(
        name=name,
        endpoint=endpoint[:1024],
        transport=transport,
        source_file=source_file,
        raw=entry if isinstance(entry, dict) else {},
    )


def scan_files(files: dict[str, str]) -> list[DiscoveredServer]:
    """Scan a map of filename -> content and return discovered servers.

    De-duplicates by endpoint. Richer signals (explicit config, then SDK usage)
    are processed first and win over a bare endpoint-URL match, so a server URL
    declared inside an mcpServers config is not also reported as a separate
    URL-only discovery.
    """
    found: dict[str, DiscoveredServer] = {}

    for path, content in files.items():
        if not isinstance(content, str):
            continue
        text = content[:_MAX_FILE_CHARS]

        # Signal 1: explicit mcpServers config map (highest fidelity — wins).
        cfg = _try_parse_mcp_config(text)
        if cfg:
            for name, entry in cfg.items():
                if not isinstance(entry, dict):
                    continue
                ds = _server_from_config_entry(str(name), entry, path)
                found[ds.endpoint] = ds

        # Signal 2: SDK usage implies an MCP server/client defined in this file.
        if any(rx.search(text) for rx in _SDK_IMPORT_PATTERNS):
            # Try to extract a declared server name.
            m = re.search(r"(?:FastMCP|McpServer|Server)\(\s*[\"']([^\"']{1,120})[\"']", text)
            name = m.group(1) if m else path.rsplit("/", 1)[-1]
            endpoint = f"sdk:{path}"
            found.setdefault(
                endpoint,
                DiscoveredServer(
                    name=name,
                    endpoint=endpoint,
                    transport="stdio",
                    source_file=path,
                    raw={"signal": "sdk-usage"},
                ),
            )

        # Signal 3: bare MCP endpoint URLs. setdefault ensures a config entry
        # for the same endpoint (added above) is not overwritten or duplicated.
        for rx in _ENDPOINT_PATTERNS:
            for m in rx.finditer(text):
                url = m.group(0)[:1024]
                transport = "sse" if url.rstrip("/").endswith("/sse") else "http"
                found.setdefault(
                    url,
                    DiscoveredServer(
                        name=url,
                        endpoint=url,
                        transport=transport,
                        source_file=path,
                        raw={"signal": "endpoint-url"},
                    ),
                )

    return list(found.values())
