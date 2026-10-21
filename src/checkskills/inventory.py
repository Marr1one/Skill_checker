"""Find the MCP servers a user has installed and audit each of them.

This answers "what is already running on my machine?", complementing the scanners, which
answer "is this thing safe to install?".
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import safety
from .models import Finding, overall_risk
from .scanners import extract_mcp_servers, inspect_mcp_server


def known_config_paths() -> list[Path]:
    """Usual locations of MCP configuration files, for Linux, macOS and Windows."""
    home = Path.home()
    paths = [
        home / ".claude.json",  # Claude Code (user + per-project servers)
        Path.cwd() / ".mcp.json",  # Claude Code project-level servers
        home / ".config/Claude/claude_desktop_config.json",  # Claude Desktop, Linux
        home / "Library/Application Support/Claude/claude_desktop_config.json",  # macOS
        home / ".cursor/mcp.json",  # Cursor
    ]
    appdata = os.environ.get("APPDATA")
    if appdata:
        paths.append(Path(appdata) / "Claude" / "claude_desktop_config.json")  # Windows
    return paths


@dataclass(frozen=True)
class ServerAudit:
    """Audit result for one installed MCP server."""

    config: str  # path of the config file that declares it
    server: str
    scope: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def risk(self) -> str:
        return overall_risk(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "config": self.config,
            "server": self.server,
            "scope": self.scope,
            "risk": self.risk,
            "findings": [f.to_dict() for f in self.findings],
        }


def audit_config_file(path: str | Path) -> list[ServerAudit]:
    """Audit every server declared in one config file."""
    resolved = safety.resolve_readable(path)
    text = safety.read_text(resolved, max_bytes=safety.MAX_CONFIG_BYTES)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError(f"{resolved} is not valid JSON: {error}") from error
    return [
        ServerAudit(str(resolved), s.name, s.scope, inspect_mcp_server(s.name, s.config))
        for s in extract_mcp_servers(data)
    ]


def audit_installed(config_path: str | Path | None = None) -> tuple[list[Path], list[ServerAudit]]:
    """Audit one given config, or every known config that exists on this machine.

    Returns:
        (config files that were read, audits of all their servers)
    """
    candidates = [Path(config_path)] if config_path else known_config_paths()
    read: list[Path] = []
    audits: list[ServerAudit] = []
    for candidate in candidates:
        if not candidate.expanduser().is_file():
            continue
        try:
            audits += audit_config_file(candidate)
            read.append(candidate.expanduser())
        except (safety.SafetyError, ValueError):
            if config_path:  # an explicit request deserves an explicit error
                raise
    return read, audits
