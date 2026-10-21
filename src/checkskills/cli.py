"""Command-line interface.

    checkskills scan PATH [--format text|markdown|json] [--fail-on low|medium|high]
    checkskills config [PATH]
    checkskills rules
    checkskills serve            # start the MCP server (stdio)

The CLI exists so the engine is usable without any AI: in a terminal, a git hook or CI.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import __version__, inventory, report as renderers, rules, safety, scanners
from .models import Severity

_RENDERERS = {
    "text": renderers.render_text,
    "markdown": renderers.render_markdown,
    "json": renderers.render_json,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="checkskills",
        description="Audit AI skills and MCP servers before you install them.",
    )
    parser.add_argument("--version", action="version", version=f"checkskills {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a file or a directory (nothing is executed)")
    scan.add_argument("path")
    scan.add_argument("--format", choices=sorted(_RENDERERS), default="text")
    scan.add_argument(
        "--fail-on", choices=["low", "medium", "high"],
        help="exit with status 1 if a finding of this severity or worse exists (for CI)",
    )

    config = sub.add_parser("config", help="audit the MCP servers installed on this machine")
    config.add_argument("path", nargs="?", help="a specific config file (default: known locations)")
    config.add_argument("--format", choices=["text", "json"], default="text")

    sub.add_parser("rules", help="list the detection rules")
    sub.add_parser("serve", help="run the MCP server over stdio")
    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    report = scanners.scan_path(args.path)
    print(_RENDERERS[args.format](report))
    if args.fail_on:
        threshold = Severity[args.fail_on.upper()]
        if any(f.severity >= threshold for f in report.findings):
            return 1
    return 0


def _cmd_config(args: argparse.Namespace) -> int:
    read, audits = inventory.audit_installed(args.path)
    if args.format == "json":
        print(json.dumps({"configs": [str(p) for p in read],
                          "servers": [a.to_dict() for a in audits]}, indent=2))
        return 0
    if not read:
        print("No MCP configuration file found.")
        return 0
    for path in read:
        print(f"Config: {path}")
    for audit in audits:
        print(f"\n[{audit.risk}] {audit.server} ({audit.scope})")
        for finding in audit.findings:
            print(f"   {finding.severity.name:<6} {finding.rule}: {finding.message}")
    return 0


def _cmd_rules(_: argparse.Namespace) -> int:
    for rule in rules.RULES.values():
        print(f"{rule.id:<24} {rule.severity.label:<7} {rule.title}")
    return 0


def _cmd_serve(_: argparse.Namespace) -> int:
    from .server import run  # imported lazily: the CLI works without the MCP SDK loaded

    run()
    return 0


_COMMANDS = {"scan": _cmd_scan, "config": _cmd_config, "rules": _cmd_rules, "serve": _cmd_serve}


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _COMMANDS[args.command](args)
    except (safety.SafetyError, FileNotFoundError, NotADirectoryError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
