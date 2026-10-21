"""The analysis engine.

Pure, deterministic Python: no network, no subprocess, no execution of audited content.
It knows nothing about AI or MCP; ``server.py`` and ``cli.py`` are thin layers on top.

Layers, from low to high level:

1. ``find_hidden_text`` / ``find_pattern_matches``  -> analyze a string
2. ``inspect_mcp_server`` / ``inspect_package_json`` -> analyze structured configs
3. ``scan_file``                                    -> pick the right analysis for a file
4. ``scan_path`` / ``scan_directory``               -> produce a ``ScanReport``
"""
from __future__ import annotations

import json
import os
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import safety
from .models import Finding, ScanReport, Severity, SkippedFile
from .rules import PATTERN_RULES

# --------------------------------------------------------------------------- constants

EVIDENCE_MAX_CHARS = 200
MAX_FILES_PER_SCAN = 2000  # a scan must always terminate quickly, even on huge repos
MINIFIED_LINE_LENGTH = 5000  # a single line this long is not meant to be read by humans

SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__", ".tox"})
# Source/text formats we analyze. Files with no extension are analyzed too (scripts).
TEXT_SUFFIXES = frozenset(
    {".md", ".txt", ".json", ".yml", ".yaml", ".toml", ".sh", ".bash", ".zsh",
     ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".ini", ".cfg"}
)
# Compiled artifacts: cannot be verified statically.
OPAQUE_SUFFIXES = frozenset(
    {".so", ".dll", ".dylib", ".exe", ".bin", ".wasm", ".pyc", ".node", ".jar", ".class"}
)

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
PACKAGE_RUNNERS = frozenset({"npx", "bunx", "pnpx", "uvx", "pipx"})
INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare")

# --------------------------------------------------------------------------- helpers


def _clip(text: str, limit: int = EVIDENCE_MAX_CHARS) -> str:
    """Single-line, length-limited evidence string."""
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _lines(text: str) -> list[str]:
    """Split on ``\\n`` only, so line numbers match what editors display."""
    return text.split("\n")


# --------------------------------------------------------------------------- 1. strings

# Zero-width characters, bidirectional overrides ("Trojan Source") and invisible operators.
_INVISIBLE = re.compile("[​-‍⁠-⁤﻿‪-‮⁦-⁩]")
# Joiners between two non-ASCII characters are legitimate (emoji sequences, Persian...).
_LEGIT_JOINER = re.compile(r"(?<=[^\x00-\x7f])[‌‍](?=[^\x00-\x7f])")
# Unicode "tag" characters mirror ASCII invisibly: a known way to smuggle hidden prompts.
_TAG_CHARS = re.compile("[\U000e0000-\U000e007f]")
# Emoji flags (e.g. England) legitimately use tag characters.
_FLAG_SEQUENCE = re.compile("\U0001f3f4[\U000e0020-\U000e007e]+\U000e007f")

_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_SUSPICIOUS_COMMENT = re.compile(
    r"\b(?:ignore|instructions?|execute|exfiltrate|upload|secret|token|password|ssh|curl)\b"
    r"|do(?:\s+not|n't)\s+tell",
    re.IGNORECASE,
)


def find_hidden_text(text: str) -> list[Finding]:
    """Detect content that humans cannot see but an AI reads.

    Covers invisible Unicode characters, hidden ASCII "tag" messages and HTML comments
    that contain instruction-like text.
    """
    findings: list[Finding] = []
    for number, line in enumerate(_lines(text), start=1):
        if number == 1:
            line = line.lstrip("﻿")  # a BOM at the very start of a file is normal
        line = _FLAG_SEQUENCE.sub("", line)
        line = _LEGIT_JOINER.sub("", line)

        tags = _TAG_CHARS.findall(line)
        if tags:
            decoded = "".join(chr(ord(c) - 0xE0000) for c in tags if 0xE0020 <= ord(c) <= 0xE007E)
            findings.append(Finding(
                "hidden-text", Severity.HIGH,
                "Invisible Unicode 'tag' characters smuggle a hidden message",
                f"Hidden message: {decoded!r}", line=number,
            ))

        invisible = _INVISIBLE.findall(line)
        if invisible:
            counts = Counter(invisible)
            evidence = ", ".join(
                f"U+{ord(c):04X} {unicodedata.name(c, 'UNKNOWN')} x{n}" for c, n in counts.items()
            )
            findings.append(Finding(
                "hidden-text", Severity.HIGH,
                "Invisible or direction-control Unicode characters", evidence, line=number,
            ))

    for match in _HTML_COMMENT.finditer(text):
        if _SUSPICIOUS_COMMENT.search(match.group(1)):
            findings.append(Finding(
                "hidden-text", Severity.MEDIUM,
                "HTML comment hides instruction-like text from human readers",
                _clip(match.group(1)), line=text.count("\n", 0, match.start()) + 1,
            ))
    return findings


def find_pattern_matches(text: str) -> list[Finding]:
    """Apply every line-level pattern rule from ``rules.py``."""
    findings: list[Finding] = []
    for number, line in enumerate(_lines(text), start=1):
        for rule in PATTERN_RULES:
            if rule.matches(line):
                findings.append(
                    Finding(rule.id, rule.severity, rule.title,
                             _clip(line), line=number)
                )
    return findings


def scan_text(text: str) -> list[Finding]:
    """Full text analysis: hidden content + pattern rules."""
    return find_hidden_text(text) + find_pattern_matches(text)


# --------------------------------------------------------------------------- 2. structures


@dataclass(frozen=True)
class McpServer:
    """One server entry of an MCP configuration."""

    name: str
    scope: str  # "global" or "project:<path>"
    config: dict[str, Any]


def extract_mcp_servers(data: Any) -> list[McpServer]:
    """List the servers declared in a parsed MCP config (Claude Code/Desktop formats)."""
    if not isinstance(data, dict):
        return []
    servers: list[McpServer] = []

    def collect(container: Any, scope: str) -> None:
        if isinstance(container, dict):
            for name, config in container.items():
                if isinstance(config, dict):
                    servers.append(McpServer(str(name), scope, config))

    collect(data.get("mcpServers"), "global")
    projects = data.get("projects")
    if isinstance(projects, dict):  # ~/.claude.json keeps per-project servers here
        for project, project_data in projects.items():
            if isinstance(project_data, dict):
                collect(project_data.get("mcpServers"), f"project:{project}")
    return servers


def is_version_pinned(spec: str) -> bool:
    """True if a runner argument pins an exact version.

    >>> is_version_pinned("good-server@1.2.3"), is_version_pinned("@scope/pkg@2.0.0")
    (True, True)
    >>> is_version_pinned("some-server"), is_version_pinned("pkg@latest"), is_version_pinned("@scope/pkg")
    (False, False, False)
    """
    return bool(re.search(r"(?:@|==)v?\d+(?:\.\d+)*[\w.+-]*$", spec.lstrip("@")))


def _broad_paths() -> frozenset[str]:
    """Directories that should never be handed to a tool in full."""
    home = str(Path.home())
    return frozenset({"/", "~", "$HOME", "${HOME}", "/home", "/root", "/etc", "/usr", "/var", home})


def inspect_mcp_server(name: str, config: dict[str, Any]) -> list[Finding]:
    """Analyze one MCP server entry (``command``, ``args``, ``env``, ``url``).

    Evidence never contains environment *values*, so secrets are not copied into reports.
    """
    findings: list[Finding] = []
    command = str(config.get("command", ""))
    args = [str(a) for a in (config.get("args") or [])]
    full = " ".join([command, *args]).strip()

    def add(rule: str, severity: Severity, message: str, evidence: str) -> None:
        findings.append(Finding(rule, severity, f'Server "{name}": {message}', _clip(evidence)))

    # Remote servers must use HTTPS (plain HTTP is acceptable only on localhost).
    url = config.get("url")
    if isinstance(url, str):
        parsed = urlparse(url)
        if parsed.scheme == "http" and parsed.hostname not in LOCAL_HOSTS:
            add("insecure-transport", Severity.MEDIUM, "remote server uses unencrypted HTTP", url)

    if re.search(r"\b(?:sudo|doas)\b", full):
        add("excessive-permissions", Severity.HIGH, "runs with elevated privileges", full)

    # Reuse the text rules on the command line (curl | sh, ~/.ssh, ...).
    for rule in PATTERN_RULES:
        if rule.matches(full):
            add(rule.id, rule.severity, rule.title, full)

    # `npx pkg` runs whatever version is newest *today*: not reproducible, not reviewable.
    if Path(command).name in PACKAGE_RUNNERS:
        positional = [a for a in args if not a.startswith("-")]
        if Path(command).name == "pipx" and positional[:1] == ["run"]:
            positional = positional[1:]
        # Simplification: the first positional argument is taken as the package spec.
        if positional and not is_version_pinned(positional[0]):
            add("unpinned-package", Severity.MEDIUM,
                f"'{positional[0]}' is not pinned to an exact version", full)

    broad = _broad_paths()
    for arg in args:
        if (arg.rstrip("/") or "/") in broad:
            add("excessive-permissions", Severity.HIGH,
                f"grants access to a very broad path ({arg})", arg)

    env = config.get("env")
    if isinstance(env, dict):
        for key, value in env.items():
            is_literal = isinstance(value, str) and value and not value.startswith("$")
            if is_literal and re.search(r"KEY|TOKEN|SECRET|PASSWORD", str(key), re.IGNORECASE):
                add("secret-in-config", Severity.LOW,
                    f"secret stored as a literal value in env var {key}", f"env.{key}")
    return findings


_DANGEROUS_SCRIPT = re.compile(
    r"\b(?:curl|wget)\b|base64|\bnode\s+-e\b|\bpython3?\s+-c\b|\beval\b|\|\s*(?:ba|z)?sh\b|chmod\s+\+x",
    re.IGNORECASE,
)
_NON_REGISTRY_DEP = re.compile(r"(?:git\+|git://|https?:|github:|file:|ssh:)", re.IGNORECASE)


def inspect_package_json(text: str) -> list[Finding]:
    """Analyze a ``package.json``: install hooks and dependencies outside the registry."""
    try:
        package = json.loads(text)
    except json.JSONDecodeError as error:
        return [Finding("invalid-file", Severity.LOW, f"Invalid JSON: {error}")]
    if not isinstance(package, dict):
        return [Finding("invalid-file", Severity.LOW, "package.json is not a JSON object")]

    findings: list[Finding] = []
    scripts = package.get("scripts") if isinstance(package.get("scripts"), dict) else {}
    for hook in INSTALL_HOOKS:  # these run automatically on `npm install`
        script = scripts.get(hook)
        if isinstance(script, str):
            severity = Severity.HIGH if _DANGEROUS_SCRIPT.search(script) else Severity.LOW
            findings.append(Finding(
                "install-script", severity,
                f"'{hook}' runs automatically when the package is installed",
                _clip(f"scripts.{hook} = {script}"),
            ))

    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = package.get(section)
        for dep, spec in (deps.items() if isinstance(deps, dict) else []):
            spec = str(spec)
            if _NON_REGISTRY_DEP.match(spec) or spec in {"*", "latest", ""}:
                findings.append(Finding(
                    "unpinned-package", Severity.MEDIUM,
                    f"Dependency '{dep}' is not a fixed registry version",
                    _clip(f"{section}.{dep} = {spec}"),
                ))
    return findings


# --------------------------------------------------------------------------- 3. one file


def _opaque(label: str, severity: Severity, message: str) -> Finding:
    return Finding("opaque-content", severity, message, file=label)


def _parse_json(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def scan_file(path: str | Path, label: str | None = None) -> list[Finding]:
    """Analyze one file with the analysis that matches its type.

    Args:
        path: the file to read (validated by ``safety``).
        label: name shown in findings (defaults to the resolved path).
    """
    resolved = safety.resolve_readable(path)
    label = label or str(resolved)
    suffix = resolved.suffix.lower()

    if suffix in OPAQUE_SUFFIXES or b"\x00" in safety.read_head(resolved):
        return [_opaque(label, Severity.MEDIUM,
                        "Compiled or binary file: cannot be verified by static text analysis")]

    text = safety.read_text(resolved)
    servers = extract_mcp_servers(_parse_json(text)) if suffix == ".json" else []

    if resolved.name == "package.json":
        findings = scan_text(text) + inspect_package_json(text)
    elif servers:
        # MCP config: dedicated checks per server; text rules would only duplicate them.
        findings = find_hidden_text(text)
        for server in servers:
            findings += inspect_mcp_server(server.name, server.config)
    else:
        findings = scan_text(text)

    if suffix in {".js", ".mjs", ".cjs"} and any(len(l) > MINIFIED_LINE_LENGTH for l in _lines(text)):
        findings.append(_opaque(label, Severity.LOW,
                                "Minified or obfuscated script: hard to review by hand"))
    return [f if f.file else f.in_file(label) for f in findings]


# --------------------------------------------------------------------------- 4. reports


def scan_directory(root: str | Path) -> ScanReport:
    """Recursively analyze a directory. Nothing is executed; symlinks are not followed."""
    base = safety.resolve_readable(root, expect="dir")
    report = ScanReport(target=str(base))

    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for filename in sorted(filenames):
            path = Path(dirpath, filename)
            label = str(path.relative_to(base))
            suffix = path.suffix.lower()

            if suffix not in TEXT_SUFFIXES and suffix not in OPAQUE_SUFFIXES and suffix != "":
                continue  # images, fonts, archives...: out of scope, not worth listing
            if path.is_symlink():
                report.skipped.append(SkippedFile(label, "symlink (not followed)"))
                continue
            if len(report.scanned) >= MAX_FILES_PER_SCAN:
                report.skipped.append(SkippedFile(label, f"file limit reached ({MAX_FILES_PER_SCAN})"))
                continue
            try:
                report.findings += scan_file(path, label)
                report.scanned.append(label)
            except safety.SafetyError as error:
                report.skipped.append(SkippedFile(label, str(error)))
    return report


def scan_path(target: str | Path) -> ScanReport:
    """Scan a file or a directory and return a report."""
    resolved = safety.resolve_readable(target, expect="any")
    if resolved.is_dir():
        return scan_directory(resolved)
    report = ScanReport(target=str(resolved))
    try:
        report.findings = scan_file(resolved, resolved.name)
        report.scanned.append(resolved.name)
    except safety.SafetyError as error:
        report.skipped.append(SkippedFile(resolved.name, str(error)))
    return report
