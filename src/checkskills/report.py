"""Render a ``ScanReport`` as terminal text, Markdown or JSON."""
from __future__ import annotations

import json

from .models import RISK_NOTES, ScanReport


def _quote(evidence: str) -> str:
    """Evidence as a Markdown-safe inline snippet (backticks would break the formatting)."""
    return evidence.replace("`", "'")


def render_text(report: ScanReport) -> str:
    """Compact, human-readable output for the terminal."""
    lines = [
        f"CheckSkills report for {report.target}",
        f"Risk: {report.risk} - {RISK_NOTES[report.risk]}",
        f"Files scanned: {len(report.scanned)} | Findings: {len(report.findings)}",
        "",
    ]
    for finding in report.sorted_findings():
        lines.append(
            f"[{finding.severity.name:<6}] {finding.location or '-':<32} {finding.rule}"
        )
        lines.append(f"         {finding.message}")
        if finding.evidence:
            lines.append(f"         > {finding.evidence}")
    if report.skipped:
        lines += ["", "Not analyzed:"]
        lines += [f"  - {s.path}: {s.reason}" for s in report.skipped]
    return "\n".join(lines)


def render_markdown(report: ScanReport) -> str:
    """Shareable Markdown report (the evidence is quoted, never interpreted)."""
    lines = [
        f"# Audit: {report.target}",
        "",
        f"**Risk: {report.risk}** - {RISK_NOTES[report.risk]}",
        "",
        f"- Files scanned: {len(report.scanned)}",
        f"- Findings: {len(report.findings)}",
        "",
        "## Findings",
        "",
    ]
    if not report.findings:
        lines.append("None.")
    for finding in report.sorted_findings():
        lines.append(
            f"- **{finding.severity.name}** `{finding.rule}` at `{finding.location or 'n/a'}`: "
            f"{finding.message}"
        )
        if finding.evidence:
            lines.append(f"  - Evidence (untrusted content): `{_quote(finding.evidence)}`")
    if report.skipped:
        lines += ["", "## Not analyzed", ""]
        lines += [f"- `{s.path}`: {s.reason}" for s in report.skipped]
    lines += [
        "",
        "## Limits",
        "",
        "Static pattern matching only; nothing was executed. See SECURITY.md for what is not covered.",
    ]
    return "\n".join(lines) + "\n"


def render_json(report: ScanReport) -> str:
    """Machine-readable output, for CI pipelines."""
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
