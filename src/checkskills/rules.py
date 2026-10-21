"""Detection rules.

Each rule has a stable ``id`` that is shared across the whole project:

* the ``rule`` field of every :class:`~checkskills.models.Finding`,
* the documentation card ``src/checkskills/rules/<id>.md``,
* the ``explain_rule`` MCP tool and the ``rules://<id>`` resource.

A test enforces that every rule has a card and every card has a rule.

Pattern rules are matched line by line. Rules without a pattern (``hidden-text``,
``install-script``...) are implemented as dedicated checks in ``scanners.py`` but are
still registered here so they have an id, a default severity and a documentation card.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .models import Severity

RULES_DIR = Path(__file__).parent / "rules"
_RULE_ID = re.compile(r"^[a-z][a-z0-9-]{0,40}$")


def _any_of(*parts: str) -> re.Pattern[str]:
    """Compile several alternatives into one case-insensitive pattern."""
    return re.compile("|".join(parts), re.IGNORECASE)


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity  # default / maximum severity of the rule
    title: str  # one-sentence description, used as the finding message
    pattern: re.Pattern[str] | None = None  # line-level regex, if pattern-based
    exclude: re.Pattern[str] | None = None  # lines matching this are ignored

    def matches(self, line: str) -> bool:
        if self.pattern is None or not self.pattern.search(line):
            return False
        return not (self.exclude and self.exclude.search(line))


_RULE_LIST: tuple[Rule, ...] = (
    Rule(
        "prompt-injection",
        Severity.HIGH,
        "Text that tries to override the agent's instructions or hide actions from the user",
        _any_of(
            # "ignore all previous instructions", "disregard the system prompt"...
            r"(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:of\s+)?"
            r"(?:the\s+|your\s+)?(?:previous|prior|above|earlier|system)\s+"
            r"(?:instructions?|rules?|prompts?|guidelines?)",
            # "do not tell the user", "don't reveal this to the user"
            r"do(?:\s+not|n't)\s+(?:tell|inform|mention|reveal|show)[^.\n]{0,40}\b(?:user|human)\b",
            r"without\s+(?:telling|informing|notifying|asking)\s+the\s+(?:user|human)",
            r"\b(?:secretly|silently|quietly)\s+(?:run|execute|send|upload|read|copy|exfiltrate)\b",
            # French variants (the same attacks are written in other languages)
            r"ignore[rz]?\s+les\s+instructions\s+pr[ée]c[ée]dentes",
            r"ne\s+(?:le\s+)?(?:dis|dites|mentionne[rz]?)\s[^.\n]{0,30}utilisateur",
        ),
    ),
    Rule(
        "remote-exec",
        Severity.HIGH,
        "Downloads and runs code that nobody reviewed (pipe-to-shell, decoded payloads)",
        _any_of(
            r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b",
            r"base64\s+(?:-d|--decode)\b[^\n|]*\|\s*(?:ba|z|da)?sh\b",
            r"\beval\s*\(\s*(?:atob|base64)",
            r"\b(?:ba)?sh\s+<\(\s*(?:curl|wget)",
        ),
    ),
    Rule(
        "sensitive-access",
        Severity.HIGH,
        "References credentials, keys or other secrets that a normal tool does not need",
        _any_of(
            r"~/\.ssh",
            r"\.ssh/id_",
            r"\bid_(?:rsa|ed25519|ecdsa|dsa)\b",
            r"\.aws/credentials",
            r"\.gnupg\b",
            r"/etc/shadow",
            r"\.kube/config",
            r"\.netrc\b",
            r"browser\s+(?:cookies|passwords|credentials)",
            r"\bwallet\.dat\b",
            # a verb + ".env": "read the .env file", "send .env to ..."
            r"\b(?:read|cat|open|send|upload|exfiltrate|copy|print)\b[^.\n]{0,40}\.env\b",
        ),
    ),
    Rule(
        "exfiltration",
        Severity.MEDIUM,
        "Instructs the agent to send data to an external URL",
        _any_of(
            r"\b(?:send|post|upload|exfiltrate|forward|transmit)\b[^.\n]{0,80}\bhttps?://",
        ),
    ),
    Rule(
        "obfuscated-payload",
        Severity.MEDIUM,
        "Very long encoded blob that a human cannot review",
        _any_of(r"[A-Za-z0-9+/]{200,}={0,2}"),
        # inline images (data:image/png;base64,...) are legitimate
        exclude=re.compile(r"data:[\w/+.-]+;base64,", re.IGNORECASE),
    ),
    # --- rules below are implemented as dedicated checks in scanners.py ---
    Rule("hidden-text", Severity.HIGH, "Content invisible to humans but readable by an AI"),
    Rule("install-script", Severity.HIGH, "Package hook that runs automatically on install"),
    Rule("unpinned-package", Severity.MEDIUM, "Dependency that can change without notice"),
    Rule("excessive-permissions", Severity.HIGH, "Grants far more access than a tool needs"),
    Rule("insecure-transport", Severity.MEDIUM, "Remote server reached without encryption"),
    Rule("secret-in-config", Severity.LOW, "Secret stored as a literal value in a config file"),
    Rule("opaque-content", Severity.MEDIUM, "Content that cannot be verified by static analysis"),
    Rule("invalid-file", Severity.LOW, "File could not be parsed"),
)

RULES: dict[str, Rule] = {rule.id: rule for rule in _RULE_LIST}
PATTERN_RULES: tuple[Rule, ...] = tuple(r for r in _RULE_LIST if r.pattern is not None)


def rule_card(rule_id: str) -> str:
    """Return the Markdown documentation card of a rule.

    The id is validated against a strict pattern *and* against the registry before it
    is used to build a path, so it can never be used for path traversal.
    """
    if not _RULE_ID.match(rule_id) or rule_id not in RULES:
        known = ", ".join(sorted(RULES))
        raise KeyError(f"Unknown rule '{rule_id}'. Known rules: {known}")
    return (RULES_DIR / f"{rule_id}.md").read_text(encoding="utf-8")
