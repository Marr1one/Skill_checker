"""Guard rails for everything CheckSkills reads.

An auditing tool is itself an attack surface: an agent can be tricked (by a hostile file
it is analyzing) into asking the tool to read something it should not. So the tool
refuses, by itself, regardless of what the agent asks:

* credential locations (``~/.ssh``, ``~/.aws``, private keys, ``.env`` files...),
* anything outside ``CHECKSKILLS_ALLOWED_ROOTS`` when that variable is set,
* files larger than a fixed limit.

All checks work on the *resolved* path, so symlinks and ``..`` tricks do not bypass them.
"""
from __future__ import annotations

import os
from pathlib import Path

MAX_FILE_BYTES = 1_000_000  # source files: 1 MB is already huge for a skill or a script
MAX_CONFIG_BYTES = 10_000_000  # MCP configs such as ~/.claude.json can grow large

# Directories (relative to $HOME) that hold credentials.
_SENSITIVE_HOME_DIRS = (".ssh", ".gnupg", ".aws", ".kube", ".password-store", ".config/gcloud")
# File names that hold credentials wherever they are.
_SENSITIVE_FILE_NAMES = frozenset(
    {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".netrc", ".pgpass", ".npmrc", ".pypirc"}
)
_ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template")


class SafetyError(Exception):
    """Base class for refusals made by the guard rails."""


class AccessRefused(SafetyError):
    """The path is protected or outside the allowed roots."""


class FileTooLarge(SafetyError):
    """The file exceeds the size limit."""


def is_sensitive(path: Path) -> bool:
    """True if ``path`` is (or lives inside) a credential location."""
    resolved = path.resolve()
    name = resolved.name
    if name in _SENSITIVE_FILE_NAMES:
        return True
    # ".env" and ".env.production" hold secrets; ".env.example" does not.
    if name == ".env" or (name.startswith(".env.") and not name.endswith(_ENV_TEMPLATE_SUFFIXES)):
        return True
    if resolved == Path("/etc/shadow"):
        return True
    home = Path.home().resolve()
    for relative in _SENSITIVE_HOME_DIRS:
        base = home / relative
        if resolved == base or base in resolved.parents:
            return True
    return False


def allowed_roots() -> list[Path]:
    """Roots listed in ``CHECKSKILLS_ALLOWED_ROOTS`` (``os.pathsep`` separated); empty = no limit."""
    raw = os.environ.get("CHECKSKILLS_ALLOWED_ROOTS", "")
    return [Path(p).expanduser().resolve() for p in raw.split(os.pathsep) if p.strip()]


def resolve_readable(path: str | Path, *, expect: str = "file") -> Path:
    """Resolve ``path`` and verify that CheckSkills may read it.

    Args:
        path: file or directory path (``~`` is expanded).
        expect: ``"file"``, ``"dir"`` or ``"any"``.

    Raises:
        AccessRefused: protected location, or outside the allowed roots.
        FileNotFoundError / NotADirectoryError: wrong kind of path.
    """
    resolved = Path(path).expanduser().resolve()
    if is_sensitive(resolved):
        raise AccessRefused(f"Refused: '{resolved}' is a protected credential location.")
    roots = allowed_roots()
    if roots and not any(root == resolved or root in resolved.parents for root in roots):
        raise AccessRefused(f"Refused: '{resolved}' is outside CHECKSKILLS_ALLOWED_ROOTS.")
    if expect == "file" and not resolved.is_file():
        raise FileNotFoundError(f"Not a file: {resolved}")
    if expect == "dir" and not resolved.is_dir():
        raise NotADirectoryError(f"Not a directory: {resolved}")
    return resolved


def read_text(path: str | Path, *, max_bytes: int = MAX_FILE_BYTES) -> str:
    """Read a text file after all safety checks (invalid UTF-8 bytes are replaced)."""
    resolved = resolve_readable(path)
    size = resolved.stat().st_size
    if size > max_bytes:
        raise FileTooLarge(f"Refused: '{resolved}' is {size} bytes (limit {max_bytes}).")
    return resolved.read_text(encoding="utf-8", errors="replace")


def read_head(path: Path, n: int = 2048) -> bytes:
    """First ``n`` bytes of an already-validated file (used to detect binaries)."""
    with path.open("rb") as handle:
        return handle.read(n)
