"""Guard rails (what the tool refuses to read) and rule/card consistency."""
import pytest

from checkskills import rules, safety


# ----------------------------------------------------------------------------- safety


def test_ssh_directory_is_protected(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    key = tmp_path / ".ssh" / "id_rsa"
    key.parent.mkdir()
    key.write_text("PRIVATE")
    with pytest.raises(safety.AccessRefused):
        safety.read_text(key)


@pytest.mark.parametrize("name", [".env", ".env.production", "id_ed25519", ".netrc"])
def test_credential_file_names_are_protected(tmp_path, name):
    path = tmp_path / name
    path.write_text("secret")
    with pytest.raises(safety.AccessRefused):
        safety.resolve_readable(path)


def test_env_templates_are_readable(tmp_path):
    path = tmp_path / ".env.example"
    path.write_text("KEY=")
    assert safety.read_text(path) == "KEY="


def test_symlink_to_secret_is_refused(tmp_path):
    secret = tmp_path / ".env"
    secret.write_text("secret")
    link = tmp_path / "innocent.txt"
    link.symlink_to(secret)
    with pytest.raises(safety.AccessRefused):
        safety.read_text(link)


def test_allowed_roots_restrict_access(tmp_path, monkeypatch):
    inside = tmp_path / "ok"
    inside.mkdir()
    (inside / "a.md").write_text("hi")
    outside = tmp_path / "other.md"
    outside.write_text("hi")
    monkeypatch.setenv("CHECKSKILLS_ALLOWED_ROOTS", str(inside))
    assert safety.read_text(inside / "a.md") == "hi"
    with pytest.raises(safety.AccessRefused):
        safety.read_text(outside)


def test_dotdot_cannot_escape_allowed_roots(tmp_path, monkeypatch):
    inside = tmp_path / "ok"
    inside.mkdir()
    (tmp_path / "secret.md").write_text("x")
    monkeypatch.setenv("CHECKSKILLS_ALLOWED_ROOTS", str(inside))
    with pytest.raises(safety.AccessRefused):
        safety.read_text(inside / ".." / "secret.md")


def test_oversized_files_are_refused(tmp_path):
    big = tmp_path / "big.md"
    big.write_text("x" * 100)
    with pytest.raises(safety.FileTooLarge):
        safety.read_text(big, max_bytes=50)


# ------------------------------------------------------------------------------ rules


def test_every_rule_has_a_card_and_every_card_has_a_rule():
    cards = {p.stem for p in rules.RULES_DIR.glob("*.md")}
    assert cards == set(rules.RULES)


def test_cards_follow_the_common_structure():
    for rule_id in rules.RULES:
        card = rules.rule_card(rule_id)
        assert card.startswith(f"# {rule_id}")
        assert "## What it detects" in card and "## What to do" in card


@pytest.mark.parametrize("bad_id", ["../README", "..", "nope", "REMOTE-EXEC", "a/b", ""])
def test_rule_card_rejects_unknown_and_traversal_ids(bad_id):
    with pytest.raises(KeyError):
        rules.rule_card(bad_id)


def test_rule_ids_used_by_scanners_are_registered():
    import re
    from pathlib import Path

    source = (Path(rules.__file__).parent / "scanners.py").read_text(encoding="utf-8")
    used = set(re.findall(r'(?:Finding|add|_opaque)\(\s*\n?\s*"([a-z-]+)"', source))
    assert used and used <= set(rules.RULES)
