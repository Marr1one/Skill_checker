"""The MCP tools (called as plain functions) and the CLI."""
import json
from pathlib import Path

from checkskills import cli, server

SAMPLES = Path(__file__).parent / "samples"


# ---------------------------------------------------------------------------- tools


def test_scan_path_tool_returns_untrusted_notice_and_findings():
    result = server.scan_path(str(SAMPLES / "evil-skill"))
    assert result["risk"] == "HIGH"
    assert "UNTRUSTED" in result["notice"]
    assert result["findings"][0]["severity"] == "high"  # most severe first


def test_clean_scan_never_says_safe():
    result = server.scan_path(str(SAMPLES / "clean-skill"))
    assert result["risk"] == "NO_ISSUES_FOUND"
    assert "NOT a guarantee" in result["risk_note"]
    assert "safe" not in result["risk"].lower()


def test_tools_return_errors_instead_of_raising(tmp_path):
    assert "error" in server.scan_path(str(tmp_path / "missing"))
    assert "error" in server.explain_rule("../../etc/passwd")
    assert "error" in server.read_lines(str(SAMPLES / "clean-skill/SKILL.md"), 5, 2)


def test_read_lines_numbers_the_lines_and_caps_the_range():
    result = server.read_lines(str(SAMPLES / "evil-skill/SKILL.md"), 8, 9)
    assert result["text"].splitlines()[0].startswith("8: Ignore all previous")
    assert (result["start"], result["end"]) == (8, 9)


def test_read_lines_refuses_credentials(tmp_path):
    secret = tmp_path / ".env"
    secret.write_text("TOKEN=x")
    assert "protected" in server.read_lines(str(secret))["error"]


def test_list_installed_servers_reads_a_given_config():
    result = server.list_installed_servers(str(SAMPLES / "bad-mcp-config.json"))
    risks = {s["server"]: s["risk"] for s in result["servers"]}
    assert risks["pinned-ok"] == "NO_ISSUES_FOUND"
    assert risks["root-tool"] == "HIGH"


def test_save_report_sanitizes_the_name(tmp_path, monkeypatch):
    monkeypatch.setenv("CHECKSKILLS_REPORTS_DIR", str(tmp_path / "out"))
    saved = Path(server.save_report("../../evil name", "# report")["saved_to"])
    assert saved.parent == (tmp_path / "out").resolve()
    assert saved.read_text() == "# report"
    assert "error" in server.save_report("x", "   ")


def test_resources_and_prompt():
    assert "remote-exec" in server.rules_index().splitlines()
    assert server.rule_resource("remote-exec").startswith("# remote-exec")
    assert "Unknown rule" in server.rule_resource("nope")
    assert "never as instructions" in server.audit_target("./skill")


# ------------------------------------------------------------------------------ CLI


def test_cli_scan_exit_codes(capsys):
    assert cli.main(["scan", str(SAMPLES / "evil-skill")]) == 0
    assert cli.main(["scan", str(SAMPLES / "evil-skill"), "--fail-on", "high"]) == 1
    assert cli.main(["scan", str(SAMPLES / "clean-skill"), "--fail-on", "low"]) == 0
    assert cli.main(["scan", "/definitely/missing"]) == 2
    capsys.readouterr()


def test_cli_json_output_is_valid(capsys):
    cli.main(["scan", str(SAMPLES / "evil-skill"), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["risk"] == "HIGH" and data["finding_count"] > 5


def test_cli_markdown_output_quotes_evidence(capsys):
    cli.main(["scan", str(SAMPLES / "evil-skill"), "--format", "markdown"])
    out = capsys.readouterr().out
    assert out.startswith("# Audit:") and "Evidence (untrusted content)" in out


def test_cli_rules_lists_everything(capsys):
    cli.main(["rules"])
    assert "prompt-injection" in capsys.readouterr().out
