# Test samples

Harmless files built **on purpose** to trigger (or not trigger) the rules. All domains use
the reserved `.invalid` TLD, so nothing can resolve.

- `evil-skill/` - a fake skill combining prompt injection, secret access, exfiltration,
  pipe-to-shell, an HTML comment and invisible characters (`SKILL.md` contains two
  zero-width spaces on its last line: that is intended), plus a `package.json` with a
  remote `postinstall`.
- `clean-skill/` - a benign skill: must produce no finding.
- `bad-mcp-config.json` - six MCP servers, one of them (`pinned-ok`) correct.
