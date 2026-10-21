# CheckSkills

> Check an AI **skill** or an **MCP server** *before* you install it, straight from Claude Code, in plain language.

A `SKILL.md` is a set of instructions your AI agent follows. An MCP server is code that runs on
your machine. Almost nobody reads either before installing. CheckSkills gives the agent the tools
and the method to do it.

```
 You: "audit ./some-skill before I install it"
   │
   ▼
 Claude Code ── follows ──▶ skills/audit/SKILL.md      (the method)
   │
   ▼  MCP (stdio, JSON-RPC)
 CheckSkills server  (read-only)
   ├─ tools      scan_path · list_installed_servers · explain_rule · read_lines · save_report
   ├─ resources  rules://<id>        one Markdown card per detection rule
   └─ prompt     audit_target
   │
   ▼
 Markdown report: verdict, evidence (file:line), mismatches, blind spots
```

Three pieces, each with one job:

| Piece | Job |
|---|---|
| **MCP server** (`src/checkskills/server.py`) | gives the agent eyes: deterministic, read-only tools |
| **Skill** (`skills/audit/SKILL.md`) | tells the agent how to investigate and what it must never conclude |
| **Rule cards** (`src/checkskills/rules/*.md`) | knowledge base read by the agent *and* by humans |

The detection itself is plain Python (regex, JSON parsing, Unicode checks): precise and
repeatable. The agent adds what code cannot: reading the context, discarding false positives,
spotting mismatches between what a tool claims and what it asks for.

## What it detects
  
| Rule | Example |
|---|---|
| `prompt-injection` | "ignore all previous instructions", "do not tell the user" |
| `hidden-text` | zero-width characters, invisible Unicode tag messages, instruction-like HTML comments |
| `remote-exec` | `curl ... \| sh`, `base64 -d \| sh` |
| `sensitive-access` | `~/.ssh`, `.aws/credentials`, "read the `.env`" |
| `exfiltration` | "send ... to https://..." |
| `install-script` | `postinstall` that downloads or evals code |
| `unpinned-package` | `npx some-server` without a version, git dependencies |
| `excessive-permissions` | `sudo`, a whole home directory handed to a server |
| `insecure-transport` | remote MCP server over `http://` |
| `secret-in-config` | literal API token in a config file |
| `obfuscated-payload`, `opaque-content`, `invalid-file` | what a human (or this tool) cannot review |

`checkskills rules` lists them all; each has a card in `src/checkskills/rules/`.

## Install

```bash
git clone <your-repo-url> && cd checkskills
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest

# connect the MCP server to Claude Code
claude mcp add checkskills -- "$(pwd)/.venv/bin/checkskills" serve

# install the skill
mkdir -p ~/.claude/skills && cp -r skills/audit ~/.claude/skills/
```

## Use

With the agent:

> "Audit `./downloads/some-skill` before I install it."
> "Check the MCP servers I already have installed."

Without any AI (terminal, git hook, CI):

```bash
checkskills scan ./some-skill                       # human-readable
checkskills scan ./some-skill --format markdown     # shareable report
checkskills scan ./some-skill --fail-on high        # exit code 1 in CI
checkskills config                                  # audit installed MCP servers
```

Example on the bundled trap sample (`tests/samples/evil-skill`): verdict **HIGH**, 9 findings
including prompt injection (line 8), `~/.ssh/id_rsa` access (line 9), `curl | bash` (line 10) and
invisible characters (line 12). On the clean sample: *no issues found (this is NOT a guarantee)*.

## Safety design

The tool is itself an attack surface: a hostile file may try to steer the agent that analyzes
it. So the guard rails live **in the code**, not only in prompts:

- read-only; nothing audited is ever executed; no network access;
- credential locations (`~/.ssh`, `~/.aws`, `.env`, private keys) are refused, symlinks included;
- optional `CHECKSKILLS_ALLOWED_ROOTS` restricts what can be read at all;
- the only write is `save_report`, with a sanitized file name, into `CHECKSKILLS_REPORTS_DIR`;
- every result that quotes file content is labelled untrusted; the skill forbids obeying it;
- the verdict scale has no "safe": the best answer is "no issues found".

Limits are documented honestly in [SECURITY.md](SECURITY.md).

## Project layout

```
src/checkskills/
  models.py      data types (Finding, Severity, ScanReport)
  rules.py       rule registry, patterns, card loader
  safety.py      what the tool refuses to read
  scanners.py    the analysis engine (pure Python)
  inventory.py   find and audit installed MCP servers
  report.py      text / Markdown / JSON output
  server.py      the MCP server
  cli.py         the command line
  rules/*.md     one documentation card per rule
skills/audit/SKILL.md   the agent's method
tests/                  pytest + harmless trap samples
```

## Add a rule

1. Add a `Rule(...)` to `src/checkskills/rules.py`.
2. Add `src/checkskills/rules/<id>.md` (a test checks every rule has a card).
3. Add a sample line and a test in `tests/`.

## Notes

- The MCP Python SDK is pinned to 1.x (`mcp>=1.2,<2`); 2.x renames the server API.
- Roadmap: `fetch_repo` (isolated shallow clone without hooks), SARIF output, a GitHub Action,
  a labelled benchmark (detection rate and false positives over N samples).

MIT license.
