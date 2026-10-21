# Security model

## What CheckSkills covers

Static, pattern-based detection of well-known risks in skills, MCP configurations and
package manifests: prompt injection, hidden Unicode and comments, pipe-to-shell, credential
references, exfiltration instructions, install hooks, unpinned runners, over-broad
permissions, plain-HTTP servers, literal secrets, encoded blobs.

## What it does NOT cover

- **Binaries, minified or obfuscated code.** Reported as `opaque-content`, never judged.
- **Runtime behavior.** Nothing is executed, so nothing dynamic is observed.
- **Rephrased attacks.** An injection written in a way the patterns do not know will pass.
  Regexes are a floor, not a ceiling.
- **Transitive dependencies and the supply chain** beyond the first level.
- **Languages other than English and French** for text patterns.
- **False positives.** A security guide quoting an attack will be flagged; the rule cards and
  the agent's review exist to triage these.

"No issues found" is **not** "safe". Reading the code remains necessary for anything that
matters.

## Threat model of the tool itself

An agent analyzing hostile files can be manipulated by them. Mitigations:

| Threat | Mitigation |
|---|---|
| File text tries to give the agent orders | Results are labelled untrusted; the skill forbids obeying them and requires reporting them |
| Agent is tricked into reading secrets | `safety.py` refuses credential paths (symlink-safe), independent of any prompt |
| Agent reads outside the project | `CHECKSKILLS_ALLOWED_ROOTS` restricts readable roots |
| Agent writes somewhere dangerous | Only `save_report` writes: sanitized name, fixed directory, size limit |
| Zip bomb / huge input | 1 MB per file, 10 MB for configs, 2000 files per scan, symlinks not followed |
| Path traversal through rule ids | Ids are matched against a strict pattern and the registry |
| Secrets copied into reports | Environment values are never included in evidence |

## Reporting a vulnerability

Open a private security advisory on the repository, or email the maintainer.
