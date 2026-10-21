# sensitive-access (severity: high)

## What it detects
References to credentials and secrets: `~/.ssh`, private keys (`id_rsa`, `id_ed25519`),
`~/.aws/credentials`, `~/.gnupg`, `~/.kube/config`, `.netrc`, browser cookies or
passwords, wallet files, and verbs such as "read" or "send" applied to a `.env` file.

## Why it matters
Almost no skill or MCP tool needs your keys. If a "text formatter" mentions them, the
declared purpose and the real behavior do not match.

## Typical false positives
Documentation of a Git or SSH helper, a backup tool, or a secrets manager legitimately
mentions these paths.

## What to do
Compare with the tool's declared function. If there is no obvious reason, treat it as
malicious and do not install.
