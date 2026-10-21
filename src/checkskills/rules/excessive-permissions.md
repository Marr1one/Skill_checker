# excessive-permissions (severity: high)

## What it detects
An MCP server started with `sudo`/`doas`, or given a very broad directory (`/`, `~`,
`$HOME`, `/home`, `/root`, `/etc`, `/usr`, `/var`) as an argument.

## Why it matters
The server (and anything that can steer it, including a prompt injection) gets everything
those permissions allow. A filesystem server that can see your whole home directory can
read your SSH keys.

## Typical false positives
Almost none for `sudo`. A broad path can be intended for a personal file-management
assistant, but it is still a decision to make consciously.

## What to do
Give the server a single working directory. Never run an MCP server as root.
