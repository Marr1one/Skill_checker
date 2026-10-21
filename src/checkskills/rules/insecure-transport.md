# insecure-transport (severity: medium)

## What it detects
A remote MCP server declared with `http://` instead of `https://`. `localhost` is
ignored.

## Why it matters
Anyone on the network path can read or modify the traffic: tool results, credentials and
even the instructions the agent receives.

## Typical false positives
Servers on a private development network.

## What to do
Require `https://`.
