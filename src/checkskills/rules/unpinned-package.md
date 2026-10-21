# unpinned-package (severity: medium)

## What it detects
- An MCP server launched with `npx`, `uvx`, `pipx run`... without an exact version
  (`some-server` instead of `some-server@1.2.3`).
- Dependencies pulled from git, a URL or a local path, or declared as `*` / `latest`.

## Why it matters
An unpinned runner executes the newest published version on every launch. If the package
is compromised tomorrow, it runs on your machine tomorrow, with no review.

## Typical false positives
Packages you maintain yourself, or throwaway experiments.

## What to do
Pin an exact version after reviewing it (`pkg@1.2.3`), and update deliberately.
