# remote-exec (severity: high)

## What it detects
Commands that download code and run it immediately, without anyone reading it:
`curl ... | sh`, `wget ... | bash`, `bash <(curl ...)`, `base64 -d | sh`,
`eval(atob(...))`.

## Why it matters
The code that runs is whatever the remote server sends *at that moment*. It can differ
between users, or change after the project was reviewed.

## Typical false positives
Well-known official installers (rustup, nvm, Homebrew) use this pattern. Check that the
domain is the official one.

## What to do
Download the script first, read it, then run it. Prefer a package manager with pinned,
checksummed versions.
