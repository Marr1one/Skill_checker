# hidden-text (severity: high, or medium for HTML comments)

## What it detects
- Zero-width characters, invisible operators and bidirectional overrides ("Trojan Source").
- Unicode "tag" characters, which mirror ASCII invisibly: a hidden message can be written
  that humans cannot see (the finding shows the decoded message).
- HTML comments containing instruction-like words.

## Why it matters
Humans review what they can see; an AI reads everything. Hidden text is a way to give the
agent instructions that no reviewer will ever notice.

## Typical false positives
- A byte-order mark at the very start of a file (ignored automatically).
- Emoji sequences and flags (ignored automatically).
- An HTML comment such as `<!-- TODO: upload new screenshot -->`.

## What to do
Display the raw content (`cat -A file`) and look for what is not visible. Remove the
invisible characters or do not install.
