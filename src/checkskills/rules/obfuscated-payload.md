# obfuscated-payload (severity: medium)

## What it detects
A single very long run (200+ characters) of base64-like text.

## Why it matters
A blob that humans cannot read can hide a script, a command or an instruction. Legitimate
text is almost never written this way.

## Typical false positives
Embedded fonts, certificates, hashes lists, test fixtures. Inline images
(`data:image/...;base64,`) are ignored automatically.

## What to do
Decode it in a safe environment (never execute it) and read the result.
