# opaque-content (severity: medium for binaries, low for minified scripts)

## What it detects
- Compiled or binary files (`.so`, `.exe`, `.wasm`, ELF binaries...).
- JavaScript files with extremely long lines (minified or obfuscated).

## Why it matters
Static text analysis cannot see what such content does. The honest answer is "cannot be
verified", not "no issues".

## Typical false positives
Minified bundles are normal in published npm packages; native modules are normal for
performance-sensitive tools.

## What to do
Check where the artifact comes from (official release, reproducible build), or ask for the
source. Do not treat the absence of findings in a binary as a sign of safety.
