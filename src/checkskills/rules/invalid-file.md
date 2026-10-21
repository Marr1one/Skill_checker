# invalid-file (severity: low)

## What it detects
A structured file (such as `package.json`) that cannot be parsed.

## Why it matters
If the audit cannot read it, it cannot judge it. A deliberately malformed file can also be
an attempt to dodge analysis.

## What to do
Open the file manually and find out why it is malformed.
