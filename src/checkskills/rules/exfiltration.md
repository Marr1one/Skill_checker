# exfiltration (severity: medium)

## What it detects
Instructions to send, post, upload or forward something to an external `http(s)://` URL.

## Why it matters
This is the second half of a data theft: after reading secrets (see `sensitive-access`),
the data has to leave the machine. Alone it is weaker evidence, together it is strong.

## Typical false positives
Any API client or webhook integration documents "send a POST request to https://...".

## What to do
Check what is sent and whether the destination belongs to the tool's own service. Be
especially suspicious when it appears next to a `sensitive-access` finding.
