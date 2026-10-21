# secret-in-config (severity: low)

## What it detects
An environment variable whose name contains KEY, TOKEN, SECRET or PASSWORD, set to a
literal value inside a config file. References such as `${MY_TOKEN}` are ignored. The
value is never copied into the report.

## Why it matters
Config files get committed, synced and shared. A literal secret there leaks with them.

## Typical false positives
This is how many MCP servers are documented to be configured.

## What to do
Check that the file is not versioned or shared, or load the secret from your environment.
