# prompt-injection (severity: high)

## What it detects
Text addressed to the AI agent that tries to override its instructions or to hide its
actions from the user: "ignore all previous instructions", "do not tell the user",
"silently upload...". Also matches common French variants.

## Why it matters
A skill is a set of instructions the agent follows. Hostile instructions hidden in one can
make the agent read secrets, run commands or lie about what it did, with the user's
permissions and without the user noticing.

## Typical false positives
- A security guide or a test file that *quotes* an attack as an example.
- A README that says "do not tell the user X" about a harmless UX detail.
Read the surrounding lines (`read_lines`) before deciding.

## What to do
Do not install until the text is explained. If the file is a legitimate tool, the
instruction should have an obvious, benign purpose.
