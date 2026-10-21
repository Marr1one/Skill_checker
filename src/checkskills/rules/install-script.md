# install-script (severity: low to high)

## What it detects
`preinstall`, `install`, `postinstall` or `prepare` scripts in `package.json`. They run
automatically on `npm install`, before you have read anything.

## Why it matters
Install hooks are a classic supply-chain attack vector. The finding is **high** when the
script downloads (`curl`, `wget`), decodes (`base64`) or runs inline code (`node -e`,
`python -c`, `eval`); otherwise **low**.

## Typical false positives
Many legitimate packages compile native code in `postinstall`, or run `husky` in `prepare`.

## What to do
Install with `npm install --ignore-scripts`, read the script, then decide.
