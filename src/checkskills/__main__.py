"""Allow ``python -m checkskills ...`` (same as the ``checkskills`` command)."""
from .cli import main

raise SystemExit(main())
