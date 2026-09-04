"""Entry point for ``python -m supplytrace``."""

from __future__ import annotations

import sys

from supplytrace.cli import main

if __name__ == "__main__":
    sys.exit(main())
