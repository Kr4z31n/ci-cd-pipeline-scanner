"""Entry point for ``python -m cicd_detector``."""

from __future__ import annotations

import sys

from supplytrace.cicd.cli import main

if __name__ == "__main__":
    sys.exit(main())
