"""``cicd_detector`` -- the CI/CD attack detector's command line entry point.

The implementation lives in :mod:`supplytrace.cicd`, where it can reuse
SupplyTrace's Git analyzer, evidence model and hardened Git layer rather than
duplicating them. This package exists so the tool is reachable under the name
the specification uses::

    python -m cicd_detector scan ./repo

Both spellings run the same code:

    python -m cicd_detector scan ./repo
    python -m supplytrace scan ./repo
"""

from __future__ import annotations

from supplytrace import __version__
from supplytrace.cicd.cli import build_parser, main

__all__ = ["__version__", "build_parser", "main"]
