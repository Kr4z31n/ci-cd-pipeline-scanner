"""SupplyTrace - software supply chain attack traceability and provenance tool.

SupplyTrace models a software repository as a provenance graph so that an
investigator can answer "where did this code come from?" and "how did it move
through the supply chain?".

The package is built in phases.  Phase 1 (implemented) covers Git repository
analysis: repository metadata, branches, commits, authors and per-commit file
changes.
"""

#: Keep in step with `version` in pyproject.toml. The CLI reports this, so a
#: drift here means `--version` disagrees with the installed package.
__version__ = "0.2.0"
__all__ = ["__version__"]
