"""Shared pytest fixtures.

Fixture repositories are built with a fully controlled environment so that the
developer's own Git configuration (user.name, commit.gpgsign, init.defaultBranch,
hooks, templates) cannot influence test results.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


class GitRepoBuilder:
    """Builds deterministic fixture repositories for tests."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.mkdir(parents=True, exist_ok=True)
        self._clock = 0
        self.git("init", "-q", "-b", "main", ".")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.autocrlf", "false")

    # -- primitives -----------------------------------------------------------

    def _env(self, name: str = "Test User", email: str = "test@example.com") -> dict[str, str]:
        stamp = f"2024-01-01T{self._clock // 60 % 24:02d}:{self._clock % 60:02d}:00+00:00"
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GIT_")
        }
        env.update(
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_AUTHOR_NAME": name,
                "GIT_AUTHOR_EMAIL": email,
                "GIT_COMMITTER_NAME": name,
                "GIT_COMMITTER_EMAIL": email,
                "GIT_AUTHOR_DATE": stamp,
                "GIT_COMMITTER_DATE": stamp,
                "LC_ALL": "C.UTF-8",
            }
        )
        return env

    def git(self, *args: str, author: str = "Test User", email: str = "test@example.com") -> str:
        result = subprocess.run(
            ["git", *args],
            cwd=self.path,
            env=self._env(author, email),
            capture_output=True,
            check=True,
        )
        return result.stdout.decode("utf-8", errors="surrogateescape")

    # -- convenience ----------------------------------------------------------

    def write(self, relative: str, content: str | bytes) -> Path:
        target = self.path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")
        return target

    def write_bytes_path(self, raw_name: bytes, content: bytes) -> None:
        """Create a file whose *name* is arbitrary bytes (spaces, newlines...)."""

        target = os.path.join(os.fsencode(str(self.path)), raw_name)
        with open(target, "wb") as handle:
            handle.write(content)

    def commit(
        self,
        message: str,
        *,
        author: str = "Test User",
        email: str = "test@example.com",
        allow_empty: bool = False,
    ) -> str:
        self._clock += 1
        self.git("add", "-A", author=author, email=email)
        args = ["commit", "-q", "-m", message]
        if allow_empty:
            args.append("--allow-empty")
        self.git(*args, author=author, email=email)
        return self.head()

    def head(self) -> str:
        return self.git("rev-parse", "HEAD").strip()

    def checkout_new(self, branch: str, start: str | None = None) -> None:
        args = ["checkout", "-q", "-b", branch]
        if start:
            args.append(start)
        self.git(*args)

    def checkout(self, ref: str) -> None:
        self.git("checkout", "-q", ref)


@pytest.fixture
def repo_builder(tmp_path: Path) -> GitRepoBuilder:
    """An initialised, empty Git repository."""

    return GitRepoBuilder(tmp_path / "repo")


@pytest.fixture
def sample_repo(repo_builder: GitRepoBuilder) -> GitRepoBuilder:
    """A repository exercising every Phase 1 code path.

    History (oldest first):

    1. Alice  - initial source + dependency manifest
    2. Bob    - modify source, add a workflow file, add a lockfile
    3. Alice  - rename source, delete a file, add a binary blob
    4. Carol  - branch commit, merged back with a no-fast-forward merge
    """

    builder = repo_builder

    builder.write("src/auth.py", "import os\n\n\ndef login(user):\n    return True\n")
    builder.write("requirements.txt", "requests==2.31.0\n")
    builder.write("README.md", "# demo\n")
    first = builder.commit("Initial commit", author="Alice", email="alice@example.com")

    builder.write(
        "src/auth.py",
        "import os\n\n\ndef login(user, token):\n    return verify(token)\n\n\ndef verify(token):\n    return bool(token)\n",
    )
    builder.write(
        ".github/workflows/build.yml",
        "name: Build\non:\n  push:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
    )
    builder.write("package-lock.json", '{"lockfileVersion": 3}\n')
    second = builder.commit("Add build workflow", author="Bob", email="bob@example.com")

    builder.git("mv", "src/auth.py", "src/authentication.py")
    builder.write(
        "src/authentication.py",
        "import os\n\n\ndef login(user, token):\n    return verify(token)\n\n\ndef verify(token):\n    return bool(token)\n\n\ndef logout(user):\n    return None\n",
    )
    builder.git("rm", "-q", "README.md")
    builder.write("assets/logo.bin", bytes(range(256)) * 4)
    third = builder.commit("Rename auth module", author="Alice", email="alice@example.com")

    builder.checkout_new("feature", third)
    builder.write("src/feature.py", "VALUE = 1\n")
    fourth = builder.commit("Add feature", author="Carol", email="carol@example.com")

    builder.checkout("main")
    builder.git(
        "merge",
        "-q",
        "--no-ff",
        "feature",
        "-m",
        "Merge feature branch",
        author="Alice",
        email="alice@example.com",
    )

    builder.shas = {  # type: ignore[attr-defined]
        "first": first,
        "second": second,
        "third": third,
        "fourth": fourth,
        "merge": builder.head(),
    }
    return builder


@pytest.fixture(scope="session")
def demo_repo(tmp_path_factory) -> Path:
    """The `paylite` demonstration repository, built once per test session.

    Tests use this to assert that the planted supply-chain attack actually
    surfaces -- if a change to the signal logic stopped ranking it first, the
    demonstration would silently stop working.
    """

    import sys

    target = tmp_path_factory.mktemp("demo") / "paylite"
    builder = Path(__file__).resolve().parents[1] / "examples" / "build_demo.py"
    subprocess.run(
        [sys.executable, str(builder), "--target", str(target)],
        capture_output=True,
        check=True,
    )
    return target
