"""Hardened ``git`` invocation layer.

SupplyTrace treats every analysed repository as untrusted input (Phase 20).  A
repository's *local* configuration can make Git execute arbitrary commands - for
example ``core.fsmonitor`` or ``diff.external`` - so all inspection goes through
this single choke point, which:

* never uses a shell (``shell=False``, argument arrays only);
* neutralises the config keys that can cause command execution;
* ignores system and per-user Git configuration for reproducibility;
* strips inherited ``GIT_*`` environment variables;
* refuses interactive prompts and credential helpers;
* uses ``--no-optional-locks`` so analysis never writes to the target repo;
* enforces a wall-clock timeout and an output-size ceiling.

Rationale for not using GitPython here: GitPython also shells out to ``git`` but
does not give per-invocation control over the hardening flags above, and its
convenience objects hide the ``-z`` (NUL-delimited) output that is required to
parse arbitrary byte paths correctly.  Byte-exact, hardened plumbing matters
more for a provenance tool than object-model convenience.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from supplytrace.core.config import AnalysisConfig
from supplytrace.core.errors import (
    DubiousOwnershipError,
    GitCommandError,
    GitOutputTooLargeError,
    GitTimeoutError,
    NotAGitRepositoryError,
    RepositoryPathError,
)
from supplytrace.core.logging import get_logger

logger = get_logger("git")

#: Git config keys that can cause Git to execute an external program during
#: read-only inspection.  Set to empty so a hostile repository cannot use them.
HARDENING_CONFIG: tuple[str, ...] = (
    "core.fsmonitor=",
    "core.hooksPath=/dev/null",
    "credential.helper=",
    "core.pager=cat",
    "gc.auto=0",
    "protocol.allow=never",
    # Keep paths as raw bytes rather than C-style quoted strings.  With -z this
    # is already the case, but it guards any non--z command added later.
    "core.quotePath=false",
)

#: Diff-producing subcommands, and the flags that stop Git from running the
#: external diff drivers and textconv filters a repository can configure.
#:
#: Blanking ``diff.external`` via ``-c`` is NOT used: it makes Git abort with
#: "external diff died" on any repository that legitimately configures one,
#: turning a hostile setting into a denial of analysis. ``--no-ext-diff`` is
#: Git's own mechanism for the job and fails safe without failing loud.
DIFF_SAFETY_FLAGS: tuple[str, ...] = ("--no-ext-diff", "--no-textconv")

#: Subcommands that accept the flags above.
DIFF_SUBCOMMANDS: frozenset[str] = frozenset(
    {"log", "diff", "show", "whatchanged", "diff-tree", "diff-index", "format-patch"}
)

#: Subcommands that accept --no-textconv but not --no-ext-diff.
TEXTCONV_ONLY_SUBCOMMANDS: frozenset[str] = frozenset({"blame", "cat-file"})

#: Flags that would re-enable the execution paths above. They are stripped from
#: any caller's arguments: with Git, the last flag wins, so a stray --ext-diff
#: after our --no-ext-diff would silently undo the protection.
UNSAFE_DIFF_FLAGS: frozenset[str] = frozenset({"--ext-diff", "--textconv"})


#: Environment variables Git honours that we set deliberately.
BASE_ENV: dict[str, str] = {
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_ASKPASS": "",
    "SSH_ASKPASS": "",
    "GIT_OPTIONAL_LOCKS": "0",
    "LC_ALL": "C.UTF-8",
    "GIT_PAGER": "cat",
}

_DUBIOUS_OWNERSHIP_RE = re.compile(r"dubious ownership", re.IGNORECASE)
_NOT_A_REPO_RE = re.compile(r"not a git repository", re.IGNORECASE)


@dataclass(frozen=True)
class GitResult:
    """Result of one ``git`` invocation."""

    argv: list[str]
    returncode: int
    stdout: bytes
    stderr: str
    duration_seconds: float

    @property
    def text(self) -> str:
        """stdout decoded permissively.

        ``surrogateescape`` is used because Git paths are byte strings and are
        not guaranteed to be valid UTF-8.  Decoding this way keeps the bytes
        recoverable instead of destroying them with replacement characters.
        """

        return self.stdout.decode("utf-8", errors="surrogateescape")


def sanitize_repo_path(path: str | os.PathLike[str]) -> Path:
    """Resolve and validate a user-supplied repository path.

    Symlinks are resolved so that later path handling operates on a single
    canonical location.
    """

    candidate = Path(path).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise RepositoryPathError(f"path does not exist: {candidate}") from exc
    except OSError as exc:  # e.g. symlink loop, permission denied on a parent
        raise RepositoryPathError(f"path could not be resolved: {candidate} ({exc})") from exc

    if not resolved.is_dir():
        raise RepositoryPathError(f"path is not a directory: {resolved}")
    if not os.access(resolved, os.R_OK | os.X_OK):
        raise RepositoryPathError(f"path is not readable: {resolved}")
    return resolved


def build_git_env(parent_env: dict[str, str] | None = None) -> dict[str, str]:
    """Build a minimal, deterministic environment for a ``git`` child process.

    All inherited ``GIT_*`` variables are dropped so that ambient configuration
    cannot silently change analysis results.
    """

    source = os.environ if parent_env is None else parent_env
    env = {
        key: value
        for key, value in source.items()
        if not key.startswith("GIT_") and key not in {"GIT_DIR", "GIT_WORK_TREE"}
    }
    env.update(BASE_ENV)
    env.setdefault("PATH", os.defpath)
    return env


class GitRunner:
    """Runs hardened, read-only ``git`` commands against one repository."""

    def __init__(
        self,
        repo_path: str | os.PathLike[str],
        config: AnalysisConfig | None = None,
        *,
        git_executable: str | None = None,
    ) -> None:
        self.config = config or AnalysisConfig()
        self.repo_path = sanitize_repo_path(repo_path)
        resolved_exe = git_executable or shutil.which("git")
        if not resolved_exe:
            raise RepositoryPathError("git executable not found on PATH")
        self.git_executable = resolved_exe
        self._env = build_git_env()

    # -- command construction -------------------------------------------------

    def _base_argv(self) -> list[str]:
        argv = [
            self.git_executable,
            "--no-pager",
            "--no-optional-locks",
            "-C",
            str(self.repo_path),
        ]
        for setting in HARDENING_CONFIG:
            argv += ["-c", setting]
        if self.config.allow_dubious_ownership:
            argv += ["-c", f"safe.directory={self.repo_path}"]
        return argv

    @staticmethod
    def _harden_subcommand(args: list[str]) -> list[str]:
        """Insert diff-safety flags directly after a diff-producing subcommand.

        A repository can configure an external diff driver or a textconv filter
        and have Git execute it while merely *reading* history.  These flags are
        Git's supported way to refuse that.
        """

        if not args:
            return args
        subcommand = args[0]
        if subcommand in DIFF_SUBCOMMANDS:
            extra = list(DIFF_SAFETY_FLAGS)
        elif subcommand in TEXTCONV_ONLY_SUBCOMMANDS:
            extra = ["--no-textconv"]
        else:
            return args

        rest = [
            arg
            for arg in args[1:]
            if arg not in UNSAFE_DIFF_FLAGS and arg not in DIFF_SAFETY_FLAGS
        ]
        return [subcommand, *extra, *rest]

    # -- execution ------------------------------------------------------------

    def run(self, args: list[str], *, check: bool = True) -> GitResult:
        """Run ``git <args>`` and return the result.

        ``args`` must be a list of already-separated arguments; no shell is used
        and no string interpolation happens anywhere in this path.
        """

        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise TypeError("git arguments must be a list of strings")

        argv = self._base_argv() + self._harden_subcommand(args)
        logger.debug("running: %s", " ".join(argv))
        started = time.monotonic()

        with subprocess.Popen(  # noqa: S603 - argv list, shell=False, fixed executable
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            env=self._env,
            cwd=str(self.repo_path),
            shell=False,
        ) as proc:
            stdout, stderr_bytes = self._communicate(proc, argv)

        duration = time.monotonic() - started
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        result = GitResult(
            argv=argv,
            returncode=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
        )

        if check and result.returncode != 0:
            self._raise_for_error(result)
        return result

    def _communicate(
        self, proc: subprocess.Popen[bytes], argv: list[str]
    ) -> tuple[bytes, bytes]:
        """Collect output, enforcing timeout and output-size limits."""

        timeout = self.config.git_timeout_seconds
        limit = self.config.max_git_output_bytes
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            proc.kill()
            proc.communicate()
            raise GitTimeoutError(argv, timeout) from exc

        if len(stdout) > limit:
            raise GitOutputTooLargeError(argv, limit)
        return stdout, stderr

    def _raise_for_error(self, result: GitResult) -> None:
        stderr = result.stderr
        if _DUBIOUS_OWNERSHIP_RE.search(stderr):
            raise DubiousOwnershipError(
                f"git refused to use {self.repo_path}: detected dubious ownership.\n"
                "This protection exists because a repository's local config can "
                "cause command execution. Re-run with --allow-dubious-ownership "
                "only if you trust the repository's owner.\n"
                f"{stderr.strip()}"
            )
        if _NOT_A_REPO_RE.search(stderr):
            raise NotAGitRepositoryError(
                f"{self.repo_path} is not inside a Git repository.\n{stderr.strip()}"
            )
        raise GitCommandError(result.argv, result.returncode, stderr)

    # -- convenience ----------------------------------------------------------

    def text(self, args: list[str], *, check: bool = True) -> str:
        """Run a command and return stdout as (surrogate-escaped) text."""

        return self.run(args, check=check).text

    def line(self, args: list[str], *, default: str = "") -> str:
        """Run a command expected to print a single line; empty on failure."""

        result = self.run(args, check=False)
        if result.returncode != 0:
            return default
        return result.text.strip()

    def version(self) -> str:
        return self.line(["version"], default="unknown")

    def toplevel(self) -> Path | None:
        """Return the repository working-tree root, or None for a bare repo."""

        value = self.line(["rev-parse", "--show-toplevel"])
        return Path(value) if value else None

    def git_dir(self) -> Path:
        value = self.line(["rev-parse", "--absolute-git-dir"])
        if not value:
            raise NotAGitRepositoryError(
                f"{self.repo_path} is not inside a Git repository."
            )
        return Path(value)

    def is_bare(self) -> bool:
        return self.line(["rev-parse", "--is-bare-repository"]) == "true"

    def is_shallow(self) -> bool:
        return self.line(["rev-parse", "--is-shallow-repository"]) == "true"

    def has_commits(self) -> bool:
        """True if HEAD resolves to a commit (false for a freshly-init'd repo)."""

        return self.run(["rev-parse", "--verify", "HEAD"], check=False).returncode == 0

    def ensure_repository(self) -> None:
        """Validate that the target path is a usable Git repository."""

        result = self.run(["rev-parse", "--git-dir"], check=False)
        if result.returncode != 0:
            self._raise_for_error(result)
