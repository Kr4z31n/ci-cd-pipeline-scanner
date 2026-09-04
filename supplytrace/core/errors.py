"""Exception hierarchy for SupplyTrace.

Every error raised by the tool derives from :class:`SupplyTraceError` so that a
caller (CLI, API, or another analyzer) can distinguish tool failures from
programming errors.
"""

from __future__ import annotations


class SupplyTraceError(Exception):
    """Base class for all SupplyTrace errors."""


class ConfigurationError(SupplyTraceError):
    """The tool was configured with values it cannot work with."""


class RepositoryError(SupplyTraceError):
    """The target repository could not be used for analysis."""


class RepositoryPathError(RepositoryError):
    """The supplied repository path is missing, unreadable, or unsafe."""


class NotAGitRepositoryError(RepositoryError):
    """The supplied path exists but is not inside a Git repository."""


class DubiousOwnershipError(RepositoryError):
    """Git refused the repository because it is owned by another user.

    Git's ``safe.directory`` protection exists precisely because a repository's
    local configuration can cause command execution.  SupplyTrace does not
    silently bypass it; the operator must opt in explicitly.
    """


class GitCommandError(SupplyTraceError):
    """A ``git`` invocation failed."""

    def __init__(
        self,
        argv: list[str],
        returncode: int,
        stderr: str = "",
    ) -> None:
        self.argv = list(argv)
        self.returncode = returncode
        self.stderr = stderr
        rendered = " ".join(argv)
        message = f"git command failed (exit {returncode}): {rendered}"
        if stderr.strip():
            message = f"{message}\n{stderr.strip()}"
        super().__init__(message)


class GitTimeoutError(GitCommandError):
    """A ``git`` invocation exceeded the configured timeout."""

    def __init__(self, argv: list[str], timeout: float) -> None:
        self.timeout = timeout
        super().__init__(argv, returncode=-1, stderr=f"timed out after {timeout}s")


class GitOutputTooLargeError(GitCommandError):
    """A ``git`` invocation produced more output than the configured limit."""

    def __init__(self, argv: list[str], limit_bytes: int) -> None:
        self.limit_bytes = limit_bytes
        super().__init__(
            argv,
            returncode=-1,
            stderr=f"output exceeded limit of {limit_bytes} bytes",
        )


class AnalysisError(SupplyTraceError):
    """Analysis could not be completed."""
