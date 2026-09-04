"""Configuration for a single repository analysis.

``AnalysisConfig`` holds the per-analysis knobs (limits, rename detection,
timeouts).  It is immutable and safe to serialise into a report, so a result can
always be reproduced from the settings recorded alongside it.

Credential handling arrives with the GitHub API phase; until something actually
needs a token, there is no settings object holding one.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

DiffMergesMode = Literal["off", "first-parent"]

#: Hard ceiling applied to any configured commit limit.  Prevents an accidental
#: ``--max-commits 0`` style value from being interpreted as "unbounded".
MAX_SUPPORTED_COMMITS = 5_000_000


class AnalysisConfig(BaseModel):
    """Knobs controlling how a repository is analysed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_commits: int | None = Field(
        default=50_000,
        description="Stop after this many commits. None means no limit.",
    )
    include_all_refs: bool = Field(
        default=True,
        description=(
            "Walk every ref (branches, remotes, tags) instead of only HEAD. "
            "Provenance questions usually need the full ref set."
        ),
    )
    detect_renames: bool = Field(
        default=True,
        description="Ask Git to detect renames (-M).",
    )
    rename_threshold: int = Field(
        default=50,
        ge=1,
        le=100,
        description="Rename similarity threshold in percent.",
    )
    detect_copies: bool = Field(
        default=False,
        description=(
            "Ask Git to detect copies (-C). Off by default because copy "
            "detection is significantly more expensive on large histories."
        ),
    )
    diff_merges: DiffMergesMode = Field(
        default="first-parent",
        description=(
            "How to compute file changes for merge commits. 'first-parent' "
            "records what a merge introduced into its target branch, which is "
            "what an 'evil merge' would exploit. 'off' records no file changes "
            "for merge commits."
        ),
    )
    git_timeout_seconds: float = Field(
        default=300.0,
        gt=0,
        description="Timeout applied to each individual git invocation.",
    )
    max_git_output_bytes: int = Field(
        default=512 * 1024 * 1024,
        gt=0,
        description="Abort a git invocation whose output exceeds this size.",
    )
    allow_dubious_ownership: bool = Field(
        default=False,
        description=(
            "Opt in to analysing a repository owned by a different user by "
            "adding it to safe.directory for the duration of the run."
        ),
    )

    @field_validator("max_commits")
    @classmethod
    def _validate_max_commits(cls, value: int | None) -> int | None:
        if value is None:
            return None
        if value < 1:
            raise ValueError("max_commits must be >= 1 (use None for no limit)")
        if value > MAX_SUPPORTED_COMMITS:
            raise ValueError(f"max_commits must be <= {MAX_SUPPORTED_COMMITS}")
        return value
