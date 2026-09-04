"""Repository-level models and the Phase 1 analysis report."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from supplytrace.core.config import AnalysisConfig
from supplytrace.models.commit import CommitRecord
from supplytrace.models.file import FileCategory


class RefKind(str, Enum):
    BRANCH = "BRANCH"
    REMOTE_BRANCH = "REMOTE_BRANCH"
    TAG = "TAG"


class BranchRef(BaseModel):
    """A named ref pointing at a commit."""

    model_config = ConfigDict(frozen=True)

    name: str
    full_ref: str
    target_sha: str
    kind: RefKind = RefKind.BRANCH
    is_head: bool = False


class RepositoryInfo(BaseModel):
    """Facts about the repository itself."""

    model_config = ConfigDict(frozen=True)

    path: str
    git_dir: str
    work_tree: str | None = None
    is_bare: bool = False
    is_shallow: bool = False
    head_sha: str | None = None
    head_ref: str | None = None
    default_branch_guess: str | None = None
    remotes: dict[str, str] = Field(default_factory=dict)
    git_version: str = "unknown"


class ParseAnomaly(BaseModel):
    """A record SupplyTrace could not parse.

    Anomalies are reported rather than silently dropped: for a provenance tool,
    "we could not read this" is a materially different answer from "there was
    nothing here".
    """

    model_config = ConfigDict(frozen=True)

    stage: str
    detail: str
    raw_excerpt: str = ""


class AnalysisStats(BaseModel):
    """Aggregate counters over the analysed history."""

    model_config = ConfigDict(frozen=True)

    commit_count: int = 0
    merge_commit_count: int = 0
    root_commit_count: int = 0
    author_count: int = 0
    committer_count: int = 0
    branch_count: int = 0
    tag_count: int = 0
    file_change_count: int = 0
    distinct_path_count: int = 0
    total_additions: int = 0
    total_deletions: int = 0
    binary_change_count: int = 0
    rename_count: int = 0
    commits_touching_workflows: int = 0
    commits_touching_dependencies: int = 0
    category_counts: dict[FileCategory, int] = Field(default_factory=dict)
    first_commit_at: datetime | None = None
    last_commit_at: datetime | None = None
    commit_limit_reached: bool = False


class AuthorSummary(BaseModel):
    """Per-author activity summary."""

    model_config = ConfigDict(frozen=True)

    name: str
    email: str
    commit_count: int = 0
    additions: int = 0
    deletions: int = 0
    files_touched: int = 0
    first_commit_at: datetime | None = None
    last_commit_at: datetime | None = None
    workflow_commit_count: int = 0
    dependency_commit_count: int = 0


class RepositoryAnalysis(BaseModel):
    """Complete Phase 1 result for one repository."""

    model_config = ConfigDict(frozen=True)

    tool_version: str
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    config: AnalysisConfig
    repository: RepositoryInfo
    branches: list[BranchRef] = Field(default_factory=list)
    commits: list[CommitRecord] = Field(default_factory=list)
    authors: list[AuthorSummary] = Field(default_factory=list)
    stats: AnalysisStats = Field(default_factory=AnalysisStats)
    anomalies: list[ParseAnomaly] = Field(default_factory=list)
    duration_seconds: float = 0.0

    def commit(self, sha: str) -> CommitRecord | None:
        """Look up a commit by full or abbreviated SHA."""

        if not sha:
            return None
        needle = sha.lower()
        for record in self.commits:
            if record.commit_sha == needle:
                return record
        matches = [c for c in self.commits if c.commit_sha.startswith(needle)]
        return matches[0] if len(matches) == 1 else None
