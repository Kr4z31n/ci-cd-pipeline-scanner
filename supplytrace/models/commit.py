"""Commit-level models.

Field names follow the specification (``commit_sha``, ``author_name``, ...) so
that the REST API in a later phase can serialise these objects directly.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, computed_field

from supplytrace.models.evidence import Evidence
from supplytrace.models.file import FileChange


class Identity(BaseModel):
    """A name/email pair as recorded in a Git commit object.

    Git identities are self-asserted: anyone can set ``user.email`` to anything.
    An identity is evidence of what the commit *claims*, not proof of who acted.
    """

    model_config = ConfigDict(frozen=True)

    name: str = ""
    email: str = ""

    @property
    def key(self) -> str:
        """Stable identity key, preferring email (lowercased)."""

        return (self.email or self.name).strip().lower()

    def __str__(self) -> str:
        if self.name and self.email:
            return f"{self.name} <{self.email}>"
        return self.name or self.email or "(unknown)"


class CommitRecord(BaseModel):
    """One commit and the file changes it introduced."""

    model_config = ConfigDict(frozen=True)

    commit_sha: str
    author_name: str = ""
    author_email: str = ""
    committer_name: str = ""
    committer_email: str = ""
    timestamp: datetime = Field(description="Author timestamp (when work was written).")
    committed_timestamp: datetime | None = Field(
        default=None, description="Committer timestamp (when it entered history)."
    )
    message: str = ""
    parent_commits: list[str] = Field(default_factory=list)
    file_changes: list[FileChange] = Field(default_factory=list)
    evidence: Evidence | None = None
    diff_truncated: bool = Field(
        default=False,
        description="True when file changes were not collected for this commit.",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def short_sha(self) -> str:
        return self.commit_sha[:12]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def subject(self) -> str:
        """First line of the commit message."""

        return self.message.splitlines()[0] if self.message else ""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_merge(self) -> bool:
        return len(self.parent_commits) > 1

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_root(self) -> bool:
        return not self.parent_commits

    @property
    def author(self) -> Identity:
        return Identity(name=self.author_name, email=self.author_email)

    @property
    def committer(self) -> Identity:
        return Identity(name=self.committer_name, email=self.committer_email)

    @property
    def additions(self) -> int:
        return sum(change.additions or 0 for change in self.file_changes)

    @property
    def deletions(self) -> int:
        return sum(change.deletions or 0 for change in self.file_changes)

    @property
    def touches_workflow(self) -> bool:
        """True if this commit modified a CI/CD workflow definition.

        This is the hook Phase 8 uses to link commits to workflows.
        """

        return any(c.is_workflow_file for c in self.file_changes)

    @property
    def touches_dependencies(self) -> bool:
        return any(c.is_dependency_file for c in self.file_changes)
