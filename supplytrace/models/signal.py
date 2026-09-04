"""Review-priority signals.

A signal is an *observed structural fact* about a commit that makes it worth a
human's attention -- for example "this commit changed a resolved lockfile
without changing any declared dependency".

Two things are kept strictly apart:

* Each individual signal is **OBSERVED**: it is read directly from Git data.
* The resulting *ranking* is **INFERRED**: it is a heuristic ordering, not a
  finding of compromise.

Nothing here asserts that a commit is malicious. The output is a reading order.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, computed_field

from supplytrace.models.evidence import Confidence, Evidence, EvidenceSource, RelationshipState


class Signal(str, Enum):
    """A structural property of a commit that is worth reviewing."""

    WORKFLOW_MODIFIED = "WORKFLOW_MODIFIED"
    DEPENDENCY_MANIFEST_MODIFIED = "DEPENDENCY_MANIFEST_MODIFIED"
    LOCKFILE_MODIFIED = "LOCKFILE_MODIFIED"
    LOCKFILE_WITHOUT_MANIFEST = "LOCKFILE_WITHOUT_MANIFEST"
    BUILD_AND_DEPENDENCIES_TOGETHER = "BUILD_AND_DEPENDENCIES_TOGETHER"
    FIRST_COMMIT_BY_AUTHOR = "FIRST_COMMIT_BY_AUTHOR"
    BINARY_ADDED = "BINARY_ADDED"


#: Relative weights. These order a reading list; they are not severity scores.
SIGNAL_WEIGHTS: dict[Signal, int] = {
    Signal.BUILD_AND_DEPENDENCIES_TOGETHER: 4,
    Signal.LOCKFILE_WITHOUT_MANIFEST: 3,
    Signal.WORKFLOW_MODIFIED: 2,
    Signal.DEPENDENCY_MANIFEST_MODIFIED: 1,
    Signal.LOCKFILE_MODIFIED: 1,
    Signal.FIRST_COMMIT_BY_AUTHOR: 1,
    Signal.BINARY_ADDED: 1,
}

#: Plain-language explanation of what each signal means and why it matters.
SIGNAL_DESCRIPTIONS: dict[Signal, str] = {
    Signal.WORKFLOW_MODIFIED:
        "changed a CI/CD workflow definition (how the software is built)",
    Signal.DEPENDENCY_MANIFEST_MODIFIED:
        "changed a declared dependency manifest",
    Signal.LOCKFILE_MODIFIED:
        "changed a resolved dependency lockfile",
    Signal.LOCKFILE_WITHOUT_MANIFEST:
        "changed resolved dependencies WITHOUT any declared dependency change",
    Signal.BUILD_AND_DEPENDENCIES_TOGETHER:
        "changed how the software is built AND what it is built from, in one commit",
    Signal.FIRST_COMMIT_BY_AUTHOR:
        "first commit by this author in the analysed history",
    Signal.BINARY_ADDED:
        "added a binary file, whose contents a diff cannot show",
}


class SignalHit(BaseModel):
    """One signal that fired on one commit, with the evidence for it."""

    model_config = ConfigDict(frozen=True)

    signal: Signal
    description: str
    paths: list[str] = Field(default_factory=list)
    evidence: Evidence

    @computed_field  # type: ignore[prop-decorator]
    @property
    def weight(self) -> int:
        return SIGNAL_WEIGHTS.get(self.signal, 1)


class CommitReviewPriority(BaseModel):
    """A commit's signals and its resulting position in the reading order."""

    model_config = ConfigDict(frozen=True)

    commit_sha: str
    short_sha: str
    author_name: str
    author_email: str
    timestamp: str
    subject: str
    hits: list[SignalHit] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def score(self) -> int:
        """Sum of the weights of every signal that fired."""

        return sum(hit.weight for hit in self.hits)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def signals(self) -> list[Signal]:
        return [hit.signal for hit in self.hits]

    def ranking_evidence(self) -> Evidence:
        """The ranking itself is an inference, and says so."""

        return Evidence(
            source=EvidenceSource.HEURISTIC,
            state=RelationshipState.INFERRED,
            confidence=Confidence.MEDIUM if self.score >= 4 else Confidence.LOW,
            detail={
                "score": self.score,
                "signals": ",".join(s.value for s in self.signals),
                "meaning": "review priority, not a finding of compromise",
            },
        )
