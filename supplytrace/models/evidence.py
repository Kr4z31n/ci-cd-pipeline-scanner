"""Evidence and confidence primitives.

Phase 14 of the specification requires that *every* relationship SupplyTrace
asserts carries evidence.  These types exist from Phase 1 onward so that later
phases (graph edges, trace engine, impact analysis) never have to retrofit them.

The tool distinguishes three things that are easy to conflate:

``RelationshipState``
    Epistemic status of the claim itself.  OBSERVED means the tool read the fact
    from an authoritative source (a Git object, a GitHub API response).
    INFERRED means the tool derived it from configuration or heuristics.

``Confidence``
    How much the tool trusts the claim, given the source.

``EvidenceSource``
    Where the claim came from, so a human investigator can re-check it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Confidence(str, Enum):
    """Confidence in an asserted relationship or provenance claim."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class RelationshipState(str, Enum):
    """Whether a relationship was observed, inferred, or is unknown."""

    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class EvidenceSource(str, Enum):
    """Authoritative source a claim was read from."""

    GIT_LOG = "git log"
    GIT_DIFF = "git diff"
    GIT_BLAME = "git blame"
    GIT_REFS = "git refs"
    WORKFLOW_YAML = "workflow yaml"
    GITHUB_API = "github api"
    DEPENDENCY_MANIFEST = "dependency manifest"
    HEURISTIC = "heuristic"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Evidence(BaseModel):
    """A citation supporting one claim made by the tool."""

    model_config = ConfigDict(frozen=True)

    source: EvidenceSource
    state: RelationshipState = RelationshipState.OBSERVED
    confidence: Confidence = Confidence.HIGH
    detail: dict[str, Any] = Field(default_factory=dict)
    collected_at: datetime = Field(default_factory=_utcnow)

    def describe(self) -> str:
        """Human-readable one-liner for CLI and report output."""

        bits = [f"{self.state.value} via {self.source.value}", f"confidence={self.confidence.value}"]
        if self.detail:
            rendered = ", ".join(f"{k}={v}" for k, v in sorted(self.detail.items()))
            bits.append(rendered)
        return "; ".join(bits)


def git_log_evidence(**detail: Any) -> Evidence:
    """Evidence for a fact read directly out of a Git commit object."""

    return Evidence(
        source=EvidenceSource.GIT_LOG,
        state=RelationshipState.OBSERVED,
        confidence=Confidence.HIGH,
        detail=detail,
    )


def git_diff_evidence(confidence: Confidence = Confidence.HIGH, **detail: Any) -> Evidence:
    """Evidence for a fact derived from a Git diff."""

    return Evidence(
        source=EvidenceSource.GIT_DIFF,
        state=RelationshipState.OBSERVED,
        confidence=confidence,
        detail=detail,
    )
