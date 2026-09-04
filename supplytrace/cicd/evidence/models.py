"""The Finding model: what a rule produces and everything downstream consumes.

Three things are kept apart here, because conflating them is how a scanner
starts telling people they have been breached when they have not:

``OBSERVED``
    A fact read out of the repository.  "Line 29 says ``uses:
    tj-actions/changed-files@v35``" is observed.

``INFERRED``
    A security judgement built on observations.  "That reference is mutable, so
    the action's owner can change what runs here" is inferred.

``HYPOTHESIS``
    A possible chain of events consistent with the evidence, which is what an
    attack path -- and anything the LLM says -- amounts to.

Every :class:`Finding` records which of the three it is, and carries the file,
line and snippet a reviewer needs to check it.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field

from supplytrace.cicd.parser.workflow import Location
from supplytrace.models.evidence import Confidence, RelationshipState


class Severity(str, Enum):
    """How much damage the weakness enables if it is reachable."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Sort key, highest severity first."""

        return _SEVERITY_ORDER[self]


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class FindingType(str, Enum):
    """What kind of weakness a finding describes.

    These are the categories the graph reasons over, so they name a *capability*
    an attacker gains rather than the rule that spotted it.
    """

    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    PRIVILEGE = "PRIVILEGE"
    UNTRUSTED_INPUT = "UNTRUSTED_INPUT"
    CODE_EXECUTION = "CODE_EXECUTION"
    SECRET_ACCESS = "SECRET_ACCESS"
    SECRET_EXFILTRATION = "SECRET_EXFILTRATION"
    NETWORK = "NETWORK"
    ARTIFACT_INTEGRITY = "ARTIFACT_INTEGRITY"
    RELEASE_INTEGRITY = "RELEASE_INTEGRITY"
    HISTORY = "HISTORY"
    PARSE_ERROR = "PARSE_ERROR"


class EvidenceItem(BaseModel):
    """One concrete, checkable citation.

    A finding without at least one of these is a claim with nothing behind it,
    which the collector refuses to accept.
    """

    model_config = ConfigDict(frozen=True)

    file: str
    line: int = 0
    snippet: str = ""
    """The exact text at that location, verbatim."""
    label: str = ""
    """What this citation is meant to show."""
    commit: str | None = None

    def describe(self) -> str:
        where = f"{self.file}:{self.line}" if self.line else self.file
        if self.commit:
            where = f"{where} @{self.commit[:12]}"
        return f"{where}  {self.snippet.strip()}" if self.snippet else where


class Finding(BaseModel):
    """One weakness, located and evidenced."""

    model_config = ConfigDict(frozen=True)

    id: str = ""
    """Assigned by the collector, e.g. ``F001``. Empty until then."""
    rule_id: str
    type: FindingType
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    """How sure the *detection* is, not how bad the issue is."""
    state: RelationshipState = RelationshipState.INFERRED
    """OBSERVED for a plain fact; INFERRED for a security judgement."""

    title: str
    description: str
    remediation: str = ""
    references: list[str] = Field(default_factory=list)

    file: str = ""
    line: int = 0
    workflow: str | None = None
    job: str | None = None
    step: str | None = None
    commit: str | None = None

    evidence: list[EvidenceItem] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    """Structured detail the graph builder consumes (action ref, secret names)."""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}" if self.line else self.file

    @property
    def confidence_band(self) -> Confidence:
        """The numeric confidence expressed on SupplyTrace's shared scale."""

        if self.confidence >= 0.85:
            return Confidence.HIGH
        if self.confidence >= 0.6:
            return Confidence.MEDIUM
        if self.confidence > 0.0:
            return Confidence.LOW
        return Confidence.UNKNOWN

    @property
    def evidence_snippet(self) -> str:
        """The first citation's text, for one-line CLI output."""

        return self.evidence[0].snippet.strip() if self.evidence else ""

    def sort_key(self) -> tuple[int, float, str, int]:
        return (self.severity.rank, -self.confidence, self.file, self.line)

    def summary(self) -> str:
        return f"{self.severity.value:8} {self.id:5} {self.title}"


def finding_from_location(
    location: Location,
    **fields: Any,
) -> Finding:
    """Build a Finding whose position is taken from a parsed :class:`Location`."""

    return Finding(
        file=location.file,
        line=location.line,
        workflow=location.workflow,
        job=location.job,
        step=location.step,
        **fields,
    )


__all__ = [
    "Confidence",
    "EvidenceItem",
    "Finding",
    "FindingType",
    "RelationshipState",
    "Severity",
    "finding_from_location",
]
