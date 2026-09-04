"""What the model is allowed to say, and how that is enforced.

Validation here does two separate jobs, and the second is the one that matters:

1. *Shape*: the response must be JSON matching :class:`LLMAnalysis`. Pydantic
   handles that.

2. *Grounding*: every finding id the model cites must be one that was actually
   sent to it. A model that invents ``F999`` -- or cites a real id that was not
   in its context -- has produced an unsupported claim, and unsupported claims
   are exactly what this tool exists to avoid. Invented ids are stripped and
   recorded in :attr:`ValidationReport.hallucinated_ids` rather than quietly
   passed through.

The verdict vocabulary contains no value meaning "an attack happened", for the
same reason the correlator's does not.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class LLMVerdict(str, Enum):
    """How the model characterises what it was shown."""

    POTENTIAL_ATTACK_CHAIN = "POTENTIAL_ATTACK_CHAIN"
    """The findings link into a coherent route an attacker could take."""
    ISOLATED_WEAKNESSES = "ISOLATED_WEAKNESSES"
    """Real problems, but they do not chain."""
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    """Not enough in the provided context to say either way."""
    NO_SIGNIFICANT_RISK = "NO_SIGNIFICANT_RISK"


class LLMConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class LLMAnalysis(BaseModel):
    """The structured response required from the model."""

    model_config = ConfigDict(extra="ignore")

    verdict: LLMVerdict
    confidence: LLMConfidence
    entry_point: str = ""
    attack_chain: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    impact: list[str] = Field(default_factory=list)
    attacker_requirements: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    summary: str = ""

    def render(self) -> str:
        """Plain-text rendering for the CLI."""

        lines = [
            f"verdict     : {self.verdict.value}",
            f"confidence  : {self.confidence.value}",
        ]
        if self.entry_point:
            lines.append(f"entry point : {self.entry_point}")
        if self.summary:
            lines.append(f"summary     : {self.summary}")
        for title, items in (
            ("attack chain", self.attack_chain),
            ("impact", self.impact),
            ("attacker must", self.attacker_requirements),
            ("missing evidence", self.missing_evidence),
            ("recommended", self.recommended_actions),
        ):
            if not items:
                continue
            lines.append(f"\n{title}:")
            lines.extend(f"  - {item}" for item in items)
        if self.evidence_ids:
            lines.append(f"\ngrounded in : {', '.join(self.evidence_ids)}")
        return "\n".join(lines)


@dataclass
class ValidationReport:
    """Result of checking a model response."""

    analysis: LLMAnalysis | None = None
    errors: list[str] = field(default_factory=list)
    hallucinated_ids: list[str] = field(default_factory=list)
    """Ids the model cited that were never sent to it."""

    @property
    def ok(self) -> bool:
        return self.analysis is not None


#: Matches a fenced code block, with or without a language tag. Models wrap
#: JSON in these even when told not to.
_FENCE_RE = re.compile(r"```(?:json)?\s*(?P<body>.*?)```", re.DOTALL | re.IGNORECASE)


def extract_json(text: str) -> str:
    """Pull the JSON object out of a model response.

    Handles the three things models actually do: return bare JSON, wrap it in a
    fence, or wrap it in prose. Anything else fails validation, which is the
    correct outcome.
    """

    stripped = (text or "").strip()
    if not stripped:
        return ""

    fenced = _FENCE_RE.search(stripped)
    if fenced:
        stripped = fenced.group("body").strip()

    if stripped.startswith("{"):
        return stripped

    # Fall back to the outermost balanced braces.
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start != -1 and end > start:
        return stripped[start : end + 1]
    return stripped


def validate_response(text: str, allowed_ids: set[str]) -> ValidationReport:
    """Parse and ground-check a model response.

    ``allowed_ids`` is the exact set of finding ids that were put in the
    prompt. Anything else the model cites is removed.
    """

    report = ValidationReport()
    payload = extract_json(text)
    if not payload:
        report.errors.append("model returned an empty response")
        return report

    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        report.errors.append(f"response was not valid JSON: {exc}")
        return report

    if not isinstance(data, dict):
        report.errors.append(
            f"expected a JSON object, got {type(data).__name__}"
        )
        return report

    try:
        analysis = LLMAnalysis.model_validate(data)
    except ValidationError as exc:
        report.errors.append(f"response did not match the required schema: {exc}")
        return report

    cited = list(analysis.evidence_ids)
    grounded = [fid for fid in cited if fid in allowed_ids]
    invented = [fid for fid in cited if fid not in allowed_ids]
    if invented:
        report.hallucinated_ids = invented
        report.errors.append(
            "model cited finding ids that were not provided: " + ", ".join(invented)
        )

    # A chain with no grounding left is a story, not an analysis.
    if not grounded and analysis.verdict is LLMVerdict.POTENTIAL_ATTACK_CHAIN:
        report.errors.append(
            "model claimed an attack chain but cited no valid evidence id; "
            "downgraded to INSUFFICIENT_EVIDENCE"
        )
        analysis = analysis.model_copy(
            update={
                "verdict": LLMVerdict.INSUFFICIENT_EVIDENCE,
                "confidence": LLMConfidence.LOW,
                "evidence_ids": [],
            }
        )
    else:
        analysis = analysis.model_copy(update={"evidence_ids": grounded})

    report.analysis = analysis
    return report


#: The JSON shape named in the prompt, kept next to the model that enforces it
#: so the two cannot drift apart.
RESPONSE_TEMPLATE = """{
  "verdict": "POTENTIAL_ATTACK_CHAIN | ISOLATED_WEAKNESSES | INSUFFICIENT_EVIDENCE | NO_SIGNIFICANT_RISK",
  "confidence": "HIGH | MEDIUM | LOW",
  "entry_point": "where an attacker starts, referencing a finding id",
  "attack_chain": ["ordered steps, each naming the finding id it rests on"],
  "evidence_ids": ["F001", "F004"],
  "impact": ["what the attacker gains"],
  "attacker_requirements": ["what the attacker must be able to do"],
  "missing_evidence": ["what cannot be determined from the provided context"],
  "recommended_actions": ["specific, ordered remediation"],
  "summary": "two sentences at most"
}"""


__all__ = [
    "LLMAnalysis",
    "LLMConfidence",
    "LLMVerdict",
    "RESPONSE_TEMPLATE",
    "ValidationReport",
    "extract_json",
    "validate_response",
]
