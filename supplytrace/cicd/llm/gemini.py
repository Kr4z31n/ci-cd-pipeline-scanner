"""Gemini provider, and the analysis entry point the CLI calls.

``google-genai`` is imported lazily inside the constructor so that the package
imports -- and the whole test suite runs -- without it installed. An optional
dependency that breaks ``import`` is not optional.

The API key comes from ``GEMINI_API_KEY`` (or ``GOOGLE_API_KEY``). It is never
read from a file, never logged, and never written into a report.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from supplytrace.cicd.evidence.collector import ScanResult
from supplytrace.cicd.graph.builder import AttackGraph
from supplytrace.cicd.graph.correlation import AttackPath
from supplytrace.cicd.llm.base import LLMError, LLMProvider, LLMResponse
from supplytrace.cicd.llm.prompts import (
    SYSTEM_PROMPT,
    EvidencePackage,
    build_evidence_package,
)
from supplytrace.cicd.llm.schemas import LLMAnalysis, validate_response

#: Environment variables checked for a key, in order.
API_KEY_VARIABLES = ("GEMINI_API_KEY", "GOOGLE_API_KEY")

DEFAULT_MODEL = "gemini-2.5-flash"


def api_key_from_environment() -> str:
    """The configured key, or an empty string."""

    for variable in API_KEY_VARIABLES:
        value = os.environ.get(variable, "").strip()
        if value:
            return value
    return ""


class GeminiProvider:
    """Talks to Gemini through the ``google-genai`` SDK."""

    name = "gemini"

    def __init__(self, *, model: str = DEFAULT_MODEL, api_key: str = "") -> None:
        self.model = model
        self._api_key = api_key or api_key_from_environment()
        self._client = None

    def is_available(self) -> bool:
        if not self._api_key:
            return False
        try:
            import google.genai  # noqa: F401
        except ImportError:
            return False
        return True

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        if not self._api_key:
            raise LLMError(
                "no API key found. Set GEMINI_API_KEY, or pass --no-llm to skip "
                "the correlation step."
            )
        try:
            from google import genai
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise LLMError(
                "google-genai is not installed. Install it with "
                "'pip install google-genai', or pass --no-llm."
            ) from exc
        self._client = genai.Client(api_key=self._api_key)
        return self._client

    def generate(self, prompt: str, *, system: str = "") -> LLMResponse:
        client = self._ensure_client()
        try:
            from google.genai import types

            config = types.GenerateContentConfig(
                system_instruction=system or None,
                # The response has to parse as JSON; creativity is not wanted
                # anywhere in this path.
                temperature=0.1,
                response_mime_type="application/json",
            )
            response = client.models.generate_content(
                model=self.model, contents=prompt, config=config
            )
        except Exception as exc:  # noqa: BLE001 - SDK raises many types
            raise LLMError(f"Gemini request failed: {type(exc).__name__}: {exc}") from exc

        text = getattr(response, "text", "") or ""
        if not text:
            raise LLMError("Gemini returned an empty response")

        usage: dict[str, int] = {}
        metadata = getattr(response, "usage_metadata", None)
        if metadata is not None:
            for attribute in ("prompt_token_count", "candidates_token_count", "total_token_count"):
                value = getattr(metadata, attribute, None)
                if isinstance(value, int):
                    usage[attribute] = value

        return LLMResponse(text=text, model=self.model, usage=usage)


@dataclass
class CorrelationResult:
    """Outcome of the LLM step, successful or not."""

    analysis: LLMAnalysis | None = None
    errors: list[str] = field(default_factory=list)
    hallucinated_ids: list[str] = field(default_factory=list)
    prompt_chars: int = 0
    findings_sent: int = 0
    paths_sent: int = 0
    model: str = ""
    usage: dict[str, int] = field(default_factory=dict)
    skipped_reason: str = ""

    @property
    def ok(self) -> bool:
        return self.analysis is not None


def correlate(
    result: ScanResult,
    graph: AttackGraph | None = None,
    paths: list[AttackPath] | None = None,
    *,
    provider: LLMProvider | None = None,
    package: EvidencePackage | None = None,
) -> CorrelationResult:
    """Ask the model to correlate the findings, and validate what comes back.

    Every failure mode -- no key, no network, malformed JSON, invented evidence
    ids -- returns a :class:`CorrelationResult` carrying the reason. None of
    them raises, because the deterministic report is already complete by this
    point and must still be printed.
    """

    provider = provider or GeminiProvider()
    package = package or build_evidence_package(result, graph, paths)

    outcome = CorrelationResult(
        prompt_chars=len(package.prompt),
        findings_sent=package.finding_count,
        paths_sent=package.path_count,
        model=getattr(provider, "model", provider.name),
    )

    if not provider.is_available():
        outcome.skipped_reason = (
            "no LLM provider configured (set GEMINI_API_KEY to enable correlation)"
        )
        return outcome

    try:
        response = provider.generate(package.prompt, system=SYSTEM_PROMPT)
    except LLMError as exc:
        outcome.errors.append(str(exc))
        return outcome

    outcome.usage = response.usage
    if response.model:
        outcome.model = response.model

    report = validate_response(response.text, package.allowed_ids)
    outcome.analysis = report.analysis
    outcome.errors.extend(report.errors)
    outcome.hallucinated_ids = report.hallucinated_ids
    return outcome


__all__ = [
    "API_KEY_VARIABLES",
    "DEFAULT_MODEL",
    "CorrelationResult",
    "GeminiProvider",
    "api_key_from_environment",
    "correlate",
]
