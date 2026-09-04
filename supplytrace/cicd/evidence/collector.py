"""Run the rules, assign finding IDs, and refuse unevidenced claims.

The registry lives here so that ``scan``, ``graph`` and the tests all run the
same rules in the same order and get the same IDs for the same repository.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from supplytrace.cicd.evidence.models import (
    EvidenceItem,
    Finding,
    FindingType,
    RelationshipState,
    Severity,
)
from supplytrace.cicd.parser.workflow import ParsedWorkflow, parse_repository_workflows
from supplytrace.cicd.rules.action_pinning import UnpinnedActionRule
from supplytrace.cicd.rules.artifacts import ArtifactTamperingRule
from supplytrace.cicd.rules.base import Rule, ScanContext
from supplytrace.cicd.rules.checkout import UntrustedCodeExecutionRule
from supplytrace.cicd.rules.history import WorkflowHistory, WorkflowHistoryRule
from supplytrace.cicd.rules.injection import ScriptInjectionRule
from supplytrace.cicd.rules.network import SuspiciousDownloadRule
from supplytrace.cicd.rules.permissions import ExcessivePermissionsRule
from supplytrace.cicd.rules.release import ReleaseRiskRule
from supplytrace.cicd.rules.secrets import SecretExposureRule
from supplytrace.cicd.rules.third_party import ThirdPartyActionRule
from supplytrace.cicd.rules.triggers import DangerousTriggerRule
from supplytrace.models.repository import RepositoryAnalysis


def default_rules() -> list[Rule]:
    """Every rule, in a fixed order so finding IDs are reproducible."""

    return [
        UnpinnedActionRule(),
        ExcessivePermissionsRule(),
        DangerousTriggerRule(),
        ScriptInjectionRule(),
        SecretExposureRule(),
        SuspiciousDownloadRule(),
        UntrustedCodeExecutionRule(),
        ArtifactTamperingRule(),
        ReleaseRiskRule(),
        ThirdPartyActionRule(),
        WorkflowHistoryRule(),
    ]


@dataclass
class ScanResult:
    """Everything one scan produced."""

    repo_path: str
    workflows: list[ParsedWorkflow] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    history: RepositoryAnalysis | None = None
    workflow_history: WorkflowHistory | None = None
    rule_errors: list[str] = field(default_factory=list)
    """Rules that raised. A crashing rule must not lose the other rules' work."""

    @property
    def context(self) -> ScanContext:
        return ScanContext(
            repo_path=self.repo_path,
            workflows=self.workflows,
            history=self.history,
            workflow_history=self.workflow_history,
        )

    def by_severity(self, *severities: Severity) -> list[Finding]:
        wanted = set(severities)
        return [f for f in self.findings if f.severity in wanted]

    def by_rule(self, rule_id: str) -> list[Finding]:
        return [f for f in self.findings if f.rule_id == rule_id]

    def by_type(self, finding_type: FindingType) -> list[Finding]:
        return [f for f in self.findings if f.type is finding_type]

    def finding(self, finding_id: str) -> Finding | None:
        return next((f for f in self.findings if f.id == finding_id), None)

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts

    @property
    def parse_failures(self) -> list[ParsedWorkflow]:
        return [w for w in self.workflows if not w.is_parsed]


def _parse_error_findings(workflows: list[ParsedWorkflow]) -> list[Finding]:
    """A workflow the tool could not read becomes a finding, not a silence.

    The spec is explicit about this: a malformed workflow is reported as
    evidence. "We could not analyse this file" is a materially different answer
    from "this file is clean", and only one of them is honest.
    """

    findings: list[Finding] = []
    for workflow in workflows:
        if workflow.is_parsed:
            continue
        findings.append(
            Finding(
                rule_id="WORKFLOW_PARSE_ERROR",
                type=FindingType.PARSE_ERROR,
                severity=Severity.INFO,
                confidence=1.0,
                state=RelationshipState.OBSERVED,
                title=f"Could not analyse {Path(workflow.path).name}",
                description=(
                    f"{workflow.path} could not be parsed: {workflow.parse_error}. "
                    f"No rule ran against this file, so its absence from the "
                    f"findings below means nothing was checked, not that nothing "
                    f"is wrong."
                ),
                remediation="Fix the YAML so the file can be analysed.",
                file=workflow.path,
                line=0,
                evidence=[
                    EvidenceItem(
                        file=workflow.path,
                        line=0,
                        snippet=workflow.parse_error,
                        label="parser output",
                    )
                ],
                metadata={"parse_error": workflow.parse_error},
            )
        )
    return findings


def collect_findings(context: ScanContext, rules: list[Rule] | None = None) -> tuple[list[Finding], list[str]]:
    """Run every rule and return sorted, ID-assigned findings plus rule errors.

    A finding with no evidence is dropped. The whole design rests on every claim
    being checkable, so a rule that produces an unevidenced one has a bug, and
    silently publishing it would undermine the guarantee the report makes.
    """

    rules = rules if rules is not None else default_rules()
    raw: list[Finding] = _parse_error_findings(context.workflows)
    errors: list[str] = []

    for rule in rules:
        try:
            produced = list(rule.apply(context))
        except Exception as exc:  # noqa: BLE001 - one bad rule must not sink the scan
            errors.append(f"{rule.id}: {type(exc).__name__}: {exc}")
            continue
        for finding in produced:
            if not finding.evidence:
                errors.append(f"{rule.id}: dropped a finding with no evidence: {finding.title}")
                continue
            raw.append(finding)

    raw.sort(key=lambda f: f.sort_key())
    findings = [
        finding.model_copy(update={"id": f"F{index:03d}"})
        for index, finding in enumerate(raw, start=1)
    ]
    return findings, errors


def scan_repository(
    repo_path: str | Path,
    *,
    history: RepositoryAnalysis | None = None,
    workflow_history: WorkflowHistory | None = None,
    rules: list[Rule] | None = None,
) -> ScanResult:
    """Parse a repository's workflows and run every rule over them."""

    path = str(repo_path)
    workflows = parse_repository_workflows(path)
    context = ScanContext(
        repo_path=path,
        workflows=workflows,
        history=history,
        workflow_history=workflow_history,
    )
    findings, errors = collect_findings(context, rules)
    return ScanResult(
        repo_path=path,
        workflows=workflows,
        findings=findings,
        history=history,
        workflow_history=workflow_history,
        rule_errors=errors,
    )


__all__ = ["ScanResult", "collect_findings", "default_rules", "scan_repository"]
