"""RULE 2 -- GITHUB_TOKEN permissions wider than the job needs.

The spec is explicit that not every write permission is critical, and that is
right: a workflow whose entire purpose is to label pull requests genuinely needs
``pull-requests: write``.  What makes a permission dangerous is the company it
keeps -- whether the job also runs code an outsider can influence.

So this rule reports two different things:

* the permission itself, at a severity set by what that scope can do; and
* the *absence* of any ``permissions:`` block, which is its own finding, because
  a repository whose default is still the legacy read-write token hands every
  job full write access to the repository without ever saying so.
"""

from __future__ import annotations

from typing import Iterable

from supplytrace.cicd.evidence.models import (
    EvidenceItem,
    Finding,
    FindingType,
    RelationshipState,
    Severity,
)
from supplytrace.cicd.parser.workflow import WRITE_PERMISSION_IMPACT
from supplytrace.cicd.rules.base import (
    Rule,
    ScanContext,
    job_writes,
    untrusted_triggers,
)

#: Scopes whose write access changes what the repository ships, or grants
#: credentials beyond GitHub. These are the ones worth waking someone for.
_HIGH_IMPACT_SCOPES = frozenset({"contents", "actions", "packages", "id-token", "deployments"})


class ExcessivePermissionsRule(Rule):
    id = "EXCESSIVE_PERMISSIONS"
    name = "Job holds write permissions on the GITHUB_TOKEN"
    rationale = (
        "The GITHUB_TOKEN is minted per run and is available to every step, "
        "including third-party actions. Whatever the token can do, anything that "
        "achieves execution in the job can do too."
    )
    references = (
        "https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#permissions-for-the-github_token",
    )

    def apply(self, context: ScanContext) -> Iterable[Finding]:
        for workflow, job in context.iter_jobs():
            permissions = workflow.effective_permissions(job)
            origin, line = workflow.permissions_origin(job)

            if permissions is None:
                yield self._undeclared(context, workflow, job)
                continue

            writes = job_writes(permissions)
            if not writes:
                continue

            untrusted = untrusted_triggers(workflow)
            secrets = workflow.secrets_in_scope(job)
            anchor = line or job.location.line

            for scope in sorted(writes):
                impact = WRITE_PERMISSION_IMPACT.get(scope, "act on this scope")
                severity, confidence = self._grade(scope, bool(untrusted))

                evidence = [
                    EvidenceItem(
                        file=workflow.path,
                        line=anchor,
                        snippet=context.snippet_at(workflow.path, anchor)
                        or f"{scope}: write",
                        label=f"{scope}: write declared at {origin} level",
                    )
                ]
                for trigger in untrusted:
                    trigger_line = workflow.trigger_lines.get(trigger, 0)
                    if trigger_line:
                        evidence.append(
                            context.evidence_at(
                                workflow.path,
                                trigger_line,
                                f"reachable by outsiders via {trigger}",
                            )
                        )

                description = (
                    f"Job '{job.id}' runs with {scope}: write, declared at {origin} "
                    f"level. Any code executing in this job can {impact}."
                )
                if untrusted:
                    description += (
                        f" The workflow is triggered by {', '.join(untrusted)}, so the "
                        f"job's inputs are not fully under the repository's control."
                    )
                if secrets:
                    description += f" The job also references {', '.join(secrets)}."

                yield Finding(
                    rule_id=self.id,
                    type=FindingType.PRIVILEGE,
                    severity=severity,
                    confidence=confidence,
                    state=RelationshipState.OBSERVED,
                    title=f"Job '{job.id}' has {scope}: write",
                    description=description,
                    remediation=(
                        f"Remove {scope}: write if the job does not need it. Set a "
                        f"minimal top-level 'permissions:' block and grant write only "
                        f"in the specific job that requires it."
                    ),
                    references=list(self.references),
                    file=workflow.path,
                    line=anchor,
                    workflow=workflow.display_name,
                    job=job.id,
                    evidence=evidence,
                    metadata={
                        "scope": scope,
                        "level": "write",
                        "origin": origin,
                        "capability": impact,
                        "untrusted_triggers": untrusted,
                        "job_secrets": secrets,
                    },
                )

    @staticmethod
    def _grade(scope: str, outsider_triggerable: bool) -> tuple[Severity, float]:
        high_impact = scope in _HIGH_IMPACT_SCOPES
        if high_impact and outsider_triggerable:
            return Severity.HIGH, 0.85
        if high_impact:
            return Severity.MEDIUM, 0.9
        if outsider_triggerable:
            return Severity.MEDIUM, 0.8
        return Severity.LOW, 0.85

    def _undeclared(self, context: ScanContext, workflow, job) -> Finding:
        """No permissions block anywhere: the job inherits the repository default."""

        untrusted = untrusted_triggers(workflow)
        anchor = job.location.line
        return Finding(
            rule_id="PERMISSIONS_UNDECLARED",
            type=FindingType.PRIVILEGE,
            severity=Severity.MEDIUM if untrusted else Severity.LOW,
            confidence=0.75,
            state=RelationshipState.INFERRED,
            title=f"Job '{job.id}' declares no permissions",
            description=(
                f"Neither the workflow nor job '{job.id}' sets a 'permissions:' "
                f"block, so the GITHUB_TOKEN's scopes come from the repository or "
                f"organisation default. Where that default is still the legacy "
                f"read-write setting, this job holds write access to contents, "
                f"packages, and more. The workflow file alone cannot show which."
                + (
                    f" The workflow is reachable by outsiders via "
                    f"{', '.join(untrusted)}."
                    if untrusted
                    else ""
                )
            ),
            remediation=(
                "Add an explicit 'permissions:' block. Start from "
                "'permissions: {contents: read}' at workflow level and add scopes "
                "per job as needed."
            ),
            references=list(self.references),
            file=workflow.path,
            line=anchor,
            workflow=workflow.display_name,
            job=job.id,
            evidence=[
                EvidenceItem(
                    file=workflow.path,
                    line=anchor,
                    snippet=context.snippet_at(workflow.path, anchor),
                    label="job with no permissions block in scope",
                )
            ],
            metadata={
                "origin": "default",
                "untrusted_triggers": untrusted,
                "note": "effective scopes depend on repository settings not in this file",
            },
        )
