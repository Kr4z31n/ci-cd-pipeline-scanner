"""RULE 3 -- privileged triggers, graded by what the workflow then does.

``pull_request_target`` is not a vulnerability.  It exists so that a workflow
can label or comment on a pull request from a fork, and used that way it is
correct.  What makes it dangerous is the combination the spec calls out:

    privileged trigger + checkout of outsider code + running something

so this rule refuses to fire at full severity on the trigger alone.  It walks
each job and grades on what is actually there: does the job check out the PR
head, does it then run a command, does it hold secrets or write permissions.

A workflow that uses ``pull_request_target`` and only calls ``actions/labeler``
comes back as INFO. One that checks out the PR head and runs a build script
comes back as CRITICAL. Both are true statements about the same trigger.
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
from supplytrace.cicd.rules.base import (
    Rule,
    ScanContext,
    checks_out_untrusted_code,
    job_writes,
    privileged_triggers,
)

_TRIGGER_NOTES: dict[str, str] = {
    "pull_request_target": (
        "runs in the context of the base repository, with its secrets and a "
        "writable token, while the pull request itself comes from a fork"
    ),
    "workflow_run": (
        "runs after another workflow completes, with base-repository privileges, "
        "even when the run it followed was triggered by a fork"
    ),
    "issue_comment": "fires on a comment that any user with read access can post",
    "issues": "fires on issue content authored by any user",
    "discussion": "fires on discussion content authored by any user",
    "discussion_comment": "fires on discussion comments authored by any user",
    "pull_request_review": "fires on review content authored by outside contributors",
    "pull_request_review_comment": "fires on review comments authored by outside contributors",
}


class DangerousTriggerRule(Rule):
    id = "DANGEROUS_TRIGGER"
    name = "Privileged trigger combined with untrusted code or input"
    rationale = (
        "A privileged trigger gives a workflow the repository's own credentials "
        "while the event that started it came from outside. That is only a "
        "weakness if the job goes on to execute something an outsider controls, "
        "so the trigger is graded against the rest of the workflow."
    )
    references = (
        "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
        "https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request_target",
    )

    def apply(self, context: ScanContext) -> Iterable[Finding]:
        for workflow in context.parsed_workflows():
            triggers = privileged_triggers(workflow)
            if not triggers:
                continue

            for job in workflow.jobs:
                yield self._assess_job(context, workflow, job, triggers)

    def _assess_job(self, context: ScanContext, workflow, job, triggers: list[str]) -> Finding:
        trigger = triggers[0]
        trigger_line = workflow.trigger_lines.get(trigger, 0) or job.location.line

        untrusted_checkouts = checks_out_untrusted_code(job)
        run_steps = job.run_steps()
        writes = job_writes(workflow.effective_permissions(job))
        secrets = workflow.secrets_in_scope(job)

        evidence = [
            EvidenceItem(
                file=workflow.path,
                line=trigger_line,
                snippet=context.snippet_at(workflow.path, trigger_line),
                label=f"privileged trigger: {trigger}",
            )
        ]
        for step in untrusted_checkouts:
            evidence.append(
                context.evidence_at(
                    workflow.path, step.location.line, "checks out outsider-controlled code"
                )
            )
        for step in run_steps[:3]:
            evidence.append(
                context.evidence_at(
                    workflow.path, step.location.line, "shell command runs in this job"
                )
            )

        severity, confidence, verdict = self._grade(
            has_untrusted_checkout=bool(untrusted_checkouts),
            has_run=bool(run_steps),
            has_writes=bool(writes),
            has_secrets=bool(secrets),
        )

        note = _TRIGGER_NOTES.get(trigger, "runs with base-repository privileges")
        description = (
            f"Workflow is triggered by {trigger}, which {note}. In job '{job.id}': "
            f"{verdict}"
        )
        if writes:
            description += f" The job holds write permissions ({', '.join(sorted(writes))})."
        if secrets:
            description += f" It references {', '.join(secrets)}."

        return Finding(
            rule_id=self.id,
            type=FindingType.UNTRUSTED_INPUT,
            severity=severity,
            confidence=confidence,
            state=RelationshipState.INFERRED,
            title=f"{trigger} in job '{job.id}': {self._headline(severity)}",
            description=description,
            remediation=(
                "Split the workflow: run untrusted code in a pull_request job with "
                "no secrets and a read-only token, and do the privileged part in a "
                "separate workflow that never checks out the fork's code. If the "
                "code must be checked out here, pin it to "
                "github.event.pull_request.head.sha and treat everything in the "
                "checkout as hostile."
            ),
            references=list(self.references),
            file=workflow.path,
            line=trigger_line,
            workflow=workflow.display_name,
            job=job.id,
            evidence=evidence,
            metadata={
                "trigger": trigger,
                "all_privileged_triggers": triggers,
                "untrusted_checkout_steps": [s.label for s in untrusted_checkouts],
                "run_step_count": len(run_steps),
                "job_write_permissions": sorted(writes),
                "job_secrets": secrets,
            },
        )

    @staticmethod
    def _headline(severity: Severity) -> str:
        if severity in (Severity.CRITICAL, Severity.HIGH):
            return "outsider code reaches a privileged runner"
        if severity is Severity.MEDIUM:
            return "privileged job runs commands"
        return "privileged trigger, no untrusted execution found"

    @staticmethod
    def _grade(
        *,
        has_untrusted_checkout: bool,
        has_run: bool,
        has_writes: bool,
        has_secrets: bool,
    ) -> tuple[Severity, float, str]:
        """Grade the trigger against what the job actually does."""

        privileged = has_writes or has_secrets

        if has_untrusted_checkout and has_run:
            verdict = (
                "it checks out code from the pull request and then runs shell "
                "commands, so an outsider's code executes with this job's privileges."
            )
            return (
                (Severity.CRITICAL if privileged else Severity.HIGH),
                0.9,
                verdict,
            )
        if has_untrusted_checkout:
            return (
                Severity.HIGH,
                0.8,
                "it checks out code from the pull request. Nothing here runs it "
                "directly, but any later step, action, or build file in that "
                "checkout can.",
            )
        if has_run and privileged:
            return (
                Severity.MEDIUM,
                0.6,
                "it runs shell commands while holding the repository's credentials. "
                "No checkout of outsider code was found, so this is a weakness only "
                "if one of those commands consumes attacker-controlled input.",
            )
        if has_run:
            return (
                Severity.LOW,
                0.5,
                "it runs shell commands, but no outsider checkout and no secrets or "
                "write permissions were found in this job.",
            )
        return (
            Severity.INFO,
            0.9,
            "no shell commands and no checkout of outsider code were found, which "
            "is the intended way to use this trigger.",
        )
