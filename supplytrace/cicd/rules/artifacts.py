"""RULE 8 -- artifacts that can be altered between build and use.

A build artifact is a promise: this file is what the source produced. The
promise breaks wherever something can write to the artifact after the build made
it and before whatever consumes it reads it.

Two shapes are reported:

* an artifact is uploaded by one job and downloaded by another that then
  publishes or executes it, with steps in between that could modify it; and
* a job downloads an artifact produced by a *different* workflow run
  (``workflow_run``), which is the classic path for a fork's build output to
  reach a privileged job.
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
from supplytrace.cicd.parser.shell import ShellBehaviour, analyse_run_block
from supplytrace.cicd.rules.base import Rule, ScanContext, job_writes

_UPLOAD_ACTIONS = {"actions/upload-artifact", "actions/upload-pages-artifact"}
_DOWNLOAD_ACTIONS = {"actions/download-artifact", "dawidd6/action-download-artifact"}


class ArtifactTamperingRule(Rule):
    id = "ARTIFACT_TAMPERING"
    name = "An artifact can be modified between creation and use"
    rationale = (
        "Artifacts carry no integrity guarantee of their own. Whatever runs "
        "between the upload and the consuming step can replace the contents, and "
        "the consumer has no way to tell."
    )
    references = (
        "https://docs.github.com/en/actions/using-workflows/storing-workflow-data-as-artifacts",
        "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
    )

    def apply(self, context: ScanContext) -> Iterable[Finding]:
        for workflow in context.parsed_workflows():
            uploads = self._steps_using(workflow, _UPLOAD_ACTIONS)
            downloads = self._steps_using(workflow, _DOWNLOAD_ACTIONS)

            for job, step in downloads:
                yield from self._assess_download(context, workflow, job, step, uploads)

    def _assess_download(
        self, context: ScanContext, workflow, job, step, uploads
    ) -> Iterable[Finding]:
        consumers = self._consuming_steps(job, after_index=step.index)
        if not consumers:
            return

        writes = job_writes(workflow.effective_permissions(job))
        cross_run = "workflow_run" in workflow.triggers
        consumer, what = consumers[0]

        # A download in a workflow_run job takes whatever the triggering run
        # produced -- and that run may have been a fork's pull request.
        severity = Severity.HIGH if cross_run else Severity.MEDIUM
        if cross_run and writes:
            severity = Severity.CRITICAL

        evidence = [
            EvidenceItem(
                file=workflow.path,
                line=step.location.line,
                snippet=context.snippet_at(workflow.path, step.location.line),
                label="artifact downloaded",
            ),
            EvidenceItem(
                file=workflow.path,
                line=consumer.location.line,
                snippet=context.snippet_at(workflow.path, consumer.location.line),
                label=f"artifact contents used: {what}",
            ),
        ]
        for upload_job, upload_step in uploads[:2]:
            evidence.append(
                EvidenceItem(
                    file=workflow.path,
                    line=upload_step.location.line,
                    snippet=context.snippet_at(workflow.path, upload_step.location.line),
                    label=f"artifact produced in job '{upload_job.id}'",
                )
            )

        origin = (
            "a previous workflow run, which for a workflow_run trigger may have "
            "been a pull request from a fork"
            if cross_run
            else f"job '{uploads[0][0].id}'"
            if uploads
            else "an earlier job"
        )

        yield Finding(
            rule_id=self.id,
            type=FindingType.ARTIFACT_INTEGRITY,
            severity=severity,
            confidence=0.7 if cross_run else 0.55,
            state=RelationshipState.INFERRED,
            title=f"Job '{job.id}' consumes a downloaded artifact",
            description=(
                f"Job '{job.id}' downloads an artifact from {origin} and then "
                f"{what} in step '{consumer.label}'. Nothing between the two "
                f"verifies the artifact's contents, so whoever could write to it "
                f"chooses what this job uses"
                + (
                    f". The job holds {', '.join(sorted(writes))}, so that content "
                    f"runs with those privileges."
                    if writes
                    else "."
                )
            ),
            remediation=(
                "Record a digest of the artifact when it is created and verify it "
                "after download, or sign the artifact and check the signature. For "
                "workflow_run, never treat an artifact from the triggering run as "
                "trusted input."
            ),
            references=list(self.references),
            file=workflow.path,
            line=step.location.line,
            workflow=workflow.display_name,
            job=job.id,
            step=consumer.label,
            evidence=evidence,
            metadata={
                "download_step": step.label,
                "consuming_step": consumer.label,
                "consumption": what,
                "cross_run": cross_run,
                "job_write_permissions": sorted(writes),
                "upload_jobs": [j.id for j, _ in uploads],
            },
        )

    @staticmethod
    def _steps_using(workflow, action_repos: set[str]) -> list[tuple[object, object]]:
        return [
            (job, step)
            for job, step in workflow.all_steps()
            if step.uses and step.uses.repo.lower() in action_repos
        ]

    @staticmethod
    def _consuming_steps(job, *, after_index: int) -> list[tuple[object, str]]:
        """Steps after the download that execute or publish the artifact."""

        found: list[tuple[object, str]] = []
        for step in job.steps:
            if step.index <= after_index:
                continue
            if step.run:
                behaviours = {hit.behaviour for hit in analyse_run_block(step.run)}
                if ShellBehaviour.PACKAGE_PUBLISH in behaviours:
                    found.append((step, "publishes it"))
                elif behaviours & {
                    ShellBehaviour.EXECUTE_LOCAL,
                    ShellBehaviour.MAKE_EXECUTABLE,
                    ShellBehaviour.EVAL,
                }:
                    found.append((step, "executes it"))
            elif step.uses and not step.uses.is_local:
                repo = step.uses.repo.lower()
                if any(
                    marker in repo
                    for marker in ("release", "publish", "deploy", "upload", "docker")
                ):
                    found.append((step, f"passes it to {step.uses.repo}"))
        return found
