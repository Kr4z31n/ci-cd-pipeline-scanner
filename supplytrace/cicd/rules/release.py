"""RULE 9 -- publishing steps that sit downstream of a weakness.

A job that pushes a package to a registry is the point where this repository's
problems become its users' problems. The publish step itself is not the flaw;
what matters is what else is in the job with it.

So the rule finds the publishing steps first, then asks what could reach them:
unpinned actions in the same job, code fetched from the network, an
outsider-reachable trigger, or a broad token. The severity is set by that list,
and the finding names the specific ingredients rather than asserting generic
"release risk".
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
from supplytrace.cicd.rules.base import (
    Rule,
    ScanContext,
    job_writes,
    untrusted_triggers,
)

#: Actions whose whole purpose is to publish something.
_PUBLISHING_ACTION_MARKERS = (
    "publish",
    "release",
    "deploy",
    "docker",
    "npm",
    "pypi",
    "upload-pages",
    "gh-pages",
    "cargo",
    "maven",
    "nuget",
    "helm",
)

#: Registry-credential names, so the finding can say what would be stolen.
_PUBLISH_CREDENTIAL_HINTS = (
    "NPM",
    "PYPI",
    "TWINE",
    "DOCKER",
    "REGISTRY",
    "CARGO",
    "MAVEN",
    "NUGET",
    "GPG",
    "SIGNING",
    "COSIGN",
    "AWS",
    "AZURE",
    "GCP",
)


class ReleaseRiskRule(Rule):
    id = "RELEASE_RISK"
    name = "A publishing job is exposed to an upstream weakness"
    rationale = (
        "Anything that achieves execution in a job that publishes can publish. "
        "The blast radius of a weakness in this job is every downstream consumer "
        "of the artifact, not just this repository."
    )
    references = (
        "https://slsa.dev/spec/v1.0/threats",
        "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions",
    )

    def apply(self, context: ScanContext) -> Iterable[Finding]:
        for workflow, job in context.iter_jobs():
            publishers = self._publishing_steps(job)
            if not publishers:
                continue

            exposures, evidence = self._exposures(context, workflow, job)
            if not exposures:
                continue

            step, how = publishers[0]
            credentials = [
                name
                for name in workflow.secrets_in_scope(job)
                if any(hint in name.upper() for hint in _PUBLISH_CREDENTIAL_HINTS)
            ]
            severity, confidence = self._grade(exposures)

            evidence.insert(
                0,
                EvidenceItem(
                    file=workflow.path,
                    line=step.location.line,
                    snippet=context.snippet_at(workflow.path, step.location.line),
                    label=f"publishing step: {how}",
                ),
            )

            yield Finding(
                rule_id=self.id,
                type=FindingType.RELEASE_INTEGRITY,
                severity=severity,
                confidence=confidence,
                state=RelationshipState.INFERRED,
                title=f"Publishing job '{job.id}' has {len(exposures)} upstream weakness(es)",
                description=(
                    f"Job '{job.id}' publishes ({how}) and in the same job: "
                    + "; ".join(exposures)
                    + ". Code that executes anywhere in this job can alter what is "
                    "published, and the result is signed and distributed as "
                    "genuine"
                    + (
                        f". Registry credentials in scope: {', '.join(credentials)}."
                        if credentials
                        else "."
                    )
                ),
                remediation=(
                    "Isolate publishing into its own job that does nothing else: no "
                    "unpinned actions, no network fetches, no untrusted input. Have "
                    "it consume only a verified artifact, and gate it on a protected "
                    "environment so a compromised run cannot publish unattended."
                ),
                references=list(self.references),
                file=workflow.path,
                line=step.location.line,
                workflow=workflow.display_name,
                job=job.id,
                step=step.label,
                evidence=evidence,
                metadata={
                    "publish_method": how,
                    "publish_step": step.label,
                    "exposures": exposures,
                    "publish_credentials": credentials,
                    "job_write_permissions": sorted(
                        job_writes(workflow.effective_permissions(job))
                    ),
                },
            )

    # -- detection helpers -----------------------------------------------------

    @staticmethod
    def _publishing_steps(job) -> list[tuple[object, str]]:
        found: list[tuple[object, str]] = []
        for step in job.steps:
            if step.run:
                hits = analyse_run_block(step.run)
                if any(h.behaviour is ShellBehaviour.PACKAGE_PUBLISH for h in hits):
                    hit = next(h for h in hits if h.behaviour is ShellBehaviour.PACKAGE_PUBLISH)
                    found.append((step, hit.snippet(80)))
                elif any(h.behaviour is ShellBehaviour.GIT_PUSH for h in hits):
                    found.append((step, "git push"))
            elif step.uses and not step.uses.is_local:
                repo = step.uses.repo.lower()
                if any(marker in repo for marker in _PUBLISHING_ACTION_MARKERS):
                    found.append((step, step.uses.raw))
        return found

    def _exposures(
        self, context: ScanContext, workflow, job
    ) -> tuple[list[str], list[EvidenceItem]]:
        """What in this job could alter what gets published."""

        exposures: list[str] = []
        evidence: list[EvidenceItem] = []

        unpinned = [
            step
            for step in job.action_steps()
            if step.uses
            and not step.uses.is_pinned
            and not step.uses.is_local
            and not step.uses.is_first_party
            and step.uses.ref
        ]
        if unpinned:
            names = ", ".join(sorted({s.uses.repo for s in unpinned}))
            exposures.append(f"it runs unpinned third-party actions ({names})")
            for step in unpinned[:2]:
                evidence.append(
                    context.evidence_at(
                        workflow.path, step.location.line, "unpinned action in the publishing job"
                    )
                )

        for step in job.run_steps():
            behaviours = {hit.behaviour for hit in analyse_run_block(step.run)}
            if behaviours & {ShellBehaviour.PIPE_TO_SHELL, ShellBehaviour.DOWNLOAD}:
                exposures.append("it fetches code or files from the network before publishing")
                evidence.append(
                    context.evidence_at(
                        workflow.path, step.location.line, "network fetch in the publishing job"
                    )
                )
                break

        triggers = untrusted_triggers(workflow)
        if triggers:
            exposures.append(
                f"the workflow is reachable by outsiders via {', '.join(triggers)}"
            )
            line = workflow.trigger_lines.get(triggers[0], 0)
            if line:
                evidence.append(
                    context.evidence_at(workflow.path, line, "outsider-reachable trigger")
                )

        writes = job_writes(workflow.effective_permissions(job))
        broad = {s for s in writes if s in {"contents", "packages", "id-token"}}
        if broad:
            exposures.append(f"the token can write {', '.join(sorted(broad))}")
            _, line = workflow.permissions_origin(job)
            if line:
                evidence.append(
                    context.evidence_at(workflow.path, line, "write permissions in scope")
                )

        return exposures, evidence

    @staticmethod
    def _grade(exposures: list[str]) -> tuple[Severity, float]:
        if len(exposures) >= 3:
            return Severity.HIGH, 0.75
        if len(exposures) == 2:
            return Severity.MEDIUM, 0.7
        return Severity.LOW, 0.6
