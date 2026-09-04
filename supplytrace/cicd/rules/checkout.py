"""RULE 7 -- outsider-controlled code reaching a privileged runner.

This is the composite the other rules feed: a privileged trigger, a checkout of
code from the fork, and then something that runs. The individual parts are
reported by RULE 3 and RULE 4; this rule exists because the *combination* is
what turns them into remote code execution against the base repository, and a
reviewer reading three separate findings will not necessarily see it.

The rule only fires when the chain is complete, so it stays quiet on the many
workflows that have one or two of the parts for good reasons.
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
    checks_out_untrusted_code,
    job_writes,
    privileged_triggers,
)

#: Commands that execute whatever the checked-out tree contains. Running these
#: after checking out a fork's code runs the fork's code.
_BUILD_COMMANDS = (
    "npm install",
    "npm ci",
    "npm run",
    "yarn install",
    "yarn ",
    "pnpm install",
    "pnpm ",
    "make",
    "mvn ",
    "gradle",
    "./gradlew",
    "pip install",
    "python setup.py",
    "pytest",
    "tox",
    "cargo build",
    "cargo test",
    "go test",
    "go build",
    "bundle install",
    "composer install",
    "docker build",
    "terraform",
    "./",
    "bash ",
    "sh ",
)


class UntrustedCodeExecutionRule(Rule):
    id = "UNTRUSTED_CODE_EXECUTION"
    name = "Fork-controlled code executes with base-repository privileges"
    rationale = (
        "Checking out a pull request's head under a privileged trigger puts "
        "attacker-authored files on the runner. Any command that reads those "
        "files -- a build, a test run, an install script -- executes them, with "
        "whatever credentials the job holds."
    )
    references = (
        "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
    )

    def apply(self, context: ScanContext) -> Iterable[Finding]:
        for workflow in context.parsed_workflows():
            triggers = privileged_triggers(workflow)
            if not triggers:
                continue

            for job in workflow.jobs:
                checkouts = checks_out_untrusted_code(job)
                if not checkouts:
                    continue

                checkout = checkouts[0]
                executors = self._executing_steps(job, after_index=checkout.index)
                if not executors:
                    continue

                writes = job_writes(workflow.effective_permissions(job))
                secrets = workflow.secrets_in_scope(job)
                executor, matched = executors[0]
                trigger_line = workflow.trigger_lines.get(triggers[0], 0)

                severity = (
                    Severity.CRITICAL if (writes or secrets) else Severity.HIGH
                )

                evidence = [
                    EvidenceItem(
                        file=workflow.path,
                        line=trigger_line or workflow.jobs[0].location.line,
                        snippet=context.snippet_at(workflow.path, trigger_line),
                        label=f"privileged trigger: {triggers[0]}",
                    ),
                    EvidenceItem(
                        file=workflow.path,
                        line=checkout.location.line,
                        snippet=context.snippet_at(workflow.path, checkout.location.line),
                        label=f"checkout of {checkout.checkout_ref}",
                    ),
                    EvidenceItem(
                        file=workflow.path,
                        line=executor.location.line,
                        snippet=context.snippet_at(workflow.path, executor.location.line),
                        label=f"executes checked-out code: {matched}",
                    ),
                ]
                _, permissions_line = workflow.permissions_origin(job)
                if writes and permissions_line:
                    evidence.append(
                        context.evidence_at(
                            workflow.path,
                            permissions_line,
                            f"privileges available to that code: {', '.join(sorted(writes))}",
                        )
                    )

                capability = []
                if writes:
                    capability.append(f"a token with {', '.join(sorted(writes))}")
                if secrets:
                    capability.append(f"the secrets {', '.join(secrets)}")

                yield Finding(
                    rule_id=self.id,
                    type=FindingType.CODE_EXECUTION,
                    severity=severity,
                    confidence=0.85,
                    state=RelationshipState.INFERRED,
                    title=f"Fork code executes with privileges in job '{job.id}'",
                    description=(
                        f"Job '{job.id}' is reachable via {triggers[0]}, checks out "
                        f"{checkout.checkout_ref} (code authored by whoever opened "
                        f"the pull request), and then runs '{matched}' in step "
                        f"'{executor.label}'. That command executes files from the "
                        f"checkout, so the pull request author chooses what runs"
                        + (
                            f", with access to {' and '.join(capability)}."
                            if capability
                            else "."
                        )
                    ),
                    remediation=(
                        "Do not check out fork code in a workflow that holds "
                        "credentials. Build and test the pull request in a "
                        "'pull_request' workflow, and if a privileged follow-up is "
                        "needed, pass only data -- never code -- between them."
                    ),
                    references=list(self.references),
                    file=workflow.path,
                    line=checkout.location.line,
                    workflow=workflow.display_name,
                    job=job.id,
                    step=executor.label,
                    evidence=evidence,
                    metadata={
                        "trigger": triggers[0],
                        "checkout_ref": checkout.checkout_ref,
                        "checkout_step": checkout.label,
                        "executing_step": executor.label,
                        "matched_command": matched,
                        "job_write_permissions": sorted(writes),
                        "job_secrets": secrets,
                    },
                )

    @staticmethod
    def _executing_steps(job, *, after_index: int) -> list[tuple[object, str]]:
        """Steps after the checkout that run code from the working tree."""

        found: list[tuple[object, str]] = []
        for step in job.steps:
            if step.index <= after_index:
                continue

            if step.run:
                lowered = step.run.lower()
                for command in _BUILD_COMMANDS:
                    if command in lowered:
                        found.append((step, command.strip()))
                        break
                else:
                    if any(
                        hit.behaviour
                        in (ShellBehaviour.EXECUTE_LOCAL, ShellBehaviour.EVAL)
                        for hit in analyse_run_block(step.run)
                    ):
                        found.append((step, "executes a file from the workspace"))
            elif step.uses and step.uses.is_local:
                # A local action lives in the checked-out tree, so under an
                # untrusted checkout its own code is attacker-controlled.
                found.append((step, f"local action {step.uses.raw}"))
        return found
