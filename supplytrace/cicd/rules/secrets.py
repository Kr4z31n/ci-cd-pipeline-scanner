"""RULE 5 -- where secrets go once a workflow reads them.

The spec draws the line this rule is built around: a secret being *used* is not
a secret being *stolen*. Every deploy workflow references a credential, and a
tool that calls each one a compromise is noise a reader learns to skip.

So the rule reports two different things, and never conflates them:

``SECRET_ACCESS``
    A secret is in scope. Informational, and the baseline for the graph.

``SECRET_EXPOSURE`` / ``SECRET_EXFILTRATION``
    The secret's *value* reaches a sink that can leak it. This is established
    by following the value through the script
    (:mod:`supplytrace.cicd.parser.taint`), so ``echo "build finished"`` in a
    step that happens to hold a token does not qualify -- only a line that
    actually references the value does.

Even then the claim stays "this value can escape", never "this value was
stolen". Nothing in a workflow file can establish the latter.
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
from supplytrace.cicd.parser.shell import ShellBehaviour, external_urls
from supplytrace.cicd.parser.taint import SecretFlow, seed_taint, track_secret_flows
from supplytrace.cicd.rules.base import Rule, ScanContext, untrusted_triggers

#: What reaching each sink means for the secret.
_SINK_MEANING: dict[ShellBehaviour, str] = {
    ShellBehaviour.PRINT_VALUE: (
        "printed to the build log, which is readable by anyone who can read the run"
    ),
    ShellBehaviour.OUTBOUND_NETWORK: "passed to a command that sends data to a remote host",
    ShellBehaviour.WRITE_FILE: (
        "written to a file, which a later step or an uploaded artifact can carry off"
    ),
    ShellBehaviour.ENV_EXPORT: (
        "written into GITHUB_ENV or GITHUB_OUTPUT, exposing it to every later step"
    ),
    ShellBehaviour.PIPE_TO_SHELL: (
        "in scope for a command that executes code fetched from the network"
    ),
}


class SecretExposureRule(Rule):
    id = "SECRET_EXPOSURE"
    name = "A secret's value reaches a sink that can leak it"
    rationale = (
        "GitHub masks known secret values in log output, but masking is a string "
        "match on the exact value. A secret that has been decoded, split, "
        "re-encoded or parsed out of a JSON blob no longer matches the mask and "
        "prints in the clear."
    )
    references = (
        "https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions#accessing-your-secrets",
    )

    def apply(self, context: ScanContext) -> Iterable[Finding]:
        for workflow, job, step in context.iter_steps():
            in_scope = workflow.secrets_in_scope(job)
            if not in_scope:
                continue

            reported = False
            if step.run:
                seeded = seed_taint((workflow.env, job.env, step.env))
                taint = track_secret_flows(step.run, seeded)
                for flow in self._first_per_sink(taint.flows):
                    reported = True
                    yield self._flow_finding(context, workflow, job, step, flow)

            if step.uses:
                third_party = self._third_party_finding(context, workflow, job, step, in_scope)
                if third_party is not None:
                    reported = True
                    yield third_party

            # Record plain access only where the step names the secret itself.
            # Repeating it for every step that merely inherits a workflow-level
            # env var would bury the report in noise.
            if not reported and step.secrets_used():
                yield self._access_finding(context, workflow, job, step, step.secrets_used())

    @staticmethod
    def _first_per_sink(flows: list[SecretFlow]) -> list[SecretFlow]:
        """One finding per (secret, sink) pair, not one per matching line."""

        seen: set[tuple[str, ShellBehaviour]] = set()
        chosen: list[SecretFlow] = []
        for flow in flows:
            key = (flow.secret, flow.behaviour)
            if key in seen:
                continue
            seen.add(key)
            chosen.append(flow)
        return chosen

    # -- a value reaching a sink -----------------------------------------------

    def _flow_finding(
        self, context: ScanContext, workflow, job, step, flow: SecretFlow
    ) -> Finding:
        line = step.line_for_run_offset(flow.line_offset)
        triggers = untrusted_triggers(workflow)
        external = external_urls(step.run)
        exfiltration = flow.behaviour is ShellBehaviour.OUTBOUND_NETWORK
        severity, confidence = self._grade(flow, bool(external), bool(triggers))

        carrier = (
            f"${flow.via}, which was derived from {flow.secret}"
            if flow.derived
            else f"{flow.secret}"
        )
        masking_note = (
            " Because the value was transformed before this point, GitHub's log "
            "masking no longer matches it."
            if flow.derived and flow.behaviour is ShellBehaviour.PRINT_VALUE
            else ""
        )

        return Finding(
            rule_id=self.id,
            type=FindingType.SECRET_EXFILTRATION if exfiltration else FindingType.SECRET_ACCESS,
            severity=severity,
            confidence=confidence,
            state=RelationshipState.INFERRED,
            title=f"{flow.secret} is {self._sink_label(flow.behaviour)} in job '{job.id}'",
            description=(
                f"Step '{step.label}' in job '{job.id}' references {carrier} on a "
                f"line whose value is {_SINK_MEANING[flow.behaviour]}.{masking_note} "
                f"This is an opportunity for the secret to escape, not evidence "
                f"that it did"
                + (
                    f". The step also contacts "
                    f"{', '.join(sorted(set(external))[:3])}, which is not a "
                    f"common CI host."
                    if external
                    else "."
                )
            ),
            remediation=(
                "Keep secrets in env: and never echo, cat or redirect them. If a "
                "secret must be transformed, emit '::add-mask::' for the derived "
                "value so the log masks that too."
            ),
            references=list(self.references),
            file=workflow.path,
            line=line,
            workflow=workflow.display_name,
            job=job.id,
            step=step.label,
            evidence=[
                EvidenceItem(
                    file=workflow.path,
                    line=line,
                    snippet=context.snippet_at(workflow.path, line) or flow.snippet(),
                    label=f"{flow.secret} reaches {flow.behaviour.value}",
                ),
                EvidenceItem(
                    file=workflow.path,
                    line=step.location.line,
                    snippet=context.snippet_at(workflow.path, step.location.line),
                    label="step holding the secret",
                ),
            ],
            metadata={
                "secret": flow.secret,
                "carrier": flow.via,
                "derived": flow.derived,
                "sink": flow.behaviour.value,
                "external_hosts": sorted(set(external)),
                "triggers": triggers,
            },
        )

    @staticmethod
    def _sink_label(behaviour: ShellBehaviour) -> str:
        return {
            ShellBehaviour.PRINT_VALUE: "written to the build log",
            ShellBehaviour.OUTBOUND_NETWORK: "sent to a remote host",
            ShellBehaviour.WRITE_FILE: "written to a file",
            ShellBehaviour.ENV_EXPORT: "exported to later steps",
            ShellBehaviour.PIPE_TO_SHELL: "in scope for downloaded code",
        }.get(behaviour, "used at a sink")

    @staticmethod
    def _grade(
        flow: SecretFlow, has_external_host: bool, outsider_triggerable: bool
    ) -> tuple[Severity, float]:
        if flow.behaviour is ShellBehaviour.OUTBOUND_NETWORK:
            return (
                (Severity.CRITICAL, 0.85) if has_external_host else (Severity.HIGH, 0.7)
            )
        if flow.behaviour is ShellBehaviour.PIPE_TO_SHELL:
            return Severity.CRITICAL, 0.75
        if flow.behaviour is ShellBehaviour.PRINT_VALUE:
            # A derived value defeats log masking, so it genuinely prints.
            if flow.derived:
                return (Severity.HIGH if outsider_triggerable else Severity.MEDIUM), 0.8
            return Severity.MEDIUM, 0.6
        if flow.behaviour is ShellBehaviour.ENV_EXPORT:
            return Severity.MEDIUM, 0.7
        return Severity.MEDIUM, 0.65

    # -- a secret handed to someone else's code --------------------------------

    def _third_party_finding(
        self, context: ScanContext, workflow, job, step, in_scope: list[str]
    ) -> Finding | None:
        action = step.uses
        if action is None or action.is_local or action.is_first_party:
            return None

        passed = [
            name
            for name in in_scope
            if any(
                f"secrets.{name}" in str(value)
                or (name == "GITHUB_TOKEN" and "github.token" in str(value).lower())
                for value in list(step.with_.values()) + list(step.env.values())
            )
        ]
        if not passed:
            return None

        pinned = action.is_pinned
        return Finding(
            rule_id=self.id,
            type=FindingType.SECRET_ACCESS,
            severity=Severity.MEDIUM if pinned else Severity.HIGH,
            confidence=0.8,
            state=RelationshipState.INFERRED,
            title=f"{', '.join(passed)} passed to third-party {action.repo}",
            description=(
                f"Step '{step.label}' passes {', '.join(passed)} to {action.raw}. "
                f"Once the value is inside a third-party action, what happens to "
                f"it is decided by that action's code"
                + (
                    "."
                    if pinned
                    else ", and this reference is a mutable tag, so that code can "
                    "change without any change to this repository."
                )
            ),
            remediation=(
                f"Pin {action.repo} to a full commit SHA and review what it does "
                f"with the credential. Prefer a short-lived, narrowly scoped token "
                f"over a long-lived secret."
            ),
            references=list(self.references),
            file=workflow.path,
            line=step.location.line,
            workflow=workflow.display_name,
            job=job.id,
            step=step.label,
            evidence=[
                EvidenceItem(
                    file=workflow.path,
                    line=step.location.line,
                    snippet=context.snippet_at(workflow.path, step.location.line),
                    label=f"third-party action receiving {', '.join(passed)}",
                )
            ],
            metadata={
                "secrets": passed,
                "sink": "third_party_action",
                "action": action.raw,
                "action_repo": action.repo,
                "action_pinned": pinned,
            },
        )

    # -- plain access ----------------------------------------------------------

    def _access_finding(
        self, context: ScanContext, workflow, job, step, names: list[str]
    ) -> Finding:
        return Finding(
            rule_id="SECRET_ACCESS",
            type=FindingType.SECRET_ACCESS,
            severity=Severity.INFO,
            confidence=1.0,
            state=RelationshipState.OBSERVED,
            title=f"Step '{step.label}' reads {', '.join(names)}",
            description=(
                f"Job '{job.id}' step '{step.label}' references {', '.join(names)}. "
                f"No sink that could leak the value was found in this step. "
                f"Recorded so the attack graph knows which steps hold credentials."
            ),
            file=workflow.path,
            line=step.location.line,
            workflow=workflow.display_name,
            job=job.id,
            step=step.label,
            evidence=[
                EvidenceItem(
                    file=workflow.path,
                    line=step.location.line,
                    snippet=context.snippet_at(workflow.path, step.location.line),
                    label="secret reference",
                )
            ],
            metadata={"secrets": names, "sink": None},
        )
