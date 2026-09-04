"""Rule protocol and the shared context every rule reads.

A rule is a small object with one job: look at the parsed workflows (and, where
relevant, the Git history SupplyTrace already collected) and yield
:class:`Finding` objects.  Rules never talk to each other and never mutate the
context, so the order they run in cannot change the result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Iterable, Iterator, Sequence

from supplytrace.cicd.evidence.models import EvidenceItem, Finding
from supplytrace.cicd.parser.workflow import (
    FORK_REACHABLE_PRIVILEGED_TRIGGERS,
    FORK_REACHABLE_TRIGGERS,
    ParsedJob,
    ParsedStep,
    ParsedWorkflow,
)
from supplytrace.models.repository import RepositoryAnalysis

if TYPE_CHECKING:  # pragma: no cover - import exists for type checkers only
    from supplytrace.cicd.rules.history import WorkflowHistory


@dataclass
class ScanContext:
    """Everything the rules are allowed to look at."""

    repo_path: str
    workflows: list[ParsedWorkflow] = field(default_factory=list)
    history: RepositoryAnalysis | None = None
    """Git history from SupplyTrace's existing analyzer. ``None`` when the
    target is not a Git repository, or history collection was skipped."""
    workflow_history: "WorkflowHistory | None" = None
    """What each workflow-touching commit changed. ``None`` when history was
    not collected. Typed loosely to keep this module free of a circular import
    back through the rules package."""

    def parsed_workflows(self) -> list[ParsedWorkflow]:
        return [w for w in self.workflows if w.is_parsed]

    def iter_jobs(self) -> Iterator[tuple[ParsedWorkflow, ParsedJob]]:
        for workflow in self.parsed_workflows():
            for job in workflow.jobs:
                yield workflow, job

    def iter_steps(self) -> Iterator[tuple[ParsedWorkflow, ParsedJob, ParsedStep]]:
        for workflow, job in self.iter_jobs():
            for step in job.steps:
                yield workflow, job, step

    def snippet_at(self, file: str, line: int) -> str:
        """The exact source line at ``file:line``, for evidence."""

        workflow = next((w for w in self.workflows if w.path == file), None)
        if workflow is None or not workflow.source or line < 1:
            return ""
        lines = workflow.source.splitlines()
        return lines[line - 1].strip() if line <= len(lines) else ""

    def evidence_at(self, file: str, line: int, label: str = "") -> EvidenceItem:
        return EvidenceItem(
            file=file, line=line, snippet=self.snippet_at(file, line), label=label
        )


class Rule:
    """Base class for a detection rule.

    Subclasses set the class attributes and implement :meth:`apply`.
    """

    #: Stable identifier used in findings, tests and the graph.
    id: str = ""
    #: One line describing what the rule looks for.
    name: str = ""
    #: Longer explanation shown by ``rules --explain``.
    rationale: str = ""
    references: Sequence[str] = ()

    def apply(self, context: ScanContext) -> Iterable[Finding]:  # pragma: no cover
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} {self.id}>"


# -- shared trigger reasoning ---------------------------------------------------
#
# Several rules need the same question answered -- "can an outsider cause this
# workflow to run, and does it hold the repository's own credentials when it
# does?" -- so the logic lives here once rather than in each rule.


def privileged_triggers(workflow: ParsedWorkflow) -> list[str]:
    """Triggers that run with the base repository's secrets on outsider input."""

    return sorted(set(workflow.triggers) & FORK_REACHABLE_PRIVILEGED_TRIGGERS)


def untrusted_triggers(workflow: ParsedWorkflow) -> list[str]:
    """Triggers that carry outsider-authored content, privileged or not."""

    return sorted(set(workflow.triggers) & FORK_REACHABLE_TRIGGERS)


def is_outsider_triggerable(workflow: ParsedWorkflow) -> bool:
    return bool(untrusted_triggers(workflow))


#: Refs that name outsider-authored code rather than the base branch.
_UNTRUSTED_REF_MARKERS = (
    "github.event.pull_request.head",
    "github.head_ref",
    "github.event.workflow_run.head",
    "github.event.pull_request.merge_commit_sha",
    "refs/pull/",
    "merge",
)

#: Ways a shell command fetches the pull request's code without using
#: actions/checkout at all. Matching only on the action would miss these, and
#: they are exactly what a workflow reaches for once it already has a token.
_SHELL_CHECKOUT_RE = re.compile(
    r"\bgh\s+pr\s+checkout\b"
    r"|\bgit\s+fetch\b[^\n]*\brefs/pull/"
    r"|\bgit\s+fetch\b[^\n]*\$\{\{\s*github\.event\.pull_request"
    r"|\bgit\s+checkout\b[^\n]*\$\{\{\s*github\.event\.pull_request"
    r"|\bgit\s+checkout\b[^\n]*\$\{\{\s*github\.head_ref",
    re.IGNORECASE,
)


def checks_out_untrusted_code(job: ParsedJob) -> list[ParsedStep]:
    """Steps that bring outsider-controlled code onto the runner.

    Under ``pull_request_target`` a bare ``actions/checkout`` gets the *base*
    branch, which is the safe case, so an unqualified checkout is not reported.
    What counts is a checkout that names the pull request's head -- whether
    through the action's ``ref:`` input or through a shell command such as
    ``gh pr checkout``.
    """

    dangerous: list[ParsedStep] = []
    for step in job.steps:
        ref = step.checkout_ref.lower()
        if ref and any(marker in ref for marker in _UNTRUSTED_REF_MARKERS):
            dangerous.append(step)
        elif step.run and _SHELL_CHECKOUT_RE.search(step.run):
            dangerous.append(step)
    return dangerous


def job_writes(permissions: dict[str, str] | None) -> dict[str, str]:
    """The write-level scopes in an effective permissions block."""

    if not permissions:
        return {}
    return {
        scope: level
        for scope, level in permissions.items()
        if level == "write" or (scope == "id-token" and level == "write")
    }


__all__ = [
    "Rule",
    "ScanContext",
    "checks_out_untrusted_code",
    "is_outsider_triggerable",
    "job_writes",
    "privileged_triggers",
    "untrusted_triggers",
]
