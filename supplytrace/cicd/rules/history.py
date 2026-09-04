"""Git history as evidence, built on SupplyTrace's existing analyzer.

This module deliberately collects no Git data of its own. ``GitAnalyzer`` and
``rank_commits`` already read the history, classify every changed file, and
score commits by supply-chain signal; re-deriving any of that here would leave
two implementations free to disagree about the same repository.

What is added is the join the workflow scanner needs: *which commit last touched
the workflow a finding sits in*, and *what it changed about it*. A commit that
introduced a third-party action is a different event from one that widened the
token's permissions, and that difference is what makes the temporal correlation
in :mod:`supplytrace.cicd.graph.correlation` worth building.

Each workflow-touching commit's diff is re-read through the same hardened Git
layer the rest of the tool uses -- a repository's own config can make Git
execute programs, and that layer is what refuses it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from supplytrace.analyzers.signal_analyzer import rank_commits
from supplytrace.cicd.evidence.models import (
    EvidenceItem,
    Finding,
    FindingType,
    RelationshipState,
    Severity,
)
from supplytrace.cicd.rules.base import Rule, ScanContext
from supplytrace.core.config import AnalysisConfig
from supplytrace.core.errors import SupplyTraceError
from supplytrace.core.git_command import GitRunner
from supplytrace.models.commit import CommitRecord
from supplytrace.models.file import ChangeStatus, FileCategory
from supplytrace.models.repository import RepositoryAnalysis


class WorkflowChangeKind(str, Enum):
    """What a commit did to a workflow file.

    These are the change types the specification asks the history analysis to
    notice, because each one moves the pipeline's security posture.
    """

    ACTION_ADDED = "ACTION_ADDED"
    ACTION_VERSION_CHANGED = "ACTION_VERSION_CHANGED"
    PERMISSION_WIDENED = "PERMISSION_WIDENED"
    SECRET_ADDED = "SECRET_ADDED"
    TRIGGER_CHANGED = "TRIGGER_CHANGED"
    NETWORK_COMMAND_ADDED = "NETWORK_COMMAND_ADDED"
    ARTIFACT_OPERATION_ADDED = "ARTIFACT_OPERATION_ADDED"
    RELEASE_OPERATION_ADDED = "RELEASE_OPERATION_ADDED"
    WORKFLOW_ADDED = "WORKFLOW_ADDED"


CHANGE_DESCRIPTIONS: dict[WorkflowChangeKind, str] = {
    WorkflowChangeKind.ACTION_ADDED: "introduced a third-party action",
    WorkflowChangeKind.ACTION_VERSION_CHANGED: "changed which version of an action runs",
    WorkflowChangeKind.PERMISSION_WIDENED: "granted the token a write permission",
    WorkflowChangeKind.SECRET_ADDED: "brought a secret into the workflow",
    WorkflowChangeKind.TRIGGER_CHANGED: "changed when the workflow runs",
    WorkflowChangeKind.NETWORK_COMMAND_ADDED: "added a command that contacts the network",
    WorkflowChangeKind.ARTIFACT_OPERATION_ADDED: "added an artifact upload or download",
    WorkflowChangeKind.RELEASE_OPERATION_ADDED: "added a publishing or release operation",
    WorkflowChangeKind.WORKFLOW_ADDED: "added this workflow",
}

_ADDED_LINE = re.compile(r"^\+(?!\+\+)(?P<body>.*)$")
_REMOVED_LINE = re.compile(r"^-(?!--)(?P<body>.*)$")
_USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<ref>\S+)", re.IGNORECASE)
_WRITE_PERMISSION_RE = re.compile(r"^\s*(?P<scope>[\w-]+):\s*write\s*$", re.IGNORECASE)
_SECRET_RE = re.compile(r"secrets\.[A-Za-z_][\w-]*|github\.token", re.IGNORECASE)
_TRIGGER_RE = re.compile(
    r"^\s*(?P<trigger>pull_request_target|workflow_run|pull_request|issue_comment|"
    r"schedule|workflow_dispatch|push|issues|release)\s*:",
    re.IGNORECASE,
)
_NETWORK_RE = re.compile(r"\b(curl|wget|nc|ncat|socat|dig|nslookup|Invoke-WebRequest)\b")
_ARTIFACT_RE = re.compile(r"actions/(?:upload|download)-artifact", re.IGNORECASE)
_RELEASE_RE = re.compile(
    r"\b(npm publish|twine upload|cargo publish|docker push|gh release|"
    r"gem push|mvn deploy|helm push)\b",
    re.IGNORECASE,
)


@dataclass
class WorkflowChange:
    """One observed change a commit made to one workflow file."""

    commit_sha: str
    short_sha: str
    author_name: str
    author_email: str
    timestamp: str
    subject: str
    path: str
    kind: WorkflowChangeKind
    detail: str
    added_line: str = ""

    def describe(self) -> str:
        return f"{self.short_sha} {CHANGE_DESCRIPTIONS[self.kind]}: {self.detail}"


@dataclass
class WorkflowHistory:
    """Every workflow-affecting change found in the analysed history."""

    changes: list[WorkflowChange] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)
    """Commits whose diff could not be read, recorded rather than ignored."""

    def for_path(self, path: str) -> list[WorkflowChange]:
        return [change for change in self.changes if change.path == path]

    def of_kind(self, kind: WorkflowChangeKind) -> list[WorkflowChange]:
        return [change for change in self.changes if change.kind is kind]

    def ordered(self) -> list[WorkflowChange]:
        """Changes oldest first, the order in which an attack would build."""

        return sorted(self.changes, key=lambda c: c.timestamp)


def _classify_added_line(line: str, removed: list[str]) -> list[tuple[WorkflowChangeKind, str]]:
    """What security-relevant thing does this added line introduce?"""

    found: list[tuple[WorkflowChangeKind, str]] = []
    body = line.strip()
    if not body or body.startswith("#"):
        return found

    uses = _USES_RE.match(line)
    if uses:
        ref = uses.group("ref").strip("\"'")
        action = ref.split("@")[0]
        # The same action on a removed line means its version moved, rather
        # than a new dependency being introduced. Those are different events.
        moved = any(action in candidate for candidate in removed if _USES_RE.match(candidate))
        found.append(
            (
                WorkflowChangeKind.ACTION_VERSION_CHANGED
                if moved
                else WorkflowChangeKind.ACTION_ADDED,
                ref,
            )
        )

    permission = _WRITE_PERMISSION_RE.match(line)
    if permission:
        found.append(
            (WorkflowChangeKind.PERMISSION_WIDENED, f"{permission.group('scope')}: write")
        )

    secret = _SECRET_RE.search(body)
    if secret:
        found.append((WorkflowChangeKind.SECRET_ADDED, secret.group(0)))

    trigger = _TRIGGER_RE.match(line)
    if trigger:
        found.append((WorkflowChangeKind.TRIGGER_CHANGED, trigger.group("trigger")))

    if _NETWORK_RE.search(body):
        found.append((WorkflowChangeKind.NETWORK_COMMAND_ADDED, body[:100]))
    if _ARTIFACT_RE.search(body):
        found.append((WorkflowChangeKind.ARTIFACT_OPERATION_ADDED, body[:100]))
    if _RELEASE_RE.search(body):
        found.append((WorkflowChangeKind.RELEASE_OPERATION_ADDED, body[:100]))

    return found


def _read_workflow_diff(runner: GitRunner, commit: CommitRecord, paths: list[str]) -> str:
    """Unified diff of one commit, limited to the given workflow paths."""

    argv = [
        "show",
        "--format=",
        "--unified=0",
        "--first-parent",
        commit.commit_sha,
        "--",
        *paths,
    ]
    return runner.text(argv)


def _changes_from_diff(commit: CommitRecord, diff: str) -> list[WorkflowChange]:
    """Turn one commit's workflow diff into structured changes."""

    changes: list[WorkflowChange] = []
    current_path = ""
    added: list[str] = []
    removed: list[str] = []

    def make(kind: WorkflowChangeKind, detail: str, line: str, path: str) -> WorkflowChange:
        return WorkflowChange(
            commit_sha=commit.commit_sha,
            short_sha=commit.short_sha,
            author_name=commit.author_name,
            author_email=commit.author_email,
            timestamp=commit.timestamp.isoformat(),
            subject=commit.subject,
            path=path,
            kind=kind,
            detail=detail,
            added_line=line.strip()[:200],
        )

    def flush() -> None:
        if not current_path:
            return
        seen: set[tuple[WorkflowChangeKind, str]] = set()
        for line in added:
            for kind, detail in _classify_added_line(line, removed):
                if (kind, detail) in seen:
                    continue
                seen.add((kind, detail))
                changes.append(make(kind, detail, line, current_path))

    for raw in diff.splitlines():
        if raw.startswith("+++ b/"):
            flush()
            current_path = raw[len("+++ b/") :].strip()
            added, removed = [], []
            continue
        if raw.startswith(("--- ", "diff --git", "@@", "index ", "new file", "deleted file")):
            continue
        added_match = _ADDED_LINE.match(raw)
        if added_match:
            added.append(added_match.group("body"))
            continue
        removed_match = _REMOVED_LINE.match(raw)
        if removed_match:
            removed.append(removed_match.group("body"))

    flush()

    # A workflow appearing for the first time is worth recording explicitly:
    # the diff alone would report only the lines it happens to contain.
    for change in commit.file_changes:
        if change.category is FileCategory.WORKFLOW and change.status is ChangeStatus.ADDED:
            changes.append(
                make(WorkflowChangeKind.WORKFLOW_ADDED, change.path, "", change.path)
            )

    return changes


def collect_workflow_history(
    repo_path: str,
    analysis: RepositoryAnalysis,
    *,
    max_commits: int = 300,
) -> WorkflowHistory:
    """Read what each workflow-touching commit changed.

    ``analysis`` supplies the commits and their file classification, so the cost
    here stays proportional to the interesting history rather than to the whole
    repository.
    """

    history = WorkflowHistory()
    workflow_commits = [c for c in analysis.commits if c.touches_workflow][:max_commits]
    if not workflow_commits:
        return history

    try:
        runner = GitRunner(repo_path, analysis.config or AnalysisConfig())
    except SupplyTraceError as exc:
        history.unreadable.append(f"could not open repository for diffs: {exc}")
        return history

    for commit in workflow_commits:
        paths = [
            change.path
            for change in commit.file_changes
            if change.category is FileCategory.WORKFLOW
        ]
        if not paths:
            continue
        try:
            diff = _read_workflow_diff(runner, commit, paths)
        except SupplyTraceError as exc:
            history.unreadable.append(f"{commit.short_sha}: {exc}")
            continue
        history.changes.extend(_changes_from_diff(commit, diff))

    return history


class WorkflowHistoryRule(Rule):
    """Report the workflow changes Git history shows, as evidence.

    These findings are deliberately low severity: a commit that added an action
    is a fact about the repository's past, not a weakness in its present. Their
    value is that the graph can then connect "this action was added by that
    commit, by that author, on that date" to "that action is unpinned and runs
    with write permissions today".
    """

    id = "WORKFLOW_HISTORY_CHANGE"
    name = "A commit changed a workflow's security posture"
    rationale = (
        "Attacks on a build pipeline arrive as ordinary-looking commits. Knowing "
        "which commit introduced an action, widened a permission or added a "
        "network call gives every workflow finding a point in time and an author."
    )

    #: Change kinds worth a finding of their own. Adding an action is recorded
    #: in the graph regardless, but only these read as posture changes.
    _NOTABLE = frozenset(
        {
            WorkflowChangeKind.PERMISSION_WIDENED,
            WorkflowChangeKind.NETWORK_COMMAND_ADDED,
            WorkflowChangeKind.TRIGGER_CHANGED,
            WorkflowChangeKind.RELEASE_OPERATION_ADDED,
        }
    )

    def apply(self, context: ScanContext) -> Iterable[Finding]:
        history = context.workflow_history
        if history is None or not history.changes:
            return

        ranked = (
            {item.commit_sha: item for item in rank_commits(context.history)}
            if context.history is not None
            else {}
        )

        # Group by commit: one commit that did three notable things is one
        # finding listing three, not three findings a reader has to reassemble.
        by_commit: dict[str, list[WorkflowChange]] = {}
        for change in history.changes:
            if change.kind in self._NOTABLE:
                by_commit.setdefault(change.commit_sha, []).append(change)

        for sha, changes in by_commit.items():
            first = changes[0]
            priority = ranked.get(sha)

            yield Finding(
                rule_id=self.id,
                type=FindingType.HISTORY,
                severity=Severity.LOW,
                confidence=0.9,
                state=RelationshipState.OBSERVED,
                title=f"Commit {first.short_sha} changed workflow security posture",
                description=(
                    f"{first.author_name} <{first.author_email}> in {first.short_sha} "
                    f'("{first.subject}") '
                    + "; ".join(
                        f"{CHANGE_DESCRIPTIONS[c.kind]} ({c.detail})" for c in changes[:4]
                    )
                    + f" in {first.path}."
                    + (
                        f" SupplyTrace's commit ranking scores this commit {priority.score}."
                        if priority
                        else ""
                    )
                ),
                remediation=f"Review it directly: git show {first.short_sha} -- {first.path}",
                file=first.path,
                line=0,
                commit=sha,
                evidence=[
                    EvidenceItem(
                        file=change.path,
                        line=0,
                        snippet=change.added_line or change.detail,
                        label=CHANGE_DESCRIPTIONS[change.kind],
                        commit=sha,
                    )
                    for change in changes[:5]
                ],
                metadata={
                    "commit": sha,
                    "author": f"{first.author_name} <{first.author_email}>",
                    "timestamp": first.timestamp,
                    "change_kinds": sorted({c.kind.value for c in changes}),
                    "changes": [
                        {"kind": c.kind.value, "detail": c.detail, "path": c.path}
                        for c in changes
                    ],
                    "signal_score": priority.score if priority else None,
                },
            )


__all__ = [
    "CHANGE_DESCRIPTIONS",
    "WorkflowChange",
    "WorkflowChangeKind",
    "WorkflowHistory",
    "WorkflowHistoryRule",
    "collect_workflow_history",
]
