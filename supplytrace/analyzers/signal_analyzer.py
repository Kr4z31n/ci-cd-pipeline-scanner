"""Compute review-priority signals over a completed Phase 1 analysis.

This analyzer adds no new data source. It reads the commits and file changes
that :mod:`supplytrace.analyzers.git_analyzer` already produced and points out
which commits a human should read first.

It never labels a commit malicious. It answers "where do I start?".
"""

from __future__ import annotations

from supplytrace.models.commit import CommitRecord
from supplytrace.models.evidence import (
    Confidence,
    Evidence,
    EvidenceSource,
    RelationshipState,
)
from supplytrace.models.file import ChangeStatus, FileCategory
from supplytrace.models.repository import RepositoryAnalysis
from supplytrace.models.signal import (
    SIGNAL_DESCRIPTIONS,
    CommitReviewPriority,
    Signal,
    SignalHit,
)


def _observed(commit_sha: str, **detail: object) -> Evidence:
    return Evidence(
        source=EvidenceSource.GIT_DIFF,
        state=RelationshipState.OBSERVED,
        confidence=Confidence.HIGH,
        detail={"commit": commit_sha, **detail},
    )


def _first_commit_shas(analysis: RepositoryAnalysis) -> set[str]:
    """The earliest commit of each author within the analysed history."""

    earliest: dict[str, CommitRecord] = {}
    for commit in analysis.commits:
        key = commit.author.key
        current = earliest.get(key)
        if current is None or commit.timestamp < current.timestamp:
            earliest[key] = commit
    return {commit.commit_sha for commit in earliest.values()}


def commit_signals(commit: CommitRecord, *, is_first_by_author: bool = False) -> list[SignalHit]:
    """Signals that fire on one commit."""

    hits: list[SignalHit] = []

    def add(signal: Signal, paths: list[str]) -> None:
        hits.append(
            SignalHit(
                signal=signal,
                description=SIGNAL_DESCRIPTIONS[signal],
                paths=sorted(paths),
                evidence=_observed(commit.commit_sha, signal=signal.value),
            )
        )

    workflow = [c.path for c in commit.file_changes if c.category is FileCategory.WORKFLOW]
    manifests = [
        c.path for c in commit.file_changes
        if c.category is FileCategory.DEPENDENCY_MANIFEST
    ]
    lockfiles = [c.path for c in commit.file_changes if c.category is FileCategory.LOCKFILE]
    binaries = [
        c.path for c in commit.file_changes
        if c.is_binary and c.status is ChangeStatus.ADDED
    ]

    if workflow:
        add(Signal.WORKFLOW_MODIFIED, workflow)
    if manifests:
        add(Signal.DEPENDENCY_MANIFEST_MODIFIED, manifests)
    if lockfiles:
        add(Signal.LOCKFILE_MODIFIED, lockfiles)

    # A resolved dependency set that moved with no declared change is the
    # shape of a lockfile-only dependency substitution.
    if lockfiles and not manifests:
        add(Signal.LOCKFILE_WITHOUT_MANIFEST, lockfiles)

    # How the software is built, and what it is built from, in one change.
    if workflow and (manifests or lockfiles):
        add(Signal.BUILD_AND_DEPENDENCIES_TOGETHER, workflow + manifests + lockfiles)

    if binaries:
        add(Signal.BINARY_ADDED, binaries)
    if is_first_by_author:
        add(Signal.FIRST_COMMIT_BY_AUTHOR, [])

    return hits


def rank_commits(analysis: RepositoryAnalysis) -> list[CommitReviewPriority]:
    """Rank every commit that has at least one signal, highest score first."""

    first_shas = _first_commit_shas(analysis)
    ranked: list[CommitReviewPriority] = []

    for commit in analysis.commits:
        hits = commit_signals(
            commit, is_first_by_author=commit.commit_sha in first_shas
        )
        if not hits:
            continue
        ranked.append(
            CommitReviewPriority(
                commit_sha=commit.commit_sha,
                short_sha=commit.short_sha,
                author_name=commit.author_name,
                author_email=commit.author_email,
                timestamp=commit.timestamp.isoformat(),
                subject=commit.subject,
                hits=hits,
            )
        )

    ranked.sort(key=lambda item: (-item.score, item.timestamp))
    return ranked
