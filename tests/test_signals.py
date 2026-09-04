"""Tests for review-priority signals and the investigate/commit commands."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from supplytrace.analyzers.git_analyzer import analyze_repository
from supplytrace.analyzers.signal_analyzer import (
    _first_commit_shas,
    commit_signals,
    rank_commits,
)
from supplytrace.models.commit import CommitRecord
from supplytrace.models.evidence import Confidence, EvidenceSource, RelationshipState
from supplytrace.models.file import ChangeStatus, FileCategory, FileChange
from supplytrace.models.signal import SIGNAL_WEIGHTS, Signal

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _change(path: str, category: FileCategory, **kwargs) -> FileChange:
    base = dict(path=path, status=ChangeStatus.MODIFIED, category=category)
    base.update(kwargs)
    return FileChange(**base)


def _commit(changes: list[FileChange], *, sha: str = "a" * 40, when: datetime = NOW,
            email: str = "dev@example.com") -> CommitRecord:
    return CommitRecord(
        commit_sha=sha,
        author_name="Dev",
        author_email=email,
        committer_name="Dev",
        committer_email=email,
        timestamp=when,
        message="Subject",
        parent_commits=["b" * 40],
        file_changes=changes,
    )


class TestIndividualSignals:
    def test_workflow_change_fires(self):
        commit = _commit([_change(".github/workflows/ci.yml", FileCategory.WORKFLOW)])
        assert Signal.WORKFLOW_MODIFIED in {h.signal for h in commit_signals(commit)}

    def test_manifest_change_fires(self):
        commit = _commit([_change("requirements.txt", FileCategory.DEPENDENCY_MANIFEST)])
        signals = {h.signal for h in commit_signals(commit)}
        assert Signal.DEPENDENCY_MANIFEST_MODIFIED in signals

    def test_lockfile_without_manifest_fires(self):
        """A resolved dependency set moving with no declared change."""

        commit = _commit([_change("package-lock.json", FileCategory.LOCKFILE)])
        signals = {h.signal for h in commit_signals(commit)}
        assert Signal.LOCKFILE_MODIFIED in signals
        assert Signal.LOCKFILE_WITHOUT_MANIFEST in signals

    def test_lockfile_with_manifest_does_not_fire_the_mismatch_signal(self):
        """An ordinary dependency bump changes both files together."""

        commit = _commit([
            _change("package.json", FileCategory.DEPENDENCY_MANIFEST),
            _change("package-lock.json", FileCategory.LOCKFILE),
        ])
        signals = {h.signal for h in commit_signals(commit)}
        assert Signal.LOCKFILE_WITHOUT_MANIFEST not in signals

    def test_build_and_dependencies_together_fires(self):
        commit = _commit([
            _change(".github/workflows/release.yml", FileCategory.WORKFLOW),
            _change("package-lock.json", FileCategory.LOCKFILE),
        ])
        signals = {h.signal for h in commit_signals(commit)}
        assert Signal.BUILD_AND_DEPENDENCIES_TOGETHER in signals

    def test_workflow_alone_does_not_fire_the_combination(self):
        commit = _commit([_change(".github/workflows/ci.yml", FileCategory.WORKFLOW)])
        signals = {h.signal for h in commit_signals(commit)}
        assert Signal.BUILD_AND_DEPENDENCIES_TOGETHER not in signals

    def test_added_binary_fires(self):
        commit = _commit([
            _change("logo.bin", FileCategory.OTHER,
                    status=ChangeStatus.ADDED, is_binary=True)
        ])
        assert Signal.BINARY_ADDED in {h.signal for h in commit_signals(commit)}

    def test_modified_binary_does_not_fire(self):
        commit = _commit([_change("logo.bin", FileCategory.OTHER, is_binary=True)])
        assert Signal.BINARY_ADDED not in {h.signal for h in commit_signals(commit)}

    def test_first_commit_flag_is_honoured(self):
        commit = _commit([_change("a.py", FileCategory.SOURCE)])
        assert commit_signals(commit, is_first_by_author=False) == []
        signals = {h.signal for h in commit_signals(commit, is_first_by_author=True)}
        assert signals == {Signal.FIRST_COMMIT_BY_AUTHOR}

    def test_ordinary_source_commit_has_no_signals(self):
        commit = _commit([_change("src/app.py", FileCategory.SOURCE)])
        assert commit_signals(commit) == []

    def test_hits_carry_observed_evidence_and_paths(self):
        commit = _commit([_change("package-lock.json", FileCategory.LOCKFILE)])
        hit = next(h for h in commit_signals(commit)
                   if h.signal is Signal.LOCKFILE_WITHOUT_MANIFEST)
        assert hit.evidence.state is RelationshipState.OBSERVED
        assert hit.evidence.source is EvidenceSource.GIT_DIFF
        assert hit.paths == ["package-lock.json"]
        assert hit.weight == SIGNAL_WEIGHTS[Signal.LOCKFILE_WITHOUT_MANIFEST]


class TestRanking:
    def test_first_commit_per_author_is_identified(self, sample_repo):
        analysis = analyze_repository(str(sample_repo.path))
        first = _first_commit_shas(analysis)
        # One "first commit" per distinct author identity.
        assert len(first) == analysis.stats.author_count

    def test_commits_without_signals_are_excluded(self, repo_builder):
        repo_builder.write("src/app.py", "x = 1\n")
        repo_builder.commit("plain source change")
        repo_builder.write("src/app.py", "x = 2\n")
        repo_builder.commit("another plain change")
        ranked = rank_commits(analyze_repository(str(repo_builder.path)))
        # Only the root commit qualifies, via FIRST_COMMIT_BY_AUTHOR.
        assert len(ranked) == 1

    def test_ranking_is_ordered_by_score(self, demo_repo):
        ranked = rank_commits(analyze_repository(str(demo_repo)))
        scores = [item.score for item in ranked]
        assert scores == sorted(scores, reverse=True)

    def test_the_planted_commit_ranks_first(self, demo_repo):
        """The demo's attack commit must surface at the top, by a clear margin."""

        ranked = rank_commits(analyze_repository(str(demo_repo)))
        top = ranked[0]
        assert top.author_name == "kaito-dev"
        assert Signal.BUILD_AND_DEPENDENCIES_TOGETHER in top.signals
        assert Signal.LOCKFILE_WITHOUT_MANIFEST in top.signals
        assert top.score > ranked[1].score, "top commit must be unambiguous"

    def test_score_is_the_sum_of_weights(self):
        commit = _commit([
            _change(".github/workflows/release.yml", FileCategory.WORKFLOW),
            _change("package-lock.json", FileCategory.LOCKFILE),
        ])
        ranked = rank_commits(_analysis_with([commit]))
        expected = sum(
            SIGNAL_WEIGHTS[s] for s in (
                Signal.WORKFLOW_MODIFIED,
                Signal.LOCKFILE_MODIFIED,
                Signal.LOCKFILE_WITHOUT_MANIFEST,
                Signal.BUILD_AND_DEPENDENCIES_TOGETHER,
                Signal.FIRST_COMMIT_BY_AUTHOR,
            )
        )
        assert ranked[0].score == expected

    def test_ties_are_broken_deterministically(self):
        commits = [
            _commit([_change(".github/workflows/a.yml", FileCategory.WORKFLOW)],
                    sha="1" * 40, when=NOW + timedelta(days=2), email="x@example.com"),
            _commit([_change(".github/workflows/b.yml", FileCategory.WORKFLOW)],
                    sha="2" * 40, when=NOW + timedelta(days=1), email="y@example.com"),
        ]
        first = [item.short_sha for item in rank_commits(_analysis_with(commits))]
        second = [item.short_sha for item in rank_commits(_analysis_with(commits))]
        assert first == second


class TestRankingHonesty:
    def test_ranking_is_labelled_inferred_not_observed(self, demo_repo):
        """The ordering is a heuristic and must never claim to be observed fact."""

        top = rank_commits(analyze_repository(str(demo_repo)))[0]
        evidence = top.ranking_evidence()
        assert evidence.state is RelationshipState.INFERRED
        assert evidence.source is EvidenceSource.HEURISTIC
        assert evidence.confidence is not Confidence.HIGH
        assert "not a finding of compromise" in evidence.detail["meaning"]

    def test_individual_signals_remain_observed(self, demo_repo):
        top = rank_commits(analyze_repository(str(demo_repo)))[0]
        assert all(hit.evidence.state is RelationshipState.OBSERVED for hit in top.hits)


def _analysis_with(commits: list[CommitRecord]):
    from supplytrace import __version__
    from supplytrace.core.config import AnalysisConfig
    from supplytrace.models.repository import RepositoryAnalysis, RepositoryInfo

    return RepositoryAnalysis(
        tool_version=__version__,
        config=AnalysisConfig(),
        repository=RepositoryInfo(path="/tmp/x", git_dir="/tmp/x/.git"),
        commits=commits,
    )


class TestJsonSerialisation:
    """The ranking is meant to feed later phases, so the score must survive."""

    def test_score_and_signals_appear_in_json(self, demo_repo):
        top = rank_commits(analyze_repository(str(demo_repo)))[0]
        payload = top.model_dump(mode="json")
        assert payload["score"] == top.score
        assert payload["score"] > 0
        assert Signal.BUILD_AND_DEPENDENCIES_TOGETHER.value in payload["signals"]

    def test_hit_weight_appears_in_json(self, demo_repo):
        top = rank_commits(analyze_repository(str(demo_repo)))[0]
        hit = top.model_dump(mode="json")["hits"][0]
        assert hit["weight"] >= 1

    def test_json_round_trips(self, demo_repo):
        from supplytrace.models.signal import CommitReviewPriority

        top = rank_commits(analyze_repository(str(demo_repo)))[0]
        restored = CommitReviewPriority.model_validate_json(top.model_dump_json())
        assert restored.score == top.score
