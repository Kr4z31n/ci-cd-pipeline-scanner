"""Tests for Phase 1 Git repository analysis."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from supplytrace.analyzers.git_analyzer import GitAnalyzer, analyze_repository
from supplytrace.core.config import AnalysisConfig
from supplytrace.models.evidence import Confidence, EvidenceSource, RelationshipState
from supplytrace.models.file import ChangeStatus, FileCategory
from supplytrace.models.repository import RefKind


@pytest.fixture
def analysis(sample_repo):
    return analyze_repository(str(sample_repo.path))


class TestRepositoryInfo:
    def test_reports_repository_shape(self, analysis, sample_repo):
        repo = analysis.repository
        assert repo.path == str(sample_repo.path.resolve())
        assert repo.is_bare is False
        assert repo.is_shallow is False
        assert repo.head_ref == "main"
        assert repo.git_version.startswith("git version")

    def test_head_sha_matches_git(self, analysis, sample_repo):
        assert analysis.repository.head_sha == sample_repo.head()

    def test_default_branch_is_detected(self, analysis):
        assert analysis.repository.default_branch_guess == "main"

    def test_shallow_clone_is_flagged_as_an_anomaly(self, sample_repo, tmp_path):
        shallow = tmp_path / "shallow"
        sample_repo.git("clone", "-q", "--depth", "1", f"file://{sample_repo.path}", str(shallow))
        result = analyze_repository(str(shallow))
        assert result.repository.is_shallow is True
        assert any("shallow" in a.detail.lower() for a in result.anomalies)

    def test_remote_credentials_are_redacted(self, repo_builder):
        repo_builder.write("a.txt", "x\n")
        repo_builder.commit("first")
        repo_builder.git(
            "remote", "add", "origin", "https://user:supersecret@github.com/o/r.git"
        )
        result = analyze_repository(str(repo_builder.path))
        rendered = str(result.repository.remotes)
        assert "supersecret" not in rendered
        assert "github.com/o/r.git" in rendered


class TestCommitExtraction:
    def test_all_commits_are_found(self, analysis, sample_repo):
        assert analysis.stats.commit_count == 5
        found = {c.commit_sha for c in analysis.commits}
        assert found == set(sample_repo.shas.values())

    def test_commit_fields_are_populated(self, analysis, sample_repo):
        first = analysis.commit(sample_repo.shas["first"])
        assert first is not None
        assert first.author_name == "Alice"
        assert first.author_email == "alice@example.com"
        assert first.committer_name == "Alice"
        assert first.committer_email == "alice@example.com"
        assert first.message == "Initial commit"
        assert first.subject == "Initial commit"
        assert isinstance(first.timestamp, datetime)
        assert first.timestamp.tzinfo is not None

    def test_root_commit_has_no_parents(self, analysis, sample_repo):
        first = analysis.commit(sample_repo.shas["first"])
        assert first.parent_commits == []
        assert first.is_root is True
        assert first.is_merge is False

    def test_parent_chain_is_correct(self, analysis, sample_repo):
        second = analysis.commit(sample_repo.shas["second"])
        assert second.parent_commits == [sample_repo.shas["first"]]

    def test_merge_commit_has_two_parents(self, analysis, sample_repo):
        merge = analysis.commit(sample_repo.shas["merge"])
        assert merge.is_merge is True
        assert len(merge.parent_commits) == 2
        assert merge.parent_commits[0] == sample_repo.shas["third"]
        assert merge.parent_commits[1] == sample_repo.shas["fourth"]

    def test_lookup_by_short_sha(self, analysis, sample_repo):
        full = sample_repo.shas["first"]
        assert analysis.commit(full[:8]).commit_sha == full

    def test_commit_carries_git_log_evidence(self, analysis, sample_repo):
        commit = analysis.commit(sample_repo.shas["first"])
        assert commit.evidence.source is EvidenceSource.GIT_LOG
        assert commit.evidence.state is RelationshipState.OBSERVED
        assert commit.evidence.confidence is Confidence.HIGH

    def test_multiline_message_is_preserved(self, repo_builder):
        body = "Subject line\n\nDetailed body line one.\nDetailed body line two."
        repo_builder.write("a.txt", "x\n")
        repo_builder.commit(body)
        result = analyze_repository(str(repo_builder.path))
        commit = result.commits[0]
        assert commit.message == body
        assert commit.subject == "Subject line"


class TestFileChangeExtraction:
    def test_added_files_are_recorded(self, analysis, sample_repo):
        first = analysis.commit(sample_repo.shas["first"])
        paths = {c.path: c for c in first.file_changes}
        assert set(paths) == {"src/auth.py", "requirements.txt", "README.md"}
        assert all(c.status is ChangeStatus.ADDED for c in first.file_changes)
        assert paths["src/auth.py"].additions == 5
        assert paths["src/auth.py"].deletions == 0

    def test_modified_file_has_both_counts(self, analysis, sample_repo):
        second = analysis.commit(sample_repo.shas["second"])
        change = next(c for c in second.file_changes if c.path == "src/auth.py")
        assert change.status is ChangeStatus.MODIFIED
        assert change.additions > 0
        assert change.deletions > 0

    def test_deleted_file_is_recorded(self, analysis, sample_repo):
        third = analysis.commit(sample_repo.shas["third"])
        change = next(c for c in third.file_changes if c.path == "README.md")
        assert change.status is ChangeStatus.DELETED
        assert change.new_blob is None
        assert change.old_blob is not None

    def test_rename_records_both_paths_and_similarity(self, analysis, sample_repo):
        third = analysis.commit(sample_repo.shas["third"])
        change = next(c for c in third.file_changes if c.status is ChangeStatus.RENAMED)
        assert change.old_path == "src/auth.py"
        assert change.new_path == "src/authentication.py"
        assert change.path == "src/authentication.py"
        assert 0 < change.similarity <= 100

    def test_rename_confidence_reflects_similarity(self, analysis, sample_repo):
        third = analysis.commit(sample_repo.shas["third"])
        change = next(c for c in third.file_changes if c.status is ChangeStatus.RENAMED)
        assert change.evidence.confidence in {
            Confidence.HIGH,
            Confidence.MEDIUM,
            Confidence.LOW,
        }
        if change.similarity >= 95:
            assert change.evidence.confidence is Confidence.HIGH

    def test_rename_detection_can_be_disabled(self, sample_repo):
        result = analyze_repository(
            str(sample_repo.path), AnalysisConfig(detect_renames=False)
        )
        third = result.commit(sample_repo.shas["third"])
        statuses = {c.status for c in third.file_changes}
        assert ChangeStatus.RENAMED not in statuses
        paths = {c.path for c in third.file_changes}
        assert "src/auth.py" in paths and "src/authentication.py" in paths

    def test_binary_file_has_no_line_counts(self, analysis, sample_repo):
        third = analysis.commit(sample_repo.shas["third"])
        change = next(c for c in third.file_changes if c.path == "assets/logo.bin")
        assert change.is_binary is True
        assert change.additions is None
        assert change.deletions is None

    def test_file_modes_and_blobs_are_captured(self, analysis, sample_repo):
        first = analysis.commit(sample_repo.shas["first"])
        change = next(c for c in first.file_changes if c.path == "src/auth.py")
        assert change.old_mode is None
        assert change.new_mode == "100644"
        assert change.old_blob is None
        assert len(change.new_blob) >= 7

    def test_changes_carry_diff_evidence(self, analysis, sample_repo):
        first = analysis.commit(sample_repo.shas["first"])
        change = first.file_changes[0]
        assert change.evidence.source is EvidenceSource.GIT_DIFF
        assert change.evidence.state is RelationshipState.OBSERVED


class TestFileClassification:
    def test_workflow_file_is_classified(self, analysis, sample_repo):
        second = analysis.commit(sample_repo.shas["second"])
        change = next(
            c for c in second.file_changes if c.path == ".github/workflows/build.yml"
        )
        assert change.category is FileCategory.WORKFLOW
        assert change.is_workflow_file is True
        assert second.touches_workflow is True

    def test_manifest_and_lockfile_are_classified(self, analysis, sample_repo):
        first = analysis.commit(sample_repo.shas["first"])
        manifest = next(c for c in first.file_changes if c.path == "requirements.txt")
        assert manifest.category is FileCategory.DEPENDENCY_MANIFEST
        assert first.touches_dependencies is True

        second = analysis.commit(sample_repo.shas["second"])
        lock = next(c for c in second.file_changes if c.path == "package-lock.json")
        assert lock.category is FileCategory.LOCKFILE
        assert lock.is_dependency_file is True

    def test_extension_is_recorded(self, analysis, sample_repo):
        first = analysis.commit(sample_repo.shas["first"])
        change = next(c for c in first.file_changes if c.path == "src/auth.py")
        assert change.extension == ".py"


class TestMergeHandling:
    def test_merge_uses_first_parent_diff_by_default(self, analysis, sample_repo):
        merge = analysis.commit(sample_repo.shas["merge"])
        paths = {c.path for c in merge.file_changes}
        assert "src/feature.py" in paths

    def test_merge_diffs_can_be_disabled(self, sample_repo):
        result = analyze_repository(
            str(sample_repo.path), AnalysisConfig(diff_merges="off")
        )
        merge = result.commit(sample_repo.shas["merge"])
        assert merge.file_changes == []
        assert merge.diff_truncated is True

    def test_non_merge_commits_are_unaffected_by_the_setting(self, sample_repo):
        result = analyze_repository(
            str(sample_repo.path), AnalysisConfig(diff_merges="off")
        )
        first = result.commit(sample_repo.shas["first"])
        assert len(first.file_changes) == 3
        assert first.diff_truncated is False


class TestRefs:
    def test_branches_are_listed(self, analysis):
        names = {ref.name for ref in analysis.branches if ref.kind is RefKind.BRANCH}
        assert names == {"main", "feature"}

    def test_head_branch_is_marked(self, analysis):
        head = [ref for ref in analysis.branches if ref.is_head]
        assert len(head) == 1
        assert head[0].name == "main"

    def test_annotated_tag_is_peeled_to_a_commit(self, sample_repo):
        sample_repo.git("tag", "-a", "v1.0", "-m", "release one")
        result = analyze_repository(str(sample_repo.path))
        tag = next(ref for ref in result.branches if ref.kind is RefKind.TAG)
        assert tag.name == "v1.0"
        assert tag.target_sha == sample_repo.head()
        assert result.stats.tag_count == 1

    def test_lightweight_tag_is_listed(self, sample_repo):
        sample_repo.git("tag", "v0.9")
        result = analyze_repository(str(sample_repo.path))
        assert any(ref.name == "v0.9" for ref in result.branches)


class TestAuthorsAndStats:
    def test_authors_are_aggregated(self, analysis):
        by_email = {a.email: a for a in analysis.authors}
        assert set(by_email) == {
            "alice@example.com",
            "bob@example.com",
            "carol@example.com",
        }
        assert by_email["alice@example.com"].commit_count == 3
        assert by_email["bob@example.com"].commit_count == 1

    def test_authors_are_sorted_by_commit_count(self, analysis):
        counts = [a.commit_count for a in analysis.authors]
        assert counts == sorted(counts, reverse=True)

    def test_author_supply_chain_counters(self, analysis):
        bob = next(a for a in analysis.authors if a.email == "bob@example.com")
        assert bob.workflow_commit_count == 1
        assert bob.dependency_commit_count == 1

    def test_stats_totals_are_consistent(self, analysis):
        stats = analysis.stats
        assert stats.commit_count == len(analysis.commits)
        assert stats.author_count == len(analysis.authors)
        assert stats.merge_commit_count == 1
        assert stats.root_commit_count == 1
        assert stats.file_change_count == sum(
            len(c.file_changes) for c in analysis.commits
        )
        assert stats.total_additions == sum(c.additions for c in analysis.commits)
        assert stats.rename_count == 1
        assert stats.binary_change_count == 1

    def test_date_span_is_populated(self, analysis):
        assert analysis.stats.first_commit_at <= analysis.stats.last_commit_at

    def test_category_counts_cover_every_change(self, analysis):
        assert sum(analysis.stats.category_counts.values()) == analysis.stats.file_change_count


class TestLimitsAndScope:
    def test_max_commits_truncates_and_flags(self, sample_repo):
        result = analyze_repository(str(sample_repo.path), AnalysisConfig(max_commits=2))
        assert result.stats.commit_count == 2
        assert result.stats.commit_limit_reached is True

    def test_limit_not_flagged_when_history_fits(self, sample_repo):
        result = analyze_repository(str(sample_repo.path), AnalysisConfig(max_commits=100))
        assert result.stats.commit_limit_reached is False

    def test_head_only_scope_excludes_unmerged_branches(self, sample_repo):
        sample_repo.checkout_new("orphan-work", sample_repo.shas["first"])
        sample_repo.write("src/orphan.py", "X = 1\n")
        orphan = sample_repo.commit("Orphan work", author="Dan", email="dan@example.com")
        sample_repo.checkout("main")

        all_refs = analyze_repository(str(sample_repo.path))
        head_only = analyze_repository(
            str(sample_repo.path), AnalysisConfig(include_all_refs=False)
        )
        assert orphan in {c.commit_sha for c in all_refs.commits}
        assert orphan not in {c.commit_sha for c in head_only.commits}


class TestEdgeCases:
    def test_empty_repository_produces_empty_analysis(self, repo_builder):
        result = analyze_repository(str(repo_builder.path))
        assert result.commits == []
        assert result.stats.commit_count == 0
        assert result.authors == []
        assert result.repository.head_sha is None

    def test_empty_commit_has_no_file_changes(self, repo_builder):
        repo_builder.write("a.txt", "x\n")
        repo_builder.commit("first")
        repo_builder.commit("empty one", allow_empty=True)
        result = analyze_repository(str(repo_builder.path))
        empty = next(c for c in result.commits if c.subject == "empty one")
        assert empty.file_changes == []
        assert result.anomalies == []

    def test_bare_repository_is_analysable(self, sample_repo, tmp_path):
        bare = tmp_path / "bare.git"
        sample_repo.git("clone", "-q", "--bare", f"file://{sample_repo.path}", str(bare))
        result = analyze_repository(str(bare))
        assert result.repository.is_bare is True
        assert result.stats.commit_count == 5

    def test_analysis_is_deterministic(self, sample_repo):
        first = analyze_repository(str(sample_repo.path))
        second = analyze_repository(str(sample_repo.path))
        assert [c.commit_sha for c in first.commits] == [
            c.commit_sha for c in second.commits
        ]
        assert first.stats.file_change_count == second.stats.file_change_count

    def test_analysis_does_not_modify_the_repository(self, sample_repo):
        before = sample_repo.git("status", "--porcelain")
        head_before = sample_repo.head()
        analyze_repository(str(sample_repo.path))
        assert sample_repo.git("status", "--porcelain") == before
        assert sample_repo.head() == head_before


class TestHostilePaths:
    """A repository is untrusted input; paths and messages are attacker-controlled."""

    def test_paths_with_spaces_and_unicode(self, repo_builder):
        repo_builder.write("a file with spaces.txt", "x\n")
        repo_builder.write("dir with space/ünïcode–ß.py", "y\n")
        repo_builder.commit("odd names")
        result = analyze_repository(str(repo_builder.path))
        paths = {c.path for c in result.commits[0].file_changes}
        assert "a file with spaces.txt" in paths
        assert "dir with space/ünïcode–ß.py" in paths
        assert result.anomalies == []

    def test_path_containing_a_newline(self, repo_builder):
        """The reason every git call uses -z: a newline in a filename."""

        repo_builder.write_bytes_path(b"evil\nname.txt", b"x\n")
        repo_builder.commit("newline path")
        result = analyze_repository(str(repo_builder.path))
        paths = {c.path for c in result.commits[0].file_changes}
        assert "evil\nname.txt" in paths
        assert len(result.commits[0].file_changes) == 1

    def test_path_containing_a_tab_and_quotes(self, repo_builder):
        repo_builder.write_bytes_path(b'tab\there"quote".txt', b"x\n")
        repo_builder.commit("tab path")
        result = analyze_repository(str(repo_builder.path))
        paths = {c.path for c in result.commits[0].file_changes}
        assert 'tab\there"quote".txt' in paths

    def test_filename_cannot_forge_a_record_header(self, repo_builder):
        """A file named like our diff-stream header must not split records."""

        forged = "\x0cC" + "a" * 40
        repo_builder.write_bytes_path(forged.encode(), b"x\n")
        repo_builder.write("legit.txt", "y\n")
        repo_builder.commit("forgery attempt")
        result = analyze_repository(str(repo_builder.path))
        assert len(result.commits) == 1
        paths = {c.path for c in result.commits[0].file_changes}
        assert forged in paths
        assert "legit.txt" in paths

    def test_commit_message_cannot_forge_field_separators(self, repo_builder):
        """Separator bytes in a message must stay inside the message."""

        message = "Subject\x1fnot-an-author\x1fnot-an-email\x0cCdeadbeef"
        repo_builder.write("a.txt", "x\n")
        repo_builder.commit(message)
        result = analyze_repository(str(repo_builder.path))
        commit = result.commits[0]
        assert commit.author_name == "Test User"
        assert commit.author_email == "test@example.com"
        assert "not-an-author" in commit.message

    def test_non_utf8_path_is_recorded_and_flagged(self, repo_builder):
        repo_builder.write_bytes_path(b"bad\xff\xfename.txt", b"x\n")
        repo_builder.commit("invalid utf-8 path")
        result = analyze_repository(str(repo_builder.path))
        assert len(result.commits[0].file_changes) == 1
        assert any("UTF-8" in a.detail for a in result.anomalies)
        # The report must remain serialisable despite the undecodable bytes.
        assert result.model_dump_json()


class TestAnomalyReporting:
    def test_malformed_commit_record_is_reported_not_dropped_silently(self, sample_repo):
        analyzer = GitAnalyzer(str(sample_repo.path))
        assert analyzer._parse_commit_record("garbage-without-separators") is None
        assert analyzer.anomalies
        assert analyzer.anomalies[0].stage == "commits"

    def test_record_with_bad_sha_is_reported(self, sample_repo):
        analyzer = GitAnalyzer(str(sample_repo.path))
        record = "\x1f".join(["nothex", "", "n", "e", "2024-01-01T00:00:00+00:00", "n", "e", "2024-01-01T00:00:00+00:00", "msg"])
        assert analyzer._parse_commit_record(record) is None
        assert any("SHA" in a.detail for a in analyzer.anomalies)

    def test_bad_timestamp_is_reported(self, sample_repo):
        analyzer = GitAnalyzer(str(sample_repo.path))
        record = "\x1f".join(["a" * 40, "", "n", "e", "not-a-date", "n", "e", "not-a-date", "msg"])
        assert analyzer._parse_commit_record(record) is None
        assert any("timestamp" in a.detail for a in analyzer.anomalies)


class TestSerialisation:
    def test_report_round_trips_through_json(self, analysis):
        from supplytrace.models.repository import RepositoryAnalysis

        payload = analysis.model_dump_json()
        restored = RepositoryAnalysis.model_validate_json(payload)
        assert restored.stats.commit_count == analysis.stats.commit_count
        assert [c.commit_sha for c in restored.commits] == [
            c.commit_sha for c in analysis.commits
        ]

    def test_timestamps_serialise_with_timezone(self, analysis):
        payload = analysis.model_dump_json()
        assert "+00:00" in payload or "Z" in payload
        assert analysis.generated_at.tzinfo == timezone.utc
