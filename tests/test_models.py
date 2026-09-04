"""Tests for the model layer: classification, evidence and commit helpers."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from supplytrace.models.commit import CommitRecord, Identity
from supplytrace.models.evidence import (
    Confidence,
    Evidence,
    EvidenceSource,
    RelationshipState,
    git_diff_evidence,
    git_log_evidence,
)
from supplytrace.models.file import (
    ChangeStatus,
    FileCategory,
    FileChange,
    classify_file,
    is_workflow_path,
    normalize_repo_path,
    rename_confidence,
)

NOW = datetime(2024, 1, 1, tzinfo=timezone.utc)


class TestChangeStatus:
    @pytest.mark.parametrize(
        "letter,expected",
        [
            ("A", ChangeStatus.ADDED),
            ("M", ChangeStatus.MODIFIED),
            ("D", ChangeStatus.DELETED),
            ("R", ChangeStatus.RENAMED),
            ("C", ChangeStatus.COPIED),
            ("T", ChangeStatus.TYPE_CHANGED),
            ("U", ChangeStatus.UNMERGED),
            ("?", ChangeStatus.UNKNOWN),
            ("", ChangeStatus.UNKNOWN),
        ],
    )
    def test_letters_map_to_statuses(self, letter, expected):
        assert ChangeStatus.from_git_letter(letter) is expected


class TestPathNormalization:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("./src/a.py", "src/a.py"),
            ("././src/a.py", "src/a.py"),
            (".github/workflows/ci.yml", ".github/workflows/ci.yml"),
            ("src/a.py", "src/a.py"),
        ],
    )
    def test_only_leading_dot_slash_is_removed(self, raw, expected):
        assert normalize_repo_path(raw) == expected

    def test_dotfile_prefix_survives(self):
        """Regression: str.lstrip('./') would strip the leading dot."""

        assert normalize_repo_path(".github/workflows/ci.yml").startswith(".github")


class TestWorkflowDetection:
    @pytest.mark.parametrize(
        "path",
        [
            ".github/workflows/build.yml",
            ".github/workflows/security.yaml",
            "./.github/workflows/nested.yml",
        ],
    )
    def test_workflow_paths(self, path):
        assert is_workflow_path(path) is True

    @pytest.mark.parametrize(
        "path",
        [
            ".github/workflows/README.md",
            "github/workflows/build.yml",
            "src/.github/workflows/build.yml",
            "config.yml",
        ],
    )
    def test_non_workflow_paths(self, path):
        assert is_workflow_path(path) is False


class TestFileClassification:
    @pytest.mark.parametrize(
        "path,category",
        [
            (".github/workflows/build.yml", FileCategory.WORKFLOW),
            (".github/actions/mine/action.yml", FileCategory.WORKFLOW),
            ("package-lock.json", FileCategory.LOCKFILE),
            ("poetry.lock", FileCategory.LOCKFILE),
            ("go.sum", FileCategory.LOCKFILE),
            ("requirements.txt", FileCategory.DEPENDENCY_MANIFEST),
            ("pyproject.toml", FileCategory.DEPENDENCY_MANIFEST),
            ("package.json", FileCategory.DEPENDENCY_MANIFEST),
            ("go.mod", FileCategory.DEPENDENCY_MANIFEST),
            (".gitlab-ci.yml", FileCategory.CI_CONFIG),
            (".circleci/config.yml", FileCategory.CI_CONFIG),
            ("Dockerfile", FileCategory.BUILD),
            ("Makefile", FileCategory.BUILD),
            ("src/auth.py", FileCategory.SOURCE),
            ("lib/index.ts", FileCategory.SOURCE),
            ("tests/test_auth.py", FileCategory.TEST),
            ("src/auth_test.go", FileCategory.TEST),
            ("README.md", FileCategory.DOCUMENTATION),
            ("app/settings.yaml", FileCategory.CONFIG),
            ("assets/logo.png", FileCategory.OTHER),
            ("", FileCategory.OTHER),
        ],
    )
    def test_classification(self, path, category):
        assert classify_file(path) is category

    def test_workflow_beats_generic_yaml(self):
        """Ordering matters: a workflow is not merely a CONFIG file."""

        assert classify_file(".github/workflows/x.yml") is FileCategory.WORKFLOW
        assert classify_file("other/x.yml") is FileCategory.CONFIG

    def test_lockfile_beats_manifest_for_package_lock(self):
        assert classify_file("package-lock.json") is FileCategory.LOCKFILE
        assert classify_file("package.json") is FileCategory.DEPENDENCY_MANIFEST

    def test_classification_is_case_insensitive(self):
        assert classify_file("REQUIREMENTS.TXT") is FileCategory.DEPENDENCY_MANIFEST


class TestRenameConfidence:
    @pytest.mark.parametrize(
        "similarity,expected",
        [
            (100, Confidence.HIGH),
            (95, Confidence.HIGH),
            (94, Confidence.MEDIUM),
            (75, Confidence.MEDIUM),
            (74, Confidence.LOW),
            (50, Confidence.LOW),
            (None, Confidence.UNKNOWN),
        ],
    )
    def test_similarity_maps_to_confidence(self, similarity, expected):
        assert rename_confidence(similarity) is expected


class TestEvidence:
    def test_git_log_evidence_defaults(self):
        evidence = git_log_evidence(commit="abc")
        assert evidence.source is EvidenceSource.GIT_LOG
        assert evidence.state is RelationshipState.OBSERVED
        assert evidence.confidence is Confidence.HIGH
        assert evidence.detail["commit"] == "abc"

    def test_git_diff_evidence_accepts_confidence(self):
        evidence = git_diff_evidence(confidence=Confidence.LOW, similarity=51)
        assert evidence.confidence is Confidence.LOW

    def test_inferred_state_is_representable(self):
        """Phase 8 needs INFERRED relationships; the model supports it now."""

        evidence = Evidence(
            source=EvidenceSource.WORKFLOW_YAML,
            state=RelationshipState.INFERRED,
            confidence=Confidence.MEDIUM,
        )
        assert "INFERRED" in evidence.describe()

    def test_describe_includes_details(self):
        assert "commit=abc" in git_log_evidence(commit="abc").describe()

    def test_evidence_is_immutable(self):
        evidence = git_log_evidence()
        with pytest.raises(Exception):
            evidence.confidence = Confidence.LOW  # type: ignore[misc]


class TestIdentity:
    def test_key_prefers_lowercased_email(self):
        assert Identity(name="A", email="A@Example.COM").key == "a@example.com"

    def test_key_falls_back_to_name(self):
        assert Identity(name="Nameless").key == "nameless"

    def test_str_rendering(self):
        assert str(Identity(name="A", email="a@x")) == "A <a@x>"
        assert str(Identity()) == "(unknown)"


def _commit(**overrides) -> CommitRecord:
    base = dict(
        commit_sha="a" * 40,
        author_name="Alice",
        author_email="alice@example.com",
        committer_name="Alice",
        committer_email="alice@example.com",
        timestamp=NOW,
        message="Subject\n\nBody",
        parent_commits=["b" * 40],
    )
    base.update(overrides)
    return CommitRecord(**base)


class TestCommitRecord:
    def test_subject_is_the_first_line(self):
        assert _commit().subject == "Subject"

    def test_empty_message_has_empty_subject(self):
        assert _commit(message="").subject == ""

    def test_short_sha(self):
        assert _commit().short_sha == "a" * 12

    def test_merge_and_root_detection(self):
        assert _commit(parent_commits=["b" * 40, "c" * 40]).is_merge is True
        assert _commit(parent_commits=[]).is_root is True
        assert _commit().is_merge is False

    def test_touchpoint_helpers(self):
        commit = _commit(
            file_changes=[
                FileChange(
                    path=".github/workflows/ci.yml",
                    status=ChangeStatus.MODIFIED,
                    category=FileCategory.WORKFLOW,
                ),
                FileChange(
                    path="requirements.txt",
                    status=ChangeStatus.MODIFIED,
                    category=FileCategory.DEPENDENCY_MANIFEST,
                ),
            ]
        )
        assert commit.touches_workflow is True
        assert commit.touches_dependencies is True

