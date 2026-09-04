"""Tests for configuration, logging redaction and the hardened Git runner."""

from __future__ import annotations

import logging
import os

import pytest

from supplytrace.core.config import AnalysisConfig
from supplytrace.core.errors import (
    GitCommandError,
    GitTimeoutError,
    NotAGitRepositoryError,
    RepositoryPathError,
)
from supplytrace.core.git_command import (
    BASE_ENV,
    HARDENING_CONFIG,
    GitRunner,
    build_git_env,
    sanitize_repo_path,
)
from supplytrace.core.logging import RedactingFilter, configure_logging


class TestAnalysisConfig:
    def test_defaults_are_sane(self):
        config = AnalysisConfig()
        assert config.max_commits == 50_000
        assert config.include_all_refs is True
        assert config.detect_renames is True
        assert config.diff_merges == "first-parent"

    def test_is_immutable(self):
        config = AnalysisConfig()
        with pytest.raises(Exception):
            config.max_commits = 5  # type: ignore[misc]

    @pytest.mark.parametrize("value", [0, -1, 10_000_000])
    def test_rejects_invalid_commit_limits(self, value):
        with pytest.raises(ValueError):
            AnalysisConfig(max_commits=value)

    def test_none_means_unlimited(self):
        assert AnalysisConfig(max_commits=None).max_commits is None

    def test_rejects_unknown_fields(self):
        with pytest.raises(ValueError):
            AnalysisConfig(nonexistent_option=True)  # type: ignore[call-arg]

    @pytest.mark.parametrize("threshold", [0, 101])
    def test_rejects_invalid_rename_threshold(self, threshold):
        with pytest.raises(ValueError):
            AnalysisConfig(rename_threshold=threshold)


class TestRedaction:
    @pytest.mark.parametrize(
        "secret",
        [
            "ghp_" + "A" * 36,
            "gho_" + "B" * 36,
            "ghs_" + "C" * 36,
            "github_pat_" + "D" * 40,
        ],
    )
    def test_known_token_formats_are_redacted(self, secret):
        assert secret not in RedactingFilter().redact(f"token is {secret} here")

    def test_url_embedded_credentials_are_redacted(self):
        redacted = RedactingFilter().redact("https://user:hunter2@github.com/o/r.git")
        assert "hunter2" not in redacted
        assert "github.com/o/r.git" in redacted

    def test_registered_literal_secret_is_redacted(self):
        rf = RedactingFilter()
        rf.add_secret("an-unusual-opaque-token")
        assert "an-unusual-opaque-token" not in rf.redact("value=an-unusual-opaque-token")

    def test_short_values_are_not_registered(self):
        rf = RedactingFilter()
        rf.add_secret("abc")
        assert rf.redact("abc def") == "abc def"

    def test_filter_redacts_log_records(self, caplog):
        secret = "ghp_" + "Z" * 36
        logger = configure_logging(verbosity=2)
        with caplog.at_level(logging.DEBUG, logger="supplytrace"):
            caplog.handler.addFilter(RedactingFilter())
            logger.warning("using %s", secret)
        assert all(secret not in record.getMessage() for record in caplog.records)


class TestPathSanitization:
    def test_missing_path_is_rejected(self, tmp_path):
        with pytest.raises(RepositoryPathError):
            sanitize_repo_path(tmp_path / "does-not-exist")

    def test_file_is_rejected(self, tmp_path):
        target = tmp_path / "file.txt"
        target.write_text("x")
        with pytest.raises(RepositoryPathError):
            sanitize_repo_path(target)

    def test_symlink_is_resolved(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        assert sanitize_repo_path(link) == real.resolve()

    def test_relative_path_becomes_absolute(self, tmp_path, monkeypatch):
        (tmp_path / "sub").mkdir()
        monkeypatch.chdir(tmp_path)
        assert sanitize_repo_path("sub").is_absolute()


class TestGitEnvironment:
    def test_inherited_git_variables_are_stripped(self):
        """Ambient GIT_* settings must not leak into the analysis."""

        env = build_git_env(
            {
                "GIT_AUTHOR_NAME": "attacker",
                "GIT_DIR": "/elsewhere",
                "GIT_WORK_TREE": "/elsewhere",
                "GIT_SSH_COMMAND": "touch /tmp/pwned",
                "PATH": "/usr/bin",
            }
        )
        assert "GIT_AUTHOR_NAME" not in env
        assert "GIT_DIR" not in env
        assert "GIT_WORK_TREE" not in env
        assert "GIT_SSH_COMMAND" not in env
        assert env["PATH"] == "/usr/bin"

    def test_deterministic_variables_are_set(self):
        env = build_git_env({"PATH": "/usr/bin"})
        for key, value in BASE_ENV.items():
            assert env[key] == value

    def test_global_config_is_ignored(self):
        env = build_git_env({"PATH": "/usr/bin"})
        assert env["GIT_CONFIG_GLOBAL"] == os.devnull
        assert env["GIT_CONFIG_NOSYSTEM"] == "1"


class TestGitRunner:
    def test_rejects_non_repository(self, tmp_path):
        runner = GitRunner(tmp_path)
        with pytest.raises(NotAGitRepositoryError):
            runner.ensure_repository()

    def test_accepts_repository(self, repo_builder):
        runner = GitRunner(repo_builder.path)
        runner.ensure_repository()
        assert runner.version().startswith("git version")

    def test_arguments_must_be_a_string_list(self, repo_builder):
        runner = GitRunner(repo_builder.path)
        with pytest.raises(TypeError):
            runner.run("status")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            runner.run(["log", 5])  # type: ignore[list-item]

    def test_hardening_flags_are_applied(self, repo_builder):
        runner = GitRunner(repo_builder.path)
        argv = runner._base_argv()
        assert "--no-optional-locks" in argv
        assert "--no-pager" in argv
        for setting in HARDENING_CONFIG:
            assert setting in argv

    def test_dangerous_config_is_neutralised(self, repo_builder):
        """A repo-local fsmonitor/external-diff must not be honoured."""

        runner = GitRunner(repo_builder.path)
        argv = runner._base_argv()
        assert "core.fsmonitor=" in argv
        assert "credential.helper=" in argv
        assert "core.hooksPath=/dev/null" in argv

    def test_diff_safety_flags_are_injected(self, repo_builder):
        from supplytrace.core.git_command import GitRunner as _R

        assert _R._harden_subcommand(["log", "-p"]) == [
            "log", "--no-ext-diff", "--no-textconv", "-p",
        ]
        assert _R._harden_subcommand(["diff", "HEAD"])[:3] == [
            "diff", "--no-ext-diff", "--no-textconv",
        ]
        assert _R._harden_subcommand(["blame", "f.py"]) == [
            "blame", "--no-textconv", "f.py",
        ]
        # An unsafe flag from a caller is stripped, not merely overridden.
        assert "--ext-diff" not in _R._harden_subcommand(["log", "-p", "--ext-diff"])
        assert "--textconv" not in _R._harden_subcommand(["blame", "--textconv", "f.py"])
        # Subcommands that accept neither flag are left untouched.
        assert _R._harden_subcommand(["rev-parse", "HEAD"]) == ["rev-parse", "HEAD"]
        assert _R._harden_subcommand([]) == []

    def test_hostile_repo_with_external_diff_still_analyses(self, repo_builder, tmp_path):
        """Blocking the attack must not break analysis of the repository."""

        from supplytrace.analyzers.git_analyzer import analyze_repository

        script = tmp_path / "differ.sh"
        script.write_text("#!/bin/sh\nexit 0\n")
        script.chmod(0o755)
        repo_builder.write("a.txt", "one\n")
        repo_builder.commit("first")
        repo_builder.git("config", "diff.external", str(script))

        result = analyze_repository(str(repo_builder.path))
        assert result.stats.commit_count == 1
        assert result.commits[0].file_changes

    def test_repo_local_external_diff_is_not_executed(self, repo_builder, tmp_path):
        """End-to-end: a hostile diff.external must never run."""

        marker = tmp_path / "pwned"
        script = tmp_path / "evil.sh"
        script.write_text(f"#!/bin/sh\ntouch {marker}\n")
        script.chmod(0o755)

        repo_builder.write("a.txt", "one\n")
        repo_builder.commit("first")
        repo_builder.write("a.txt", "two\n")
        repo_builder.commit("second")
        repo_builder.git("config", "diff.external", str(script))

        runner = GitRunner(repo_builder.path)
        # `git diff` honours diff.external directly; `git log -p` only does so
        # with --ext-diff. Both paths are exercised so the test cannot pass
        # vacuously just because the chosen command ignores the setting.
        runner.run(["diff", "HEAD~1", "HEAD"])
        assert not marker.exists(), "repo-local diff.external ran via git diff"
        # Even an explicit --ext-diff must not re-enable the driver: Git lets
        # the last flag win, so the unsafe flag is stripped rather than trusted.
        runner.run(["log", "-p", "--ext-diff", "--max-count", "2"])
        assert not marker.exists(), "an explicit --ext-diff re-enabled the driver"

    def test_hostile_diff_external_control_case(self, repo_builder, tmp_path):
        """Control: without the hardening flags the attack really does fire.

        Without this, the test above could pass simply because the chosen git
        command ignores diff.external, proving nothing.
        """

        import subprocess

        marker = tmp_path / "control-pwned"
        script = tmp_path / "evil-control.sh"
        script.write_text(f"#!/bin/sh\ntouch {marker}\n")
        script.chmod(0o755)

        repo_builder.write("a.txt", "one\n")
        repo_builder.commit("first")
        repo_builder.write("a.txt", "two\n")
        repo_builder.commit("second")
        repo_builder.git("config", "diff.external", str(script))

        subprocess.run(
            ["git", "diff", "HEAD~1", "HEAD"],
            cwd=repo_builder.path,
            capture_output=True,
            check=False,
        )
        assert marker.exists(), (
            "control failed: diff.external did not fire even unhardened, so the "
            "hardening test would be vacuous"
        )

    def test_failed_command_raises(self, repo_builder):
        runner = GitRunner(repo_builder.path)
        with pytest.raises(GitCommandError):
            runner.run(["cat-file", "-p", "0" * 40])

    def test_check_false_returns_result(self, repo_builder):
        runner = GitRunner(repo_builder.path)
        result = runner.run(["cat-file", "-p", "0" * 40], check=False)
        assert result.returncode != 0

    def test_timeout_kills_the_process_and_raises(self, repo_builder, monkeypatch):
        """A hung git invocation must be killed, not waited on forever."""

        import subprocess as sp

        killed: list[bool] = []
        real_communicate = sp.Popen.communicate

        def fake_communicate(self, *args, **kwargs):
            if kwargs.get("timeout") is not None:
                raise sp.TimeoutExpired(cmd="git", timeout=0.01)
            return real_communicate(self, *args, **kwargs)

        def fake_kill(self):
            killed.append(True)
            self.terminate()

        monkeypatch.setattr(sp.Popen, "communicate", fake_communicate)
        monkeypatch.setattr(sp.Popen, "kill", fake_kill)

        runner = GitRunner(repo_builder.path, AnalysisConfig(git_timeout_seconds=0.01))
        with pytest.raises(GitTimeoutError):
            runner.run(["log", "--all"])
        assert killed, "timed-out git process was not killed"

    def test_output_size_limit_is_enforced(self, sample_repo):
        from supplytrace.core.errors import GitOutputTooLargeError

        runner = GitRunner(sample_repo.path, AnalysisConfig(max_git_output_bytes=1))
        with pytest.raises(GitOutputTooLargeError):
            runner.run(["log", "--all", "--format=%H"])

    def test_missing_repo_path_raises(self, tmp_path):
        with pytest.raises(RepositoryPathError):
            GitRunner(tmp_path / "nope")

    def test_has_commits_false_on_empty_repo(self, repo_builder):
        assert GitRunner(repo_builder.path).has_commits() is False
