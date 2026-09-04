"""Tests for the SupplyTrace command line interface."""

from __future__ import annotations

import io
import json

import pytest

from supplytrace import __version__
from supplytrace.cli import EXIT_ERROR, EXIT_OK, build_parser, config_from_args, main


def run_cli(argv):
    out = io.StringIO()
    code = main(argv, out=out)
    return code, out.getvalue()


class TestArgumentParsing:
    def test_command_is_required(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args([])

    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as exc:
            build_parser().parse_args(["--version"])
        assert exc.value.code == 0
        assert __version__ in capsys.readouterr().out

    def test_defaults_map_to_config(self):
        args = build_parser().parse_args(["analyze", "/tmp"])
        config = config_from_args(args)
        assert config.include_all_refs is True
        assert config.detect_renames is True
        assert config.diff_merges == "first-parent"
        assert config.allow_dubious_ownership is False

    def test_flags_map_to_config(self):
        args = build_parser().parse_args(
            [
                "analyze",
                "/tmp",
                "--max-commits",
                "5",
                "--refs",
                "head",
                "--no-renames",
                "--detect-copies",
                "--rename-threshold",
                "80",
                "--diff-merges",
                "off",
                "--allow-dubious-ownership",
            ]
        )
        config = config_from_args(args)
        assert config.max_commits == 5
        assert config.include_all_refs is False
        assert config.detect_renames is False
        assert config.detect_copies is True
        assert config.rename_threshold == 80
        assert config.diff_merges == "off"
        assert config.allow_dubious_ownership is True

    def test_zero_max_commits_means_unlimited(self):
        args = build_parser().parse_args(["analyze", "/tmp", "--max-commits", "0"])
        assert config_from_args(args).max_commits is None

    def test_invalid_choice_is_rejected(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["analyze", "/tmp", "--refs", "sideways"])


class TestAnalyzeCommand:
    def test_succeeds_and_reports_key_sections(self, sample_repo):
        code, output = run_cli(["analyze", str(sample_repo.path)])
        assert code == EXIT_OK
        for section in (
            "REPOSITORY",
            "HISTORY",
            "SUPPLY CHAIN TOUCHPOINTS",
            "TOP AUTHORS",
            "REFS",
            "RECENT COMMITS",
        ):
            assert section in output

    def test_output_contains_expected_facts(self, sample_repo):
        _, output = run_cli(["analyze", str(sample_repo.path)])
        assert "Alice" in output
        assert "Bob" in output
        assert "commits           : 5" in output
        assert "commits touching workflow files    : 1" in output

    def test_rename_is_shown_with_similarity(self, sample_repo):
        _, output = run_cli(["analyze", str(sample_repo.path), "--top", "20"])
        assert "RENAMED" in output
        assert "similarity=" in output

    def test_json_to_stdout_is_valid_and_only_json(self, sample_repo):
        code, output = run_cli(["analyze", str(sample_repo.path), "--json", "-"])
        assert code == EXIT_OK
        payload = json.loads(output)
        assert payload["stats"]["commit_count"] == 5
        assert payload["tool_version"] == __version__
        assert len(payload["commits"]) == 5

    def test_json_to_file(self, sample_repo, tmp_path):
        target = tmp_path / "nested" / "report.json"
        code, output = run_cli(["analyze", str(sample_repo.path), "--json", str(target)])
        assert code == EXIT_OK
        assert "REPOSITORY" in output
        payload = json.loads(target.read_text())
        assert payload["repository"]["head_ref"] == "main"

    def test_json_report_carries_evidence(self, sample_repo):
        _, output = run_cli(["analyze", str(sample_repo.path), "--json", "-"])
        payload = json.loads(output)
        commit = payload["commits"][0]
        assert commit["evidence"]["source"] == "git log"
        assert commit["evidence"]["state"] == "OBSERVED"

    def test_max_commits_is_honoured(self, sample_repo):
        _, output = run_cli(
            ["analyze", str(sample_repo.path), "--max-commits", "2", "--json", "-"]
        )
        payload = json.loads(output)
        assert payload["stats"]["commit_count"] == 2
        assert payload["stats"]["commit_limit_reached"] is True

    def test_empty_repository_is_handled(self, repo_builder):
        code, output = run_cli(["analyze", str(repo_builder.path)])
        assert code == EXIT_OK
        assert "commits           : 0" in output

    def test_config_is_recorded_in_the_report(self, sample_repo):
        _, output = run_cli(["analyze", str(sample_repo.path), "--json", "-"])
        payload = json.loads(output)
        assert payload["config"]["diff_merges"] == "first-parent"
        assert payload["config"]["rename_threshold"] == 50

    def test_secrets_are_not_written_to_the_report(self, sample_repo):
        sample_repo.git(
            "remote", "add", "origin", "https://u:tokenvalue123@github.com/o/r.git"
        )
        _, output = run_cli(["analyze", str(sample_repo.path), "--json", "-"])
        assert "tokenvalue123" not in output


class TestErrorHandling:
    def test_missing_path_exits_with_error(self, tmp_path, capsys):
        code, _ = run_cli(["analyze", str(tmp_path / "absent")])
        assert code == EXIT_ERROR
        assert "error:" in capsys.readouterr().err

    def test_non_repository_exits_with_error(self, tmp_path, capsys):
        code, _ = run_cli(["analyze", str(tmp_path)])
        assert code == EXIT_ERROR
        assert "not inside a Git repository" in capsys.readouterr().err

    def test_errors_go_to_stderr_not_stdout(self, tmp_path):
        code, output = run_cli(["analyze", str(tmp_path / "absent")])
        assert code == EXIT_ERROR
        assert output == ""


class TestModuleEntryPoint:
    def test_python_dash_m_works(self, sample_repo):
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "-m", "supplytrace", "analyze", str(sample_repo.path)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "SupplyTrace" in result.stdout


class TestInvestigateCommand:
    def test_ranks_and_reports(self, demo_repo):
        code, output = run_cli(["investigate", str(demo_repo)])
        assert code == EXIT_OK
        assert "review priority" in output
        assert "kaito-dev" in output

    def test_top_commit_is_the_planted_one(self, demo_repo):
        _, output = run_cli(["investigate", str(demo_repo), "--top", "1"])
        assert "#1" in output
        assert "kaito-dev" in output
        assert "built AND what it is built from" in output

    def test_ordering_is_labelled_as_a_heuristic(self, demo_repo):
        """The output must not let a reader mistake ranking for a verdict."""

        _, output = run_cli(["investigate", str(demo_repo)])
        assert "not a\n  finding of compromise" in output or "not a finding of compromise" in output
        assert "OBSERVED" in output and "INFERRED" in output

    def test_suggests_the_next_command(self, demo_repo):
        _, output = run_cli(["investigate", str(demo_repo)])
        assert "supplytrace commit" in output
        assert "git -C" in output

    def test_top_zero_shows_everything(self, demo_repo):
        _, all_out = run_cli(["investigate", str(demo_repo), "--top", "0"])
        _, two_out = run_cli(["investigate", str(demo_repo), "--top", "2"])
        assert all_out.count("score ") > two_out.count("score ")

    def test_json_output_is_valid(self, demo_repo):
        code, output = run_cli(["investigate", str(demo_repo), "--json", "-"])
        assert code == EXIT_OK
        payload = json.loads(output)
        assert payload[0]["author_name"] == "kaito-dev"
        assert payload[0]["hits"]

    def test_repository_without_signals_is_handled(self, repo_builder):
        repo_builder.write("src/app.py", "x = 1\n")
        repo_builder.commit("first")
        repo_builder.write("src/app.py", "x = 2\n")
        repo_builder.commit("second")
        code, output = run_cli(["investigate", str(repo_builder.path), "--top", "0"])
        assert code == EXIT_OK
        assert "with signals : 1" in output

    def test_empty_repository_is_handled(self, repo_builder):
        code, output = run_cli(["investigate", str(repo_builder.path)])
        assert code == EXIT_OK
        assert "No supply-chain signals" in output


class TestCommitCommand:
    def test_shows_full_provenance(self, demo_repo):
        code, output = run_cli(["commit", str(demo_repo), "d95c2685eaf3"])
        assert code == EXIT_OK
        for section in ("IDENTITY", "MESSAGE", "POSITION IN HISTORY",
                        "FILES CHANGED", "REVIEW SIGNALS", "VERIFY THIS YOURSELF"):
            assert section in output

    def test_reports_the_self_asserted_identity_caveat(self, demo_repo):
        _, output = run_cli(["commit", str(demo_repo), "d95c2685eaf3"])
        assert "self-asserted" in output

    def test_lists_changed_files_with_categories(self, demo_repo):
        _, output = run_cli(["commit", str(demo_repo), "d95c2685eaf3"])
        assert "WORKFLOW" in output
        assert "LOCKFILE" in output
        assert ".github/workflows/release.yml" in output

    def test_accepts_a_full_sha(self, demo_repo):
        code, out_short = run_cli(["commit", str(demo_repo), "d95c2685eaf3"])
        full = out_short.split("sha        : ")[1].split("\n")[0]
        code2, out_full = run_cli(["commit", str(demo_repo), full])
        assert code == code2 == EXIT_OK

    def test_merge_commit_shows_both_parents(self, demo_repo):
        _, output = run_cli(["investigate", str(demo_repo), "--json", "-"])
        code, merge_out = run_cli(["commit", str(demo_repo), "976e67c4d37d"])
        assert code == EXIT_OK
        assert "first parent" in merge_out
        assert "parent 2" in merge_out

    def test_unknown_sha_exits_with_error(self, demo_repo, capsys):
        code, _ = run_cli(["commit", str(demo_repo), "0" * 12])
        assert code == EXIT_ERROR
        assert "no commit matching" in capsys.readouterr().err

    def test_rename_shows_similarity_and_confidence(self, demo_repo):
        _, output = run_cli(["commit", str(demo_repo), "778e1572d868"])
        assert "similarity" in output
        assert "confidence" in output
