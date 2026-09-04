"""Command line interface for SupplyTrace.

Phase 1 exposes a single command::

    python -m supplytrace analyze /path/to/repository

Human-readable output goes to stdout; diagnostics go to stderr, so
``--json -`` can be piped safely.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence, TextIO

from supplytrace import __version__
from supplytrace.analyzers.git_analyzer import GitAnalyzer
from supplytrace.analyzers.signal_analyzer import rank_commits
from supplytrace.core.config import AnalysisConfig
from supplytrace.core.errors import SupplyTraceError
from supplytrace.core.logging import configure_logging
from supplytrace.models.file import ChangeStatus
from supplytrace.models.repository import RefKind, RepositoryAnalysis
from supplytrace.models.signal import CommitReviewPriority

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="supplytrace",
        description=(
            "SupplyTrace - software supply chain provenance and attack "
            "traceability. Phase 1: Git repository analysis."
        ),
    )
    parser.add_argument("--version", action="version", version=f"supplytrace {__version__}")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase log verbosity (-v info, -vv debug). Logs go to stderr.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser(
        "analyze",
        help="Analyse a Git repository's history, authors and file changes.",
        description=(
            "Read a repository's commits, branches and per-commit file changes. "
            "The repository is only ever read, never executed."
        ),
    )
    analyze.add_argument("repository", help="Path to a Git repository.")
    analyze.add_argument(
        "--json",
        metavar="PATH",
        help="Write the full analysis as JSON to PATH ('-' for stdout).",
    )
    analyze.add_argument(
        "--max-commits",
        type=int,
        default=AnalysisConfig().max_commits,
        help="Maximum commits to read (default: %(default)s). Use 0 for no limit.",
    )
    analyze.add_argument(
        "--refs",
        choices=("all", "head"),
        default="all",
        help="Walk every ref or only HEAD (default: %(default)s).",
    )
    analyze.add_argument(
        "--no-renames",
        action="store_true",
        help="Disable Git rename detection.",
    )
    analyze.add_argument(
        "--detect-copies",
        action="store_true",
        help="Enable copy detection (slower on large histories).",
    )
    analyze.add_argument(
        "--rename-threshold",
        type=int,
        default=AnalysisConfig().rename_threshold,
        help="Rename similarity threshold, 1-100 (default: %(default)s).",
    )
    analyze.add_argument(
        "--diff-merges",
        choices=("first-parent", "off"),
        default="first-parent",
        help=(
            "How to record file changes for merge commits (default: %(default)s). "
            "'first-parent' captures what a merge introduced into its branch."
        ),
    )
    analyze.add_argument(
        "--timeout",
        type=float,
        default=AnalysisConfig().git_timeout_seconds,
        help="Per-git-command timeout in seconds (default: %(default)s).",
    )
    analyze.add_argument(
        "--allow-dubious-ownership",
        action="store_true",
        help=(
            "Analyse a repository owned by another user. Only use this if you "
            "trust that owner: repository-local Git config can execute commands."
        ),
    )
    analyze.add_argument(
        "--top",
        type=int,
        default=10,
        help="How many rows to show in each summary table (default: %(default)s).",
    )

    investigate = subparsers.add_parser(
        "investigate",
        help="Rank commits by supply-chain review priority.",
        description=(
            "Order commits by the structural signals they carry, so an "
            "investigator knows which to read first. This is a reading order, "
            "not a finding of compromise."
        ),
    )
    investigate.add_argument("repository", help="Path to a Git repository.")
    investigate.add_argument(
        "--top", type=int, default=5,
        help="How many commits to show (default: %(default)s). Use 0 for all.",
    )
    investigate.add_argument(
        "--json", metavar="PATH",
        help="Write the ranking as JSON to PATH ('-' for stdout).",
    )
    investigate.add_argument(
        "--max-commits", type=int, default=AnalysisConfig().max_commits,
        help="Maximum commits to read (default: %(default)s). Use 0 for no limit.",
    )
    investigate.add_argument(
        "--allow-dubious-ownership", action="store_true",
        help="Analyse a repository owned by another user.",
    )

    show = subparsers.add_parser(
        "commit",
        help="Show full provenance for one commit.",
        description="Everything SupplyTrace observed about a single commit.",
    )
    show.add_argument("repository", help="Path to a Git repository.")
    show.add_argument("sha", help="Full or abbreviated commit SHA.")
    show.add_argument(
        "--max-commits", type=int, default=AnalysisConfig().max_commits,
        help="Maximum commits to read (default: %(default)s). Use 0 for no limit.",
    )
    show.add_argument(
        "--allow-dubious-ownership", action="store_true",
        help="Analyse a repository owned by another user.",
    )
    return parser


def config_from_args(args: argparse.Namespace) -> AnalysisConfig:
    """Build an AnalysisConfig from whichever flags the subcommand defines."""

    defaults = AnalysisConfig()
    max_commits = getattr(args, "max_commits", defaults.max_commits)
    return AnalysisConfig(
        max_commits=None if max_commits == 0 else max_commits,
        include_all_refs=getattr(args, "refs", "all") == "all",
        detect_renames=not getattr(args, "no_renames", False),
        rename_threshold=getattr(args, "rename_threshold", defaults.rename_threshold),
        detect_copies=getattr(args, "detect_copies", False),
        diff_merges=getattr(args, "diff_merges", defaults.diff_merges),
        git_timeout_seconds=getattr(args, "timeout", defaults.git_timeout_seconds),
        allow_dubious_ownership=getattr(args, "allow_dubious_ownership", False),
    )


# -- rendering ----------------------------------------------------------------


def _heading(title: str, out: TextIO) -> None:
    print(f"\n{title}", file=out)
    print("-" * len(title), file=out)


def render_analysis(analysis: RepositoryAnalysis, out: TextIO, top: int = 10) -> None:
    repo = analysis.repository
    stats = analysis.stats

    print("=" * 68, file=out)
    print("SupplyTrace - Repository Analysis (Phase 1)", file=out)
    print("=" * 68, file=out)

    _heading("REPOSITORY", out)
    print(f"  path              : {repo.path}", file=out)
    print(f"  git dir           : {repo.git_dir}", file=out)
    print(f"  bare              : {repo.is_bare}", file=out)
    print(f"  shallow           : {repo.is_shallow}", file=out)
    print(f"  HEAD              : {repo.head_ref or '(detached)'} @ {(repo.head_sha or '-')[:12]}", file=out)
    print(f"  default branch    : {repo.default_branch_guess or '(unknown)'}", file=out)
    print(f"  git version       : {repo.git_version}", file=out)
    for name, url in repo.remotes.items():
        print(f"  remote {name:11}: {url}", file=out)

    _heading("HISTORY", out)
    span = "(no commits)"
    if stats.first_commit_at and stats.last_commit_at:
        span = f"{stats.first_commit_at.date()} .. {stats.last_commit_at.date()}"
    print(f"  commits           : {stats.commit_count}  ({stats.merge_commit_count} merges, {stats.root_commit_count} root)", file=out)
    print(f"  date span         : {span}", file=out)
    print(f"  authors           : {stats.author_count}   committers: {stats.committer_count}", file=out)
    print(f"  branches / tags   : {stats.branch_count} / {stats.tag_count}", file=out)
    print(f"  file changes      : {stats.file_change_count} across {stats.distinct_path_count} distinct paths", file=out)
    print(f"  lines             : +{stats.total_additions} / -{stats.total_deletions}", file=out)
    print(f"  renames / binary  : {stats.rename_count} / {stats.binary_change_count}", file=out)
    if stats.commit_limit_reached:
        print("  NOTE              : commit limit reached - history is truncated", file=out)

    _heading("SUPPLY CHAIN TOUCHPOINTS", out)
    print(f"  commits touching workflow files    : {stats.commits_touching_workflows}", file=out)
    print(f"  commits touching dependency files  : {stats.commits_touching_dependencies}", file=out)
    if stats.category_counts:
        print("  changed-file categories:", file=out)
        for category, count in sorted(
            stats.category_counts.items(), key=lambda kv: (-kv[1], kv[0].value)
        ):
            print(f"    {category.value:22} {count}", file=out)

    _heading(f"TOP AUTHORS (by commits, showing {min(top, len(analysis.authors))})", out)
    if not analysis.authors:
        print("  (none)", file=out)
    for author in analysis.authors[:top]:
        label = f"{author.name} <{author.email}>"
        print(
            f"  {label:44.44} {author.commit_count:5} commits  "
            f"+{author.additions}/-{author.deletions}  files={author.files_touched}",
            file=out,
        )
        if author.workflow_commit_count or author.dependency_commit_count:
            print(
                f"  {'':44} workflow-commits={author.workflow_commit_count} "
                f"dependency-commits={author.dependency_commit_count}",
                file=out,
            )

    branches = [ref for ref in analysis.branches if ref.kind is not RefKind.TAG]
    _heading(f"REFS ({len(branches)} branches, {stats.tag_count} tags)", out)
    for ref in branches[:top]:
        marker = "*" if ref.is_head else " "
        print(f"  {marker} {ref.name:40.40} {ref.target_sha[:12]}  [{ref.kind.value}]", file=out)
    if len(branches) > top:
        print(f"    ... {len(branches) - top} more", file=out)

    _heading(f"RECENT COMMITS (showing {min(top, len(analysis.commits))})", out)
    for commit in analysis.commits[:top]:
        kind = " [merge]" if commit.is_merge else ""
        print(
            f"  {commit.short_sha}  {commit.timestamp.date()}  "
            f"{commit.author_name[:20]:20}  {commit.subject[:44]}{kind}",
            file=out,
        )
        for change in commit.file_changes[:5]:
            counts = (
                "binary"
                if change.is_binary
                else f"+{change.additions or 0}/-{change.deletions or 0}"
            )
            detail = f"    {change.status.value:12} {counts:12} {change.path}"
            if change.status in {ChangeStatus.RENAMED, ChangeStatus.COPIED}:
                detail += f"  (from {change.old_path}, similarity={change.similarity}%)"
            print(detail, file=out)
        if len(commit.file_changes) > 5:
            print(f"    ... {len(commit.file_changes) - 5} more files", file=out)

    if analysis.anomalies:
        _heading(f"ANOMALIES ({len(analysis.anomalies)})", out)
        print(
            "  Reported rather than hidden: an unreadable record is a different\n"
            "  answer from an absent one.",
            file=out,
        )
        for anomaly in analysis.anomalies[:top]:
            print(f"  [{anomaly.stage}] {anomaly.detail}", file=out)
        if len(analysis.anomalies) > top:
            print(f"  ... {len(analysis.anomalies) - top} more", file=out)

    print(f"\nCompleted in {analysis.duration_seconds:.2f}s", file=out)


def render_investigation(
    analysis: RepositoryAnalysis,
    ranked: list[CommitReviewPriority],
    out: TextIO,
    top: int = 5,
) -> None:
    """Render the review-priority ordering."""

    print("=" * 68, file=out)
    print("SupplyTrace - Investigation: review priority", file=out)
    print("=" * 68, file=out)
    print(f"\n  repository   : {analysis.repository.path}", file=out)
    print(
        f"  scope        : {analysis.stats.commit_count} commits, "
        f"{analysis.stats.author_count} contributors",
        file=out,
    )
    print(f"  with signals : {len(ranked)}", file=out)

    if not ranked:
        print("\n  No supply-chain signals found in this history.", file=out)
        return

    shown = ranked if top <= 0 else ranked[:top]
    print(
        "\n  Commits are ordered by the structural signals they carry.\n"
        "  Each signal below is an OBSERVED fact read from Git.\n"
        "  The ORDERING is a heuristic (INFERRED) - a reading order, not a\n"
        "  finding of compromise. Read the diff before drawing a conclusion.",
        file=out,
    )

    for position, item in enumerate(shown, start=1):
        print("\n" + "-" * 68, file=out)
        marker = ">>" if position == 1 else "  "
        print(
            f"{marker} #{position}  score {item.score}   {item.short_sha}   "
            f"{item.timestamp[:16].replace('T', ' ')}",
            file=out,
        )
        print(f"      {item.author_name} <{item.author_email}>", file=out)
        print(f'      "{item.subject}"', file=out)
        print("      signals:", file=out)
        for hit in sorted(item.hits, key=lambda h: -h.weight):
            print(f"        [{hit.weight}] {hit.description}", file=out)
            for path in hit.paths:
                print(f"              {path}", file=out)

    print("\n" + "-" * 68, file=out)
    if len(ranked) > len(shown):
        print(f"  ... {len(ranked) - len(shown)} more commits with signals", file=out)
    top_item = ranked[0]
    print(
        f"\n  Start with {top_item.short_sha}. To see everything observed about it:\n"
        f"    supplytrace commit {analysis.repository.path} {top_item.short_sha}\n"
        f"  Then read the change itself:\n"
        f"    git -C {analysis.repository.path} show {top_item.short_sha}",
        file=out,
    )


def render_commit(
    analysis: RepositoryAnalysis, commit, ranked: list[CommitReviewPriority], out: TextIO
) -> None:
    """Render everything observed about one commit."""

    print("=" * 68, file=out)
    print(f"SupplyTrace - Commit {commit.short_sha}", file=out)
    print("=" * 68, file=out)

    _heading("IDENTITY", out)
    print(f"  sha        : {commit.commit_sha}", file=out)
    print(f"  author     : {commit.author_name} <{commit.author_email}>", file=out)
    print(f"  authored   : {commit.timestamp.isoformat()}", file=out)
    print(f"  committer  : {commit.committer_name} <{commit.committer_email}>", file=out)
    if commit.committed_timestamp:
        print(f"  committed  : {commit.committed_timestamp.isoformat()}", file=out)
    if (commit.author_name, commit.author_email) != (
        commit.committer_name, commit.committer_email
    ):
        print("  NOTE       : author and committer differ", file=out)
    print(
        "\n  A Git identity is self-asserted. This is what the commit claims,\n"
        "  not proof of who acted.",
        file=out,
    )

    _heading("MESSAGE", out)
    for line in (commit.message or "(empty)").splitlines() or ["(empty)"]:
        print(f"  {line}", file=out)

    _heading("POSITION IN HISTORY", out)
    print(f"  merge      : {commit.is_merge}", file=out)
    print(f"  root       : {commit.is_root}", file=out)
    if commit.parent_commits:
        for index, parent in enumerate(commit.parent_commits):
            label = "first parent" if index == 0 else f"parent {index + 1}"
            print(f"  {label:11}: {parent[:12]}", file=out)

    _heading(f"FILES CHANGED ({len(commit.file_changes)})", out)
    if not commit.file_changes:
        print("  (none)", file=out)
    for change in commit.file_changes:
        counts = "binary" if change.is_binary else f"+{change.additions or 0}/-{change.deletions or 0}"
        print(
            f"  {change.status.value:12} {counts:12} {change.category.value:22} {change.path}",
            file=out,
        )
        if change.old_path:
            print(
                f"  {'':12} {'':12} from {change.old_path} "
                f"(similarity {change.similarity}%, confidence "
                f"{change.evidence.confidence.value if change.evidence else 'UNKNOWN'})",
                file=out,
            )

    priority = next((r for r in ranked if r.commit_sha == commit.commit_sha), None)
    if priority:
        _heading(f"REVIEW SIGNALS (score {priority.score})", out)
        for hit in sorted(priority.hits, key=lambda h: -h.weight):
            print(f"  [{hit.weight}] {hit.description}", file=out)
        print(f"\n  Ranking evidence: {priority.ranking_evidence().describe()}", file=out)
    else:
        _heading("REVIEW SIGNALS", out)
        print("  none", file=out)

    _heading("VERIFY THIS YOURSELF", out)
    print(f"  git -C {analysis.repository.path} show {commit.short_sha}", file=out)


def _write_json(analysis: RepositoryAnalysis, destination: str, out: TextIO) -> None:
    payload = analysis.model_dump_json(indent=2)
    if destination == "-":
        print(payload, file=out)
        return
    path = Path(destination).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    print(f"\nJSON report written to {path}", file=sys.stderr)


# -- commands -----------------------------------------------------------------


def command_analyze(args: argparse.Namespace, out: TextIO) -> int:
    config = config_from_args(args)
    analysis = GitAnalyzer(args.repository, config).analyze()

    if args.json == "-":
        _write_json(analysis, "-", out)
        return EXIT_OK

    render_analysis(analysis, out, top=args.top)
    if args.json:
        _write_json(analysis, args.json, out)
    return EXIT_OK


def command_investigate(args: argparse.Namespace, out: TextIO) -> int:
    analysis = GitAnalyzer(args.repository, config_from_args(args)).analyze()
    ranked = rank_commits(analysis)

    if args.json:
        payload = json.dumps(
            [item.model_dump(mode="json") for item in ranked], indent=2
        )
        if args.json == "-":
            print(payload, file=out)
        else:
            path = Path(args.json).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(payload, encoding="utf-8")
            print(f"JSON ranking written to {path}", file=sys.stderr)
        return EXIT_OK

    render_investigation(analysis, ranked, out, top=args.top)
    return EXIT_OK


def command_commit(args: argparse.Namespace, out: TextIO) -> int:
    analysis = GitAnalyzer(args.repository, config_from_args(args)).analyze()
    commit = analysis.commit(args.sha)
    if commit is None:
        print(
            f"error: no commit matching {args.sha!r} in the analysed history.\n"
            "Hint: an abbreviated SHA must be unambiguous, and the commit must "
            "be within --max-commits.",
            file=sys.stderr,
        )
        return EXIT_ERROR
    render_commit(analysis, commit, rank_commits(analysis), out)
    return EXIT_OK


def main(argv: Sequence[str] | None = None, out: TextIO | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    stream = out if out is not None else sys.stdout
    configure_logging(args.verbose)

    try:
        if args.command == "analyze":
            return command_analyze(args, stream)
        if args.command == "investigate":
            return command_investigate(args, stream)
        if args.command == "commit":
            return command_commit(args, stream)
    except SupplyTraceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:  # pragma: no cover
        print("interrupted", file=sys.stderr)
        return EXIT_ERROR

    parser.error(f"unknown command: {args.command}")
    return EXIT_USAGE
