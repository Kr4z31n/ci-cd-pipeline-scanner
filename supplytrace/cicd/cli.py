"""Command line interface for the CI/CD attack detector.

Three commands:

``scan``     findings, attack paths, and optionally the LLM correlation
``graph``    build the DAG and export it
``analyze``  the deterministic pass only, in full detail

All of them work offline. The LLM is reached only when ``scan`` is given a key
and not passed ``--no-llm``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence, TextIO

from supplytrace import __version__
from supplytrace.analyzers.git_analyzer import GitAnalyzer
from supplytrace.cicd.evidence.collector import ScanResult, default_rules, scan_repository
from supplytrace.cicd.evidence.models import Severity
from supplytrace.cicd.graph.builder import build_graph
from supplytrace.cicd.graph.correlation import find_attack_paths
from supplytrace.cicd.graph.export import export_all
from supplytrace.cicd.llm.gemini import CorrelationResult, GeminiProvider, correlate
from supplytrace.cicd.reporting import json_report, text
from supplytrace.cicd.rules.history import collect_workflow_history
from supplytrace.core.config import AnalysisConfig
from supplytrace.core.errors import SupplyTraceError
from supplytrace.core.logging import configure_logging

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FINDINGS = 3
"""Returned by --fail-on when findings at or above the threshold exist."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cicd_detector",
        description=(
            "Detect CI/CD supply-chain weaknesses in GitHub Actions workflows, "
            "build an attack-path DAG, and optionally correlate it with Gemini."
        ),
    )
    parser.add_argument("--version", action="version", version=f"cicd_detector {__version__}")
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="Increase log verbosity (-v info, -vv debug). Logs go to stderr.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("repository", help="Path to a repository checkout.")
        sub.add_argument(
            "--no-history",
            action="store_true",
            help="Skip Git history analysis (workflow files only).",
        )
        sub.add_argument(
            "--max-commits",
            type=int,
            default=500,
            help="Commits to read for history (default: %(default)s, 0 for all).",
        )
        sub.add_argument(
            "--allow-dubious-ownership",
            action="store_true",
            help=(
                "Analyse a repository owned by another user. Only use this if "
                "you trust that owner: repository-local Git config can execute "
                "commands."
            ),
        )

    scan = subparsers.add_parser(
        "scan",
        help="Find weaknesses, build attack paths, and report.",
        description=(
            "The main command. Parses every workflow, runs the rule engine, "
            "builds the attack graph, searches it for known attack patterns, and "
            "optionally asks Gemini to correlate the result."
        ),
    )
    add_common(scan)
    scan.add_argument(
        "--no-llm", action="store_true",
        help="Skip the LLM correlation step entirely. Everything else is unchanged.",
    )
    scan.add_argument(
        "--model", default=None,
        help="Gemini model to use (default: %(default)s).",
    )
    scan.add_argument(
        "--format", choices=("text", "json", "markdown"), default="text",
        help="Output format (default: %(default)s).",
    )
    scan.add_argument(
        "--output", metavar="PATH",
        help="Write the report to PATH instead of stdout.",
    )
    scan.add_argument(
        "--top", type=int, default=15,
        help="Findings to show in text output (default: %(default)s).",
    )
    scan.add_argument(
        "--min-severity",
        choices=[s.value for s in Severity],
        default=None,
        help="Only report findings at or above this severity.",
    )
    scan.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        default=None,
        help=f"Exit {EXIT_FINDINGS} if any finding is at or above this severity.",
    )

    graph = subparsers.add_parser(
        "graph",
        help="Build the attack DAG and export it.",
        description=(
            "Writes attack_graph.json, attack_graph.dot and attack_graph.graphml. "
            "Render the DOT file with: dot -Tsvg attack_graph.dot -o graph.svg"
        ),
    )
    add_common(graph)
    graph.add_argument(
        "--output-dir", default=".", metavar="DIR",
        help="Directory to write the exports into (default: %(default)s).",
    )
    graph.add_argument(
        "--max-paths", type=int, default=25,
        help="Maximum attack paths to search for (default: %(default)s).",
    )

    analyze = subparsers.add_parser(
        "analyze",
        help="Deterministic analysis in full detail, no graph, no LLM.",
        description=(
            "Every finding with its evidence, remediation and references. Useful "
            "for reviewing the rule engine's output on its own."
        ),
    )
    add_common(analyze)
    analyze.add_argument(
        "--rule", action="append", default=None, metavar="RULE_ID",
        help="Only show findings from this rule (repeatable).",
    )
    analyze.add_argument(
        "--format", choices=("text", "json"), default="text",
        help="Output format (default: %(default)s).",
    )

    rules = subparsers.add_parser(
        "rules", help="List the detection rules and what each one looks for."
    )
    rules.add_argument(
        "--explain", metavar="RULE_ID", default=None,
        help="Show the full rationale for one rule.",
    )
    return parser


# -- shared pipeline -----------------------------------------------------------


def _run_scan(args: argparse.Namespace) -> ScanResult:
    """Parse workflows, collect history, and run every rule."""

    repo_path = args.repository
    if not Path(repo_path).exists():
        raise SupplyTraceError(f"path does not exist: {repo_path}")

    history = None
    workflow_history = None

    if not getattr(args, "no_history", False):
        max_commits = getattr(args, "max_commits", 500)
        config = AnalysisConfig(
            max_commits=None if max_commits == 0 else max_commits,
            allow_dubious_ownership=getattr(args, "allow_dubious_ownership", False),
        )
        try:
            # Reuses SupplyTrace's existing analyzer rather than re-reading Git.
            history = GitAnalyzer(repo_path, config).analyze()
            workflow_history = collect_workflow_history(repo_path, history)
        except SupplyTraceError as exc:
            # A directory that is not a Git repository is a perfectly valid
            # scan target; the workflow rules do not need history.
            print(
                f"note: Git history unavailable ({exc}). "
                f"Workflow analysis continues without it.",
                file=sys.stderr,
            )

    return scan_repository(
        repo_path, history=history, workflow_history=workflow_history
    )


def _filter_findings(result: ScanResult, minimum: str | None) -> ScanResult:
    if not minimum:
        return result
    threshold = Severity(minimum).rank
    result.findings = [f for f in result.findings if f.severity.rank <= threshold]
    return result


def _write(text_body: str, destination: str | None, out: TextIO) -> None:
    if not destination:
        print(text_body, file=out)
        return
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text_body, encoding="utf-8")
    print(f"report written to {path}", file=sys.stderr)


# -- commands ------------------------------------------------------------------


def command_scan(args: argparse.Namespace, out: TextIO) -> int:
    result = _filter_findings(_run_scan(args), args.min_severity)

    graph = build_graph(result)
    paths = find_attack_paths(graph)

    correlation: CorrelationResult | None = None
    if not args.no_llm:
        provider = GeminiProvider(model=args.model) if args.model else GeminiProvider()
        correlation = correlate(result, graph, paths, provider=provider)

    if args.format == "json":
        payload = json.dumps(
            json_report.build_report(
                result, graph=graph, paths=paths, correlation=correlation
            ),
            indent=2,
            default=str,
        )
        _write(payload, args.output, out)
    elif args.format == "markdown":
        _write(
            json_report.render_markdown(
                result, graph=graph, paths=paths, correlation=correlation
            ),
            args.output,
            out,
        )
    else:
        if args.output:
            from io import StringIO

            buffer = StringIO()
            text.render_scan(
                result, buffer, graph=graph, paths=paths,
                correlation=correlation, top=args.top,
            )
            _write(buffer.getvalue(), args.output, out)
        else:
            text.render_scan(
                result, out, graph=graph, paths=paths,
                correlation=correlation, top=args.top,
            )

    if args.fail_on:
        threshold = Severity(args.fail_on).rank
        if any(f.severity.rank <= threshold for f in result.findings):
            return EXIT_FINDINGS
    return EXIT_OK


def command_graph(args: argparse.Namespace, out: TextIO) -> int:
    result = _run_scan(args)
    graph = build_graph(result)
    paths = find_attack_paths(graph, max_paths=args.max_paths)
    written = export_all(graph, args.output_dir, paths)

    print(f"attack graph: {len(graph.nodes)} nodes, {len(graph.edges)} edges", file=out)
    print(f"attack paths: {len(paths)}", file=out)
    if graph.rejected_edges:
        print(
            f"edges refused for lack of evidence: {len(graph.rejected_edges)}",
            file=out,
        )
    for fmt, path in written.items():
        print(f"  {fmt:9} {path}", file=out)
    print(
        "\nRender the diagram with:\n"
        f"  dot -Tsvg {Path(args.output_dir) / 'attack_graph.dot'} -o attack_graph.svg",
        file=out,
    )
    return EXIT_OK


def command_analyze(args: argparse.Namespace, out: TextIO) -> int:
    result = _run_scan(args)

    if args.rule:
        wanted = set(args.rule)
        result.findings = [f for f in result.findings if f.rule_id in wanted]

    if args.format == "json":
        print(
            json.dumps(json_report.build_report(result), indent=2, default=str),
            file=out,
        )
        return EXIT_OK

    print("=" * 74, file=out)
    print("DETERMINISTIC ANALYSIS", file=out)
    print("=" * 74, file=out)
    print(f"\nrepository : {result.repo_path}", file=out)
    print(f"findings   : {len(result.findings)}", file=out)

    for finding in result.findings:
        print("\n" + "-" * 74, file=out)
        print(
            f"{finding.id}  {finding.severity.value}  {finding.rule_id}  "
            f"confidence={finding.confidence:.2f}  {finding.state.value}",
            file=out,
        )
        print(f"  {finding.title}", file=out)
        print(f"  location   : {finding.location}", file=out)
        if finding.job:
            print(f"  job/step   : {finding.job} / {finding.step or '-'}", file=out)
        if finding.commit:
            print(f"  commit     : {finding.commit[:12]}", file=out)
        print(f"\n  {finding.description}", file=out)
        if finding.evidence:
            print("\n  evidence:", file=out)
            for item in finding.evidence:
                print(f"    {item.describe()}", file=out)
        if finding.remediation:
            print(f"\n  remediation:\n    {finding.remediation}", file=out)
        for reference in finding.references:
            print(f"    see: {reference}", file=out)

    return EXIT_OK


def command_rules(args: argparse.Namespace, out: TextIO) -> int:
    rules = default_rules()

    if args.explain:
        rule = next((r for r in rules if r.id == args.explain), None)
        if rule is None:
            print(f"error: no rule with id {args.explain!r}", file=sys.stderr)
            return EXIT_ERROR
        print(f"{rule.id}\n{'=' * len(rule.id)}\n", file=out)
        print(f"{rule.name}\n", file=out)
        print(rule.rationale, file=out)
        for reference in rule.references:
            print(f"\n  see: {reference}", file=out)
        return EXIT_OK

    print(f"{len(rules)} detection rules:\n", file=out)
    for rule in rules:
        print(f"  {rule.id:26} {rule.name}", file=out)
    print("\nUse --explain RULE_ID for the reasoning behind one.", file=out)
    return EXIT_OK


def main(argv: Sequence[str] | None = None, out: TextIO | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    stream = out if out is not None else sys.stdout
    configure_logging(args.verbose)

    commands = {
        "scan": command_scan,
        "graph": command_graph,
        "analyze": command_analyze,
        "rules": command_rules,
    }

    try:
        handler = commands.get(args.command)
        if handler is None:  # pragma: no cover - argparse enforces the choices
            parser.error(f"unknown command: {args.command}")
            return EXIT_ERROR
        return handler(args, stream)
    except SupplyTraceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:  # pragma: no cover - piping into head
        return EXIT_OK
    except KeyboardInterrupt:  # pragma: no cover
        print("interrupted", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
