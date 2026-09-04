"""Human-readable report for the terminal.

The layout follows what a reader needs in order: what was scanned, what was
found, how the findings chain, and only then the model's opinion -- clearly
separated, because the first three are derived from the repository and the last
is not.
"""

from __future__ import annotations

from typing import TextIO

from supplytrace.cicd.evidence.collector import ScanResult
from supplytrace.cicd.evidence.models import Finding, Severity
from supplytrace.cicd.graph.builder import AttackGraph
from supplytrace.cicd.graph.correlation import AttackPath
from supplytrace.cicd.llm.gemini import CorrelationResult

WIDTH = 74


def _rule(character: str = "=") -> str:
    return character * WIDTH


def _heading(title: str, out: TextIO) -> None:
    print(f"\n{title}", file=out)
    print("-" * len(title), file=out)


def render_scan(
    result: ScanResult,
    out: TextIO,
    *,
    graph: AttackGraph | None = None,
    paths: list[AttackPath] | None = None,
    correlation: CorrelationResult | None = None,
    top: int = 15,
    show_evidence: bool = True,
) -> None:
    """Render the full scan report."""

    print(_rule(), file=out)
    print("CI/CD SECURITY ANALYSIS", file=out)
    print(_rule(), file=out)

    _render_scope(result, out)
    _render_findings(result, out, top=top, show_evidence=show_evidence)
    if graph is not None:
        _render_graph(graph, out)
    _render_paths(paths or [], result, out)
    if correlation is not None:
        _render_correlation(correlation, out)
    _render_footer(result, out)


def _render_scope(result: ScanResult, out: TextIO) -> None:
    _heading("SCOPE", out)
    print(f"  repository        : {result.repo_path}", file=out)
    print(f"  workflows parsed  : {len(result.workflows) - len(result.parse_failures)}"
          f" of {len(result.workflows)}", file=out)

    if result.history is not None:
        stats = result.history.stats
        print(
            f"  git history       : {stats.commit_count} commits, "
            f"{stats.commits_touching_workflows} touching workflows",
            file=out,
        )
    else:
        print("  git history       : not analysed", file=out)

    if result.parse_failures:
        print(
            f"  NOT ANALYSED      : {len(result.parse_failures)} workflow(s) "
            f"could not be parsed. Their absence below means unchecked, not clean.",
            file=out,
        )
        for workflow in result.parse_failures:
            print(f"                      {workflow.path}: {workflow.parse_error}", file=out)

    if result.rule_errors:
        print(f"  RULE ERRORS       : {len(result.rule_errors)}", file=out)
        for error in result.rule_errors[:5]:
            print(f"                      {error}", file=out)


def _render_findings(
    result: ScanResult, out: TextIO, *, top: int, show_evidence: bool
) -> None:
    counts = result.severity_counts()
    total = len(result.findings)
    summary = "  ".join(
        f"{severity.value}={counts.get(severity.value, 0)}"
        for severity in Severity
        if counts.get(severity.value)
    )
    _heading(f"FINDINGS ({total})", out)
    if not total:
        print("  No findings.", file=out)
        return
    print(f"  {summary}\n", file=out)

    shown = [
        f
        for f in result.findings
        if f.severity is not Severity.INFO
    ][:top]
    if not shown:
        shown = result.findings[:top]

    for finding in shown:
        _render_finding(finding, out, show_evidence=show_evidence)

    remaining = total - len(shown)
    if remaining > 0:
        print(
            f"\n  ... {remaining} further finding(s). Use --format json for all, "
            f"or --top {total} to list them.",
            file=out,
        )


def _render_finding(finding: Finding, out: TextIO, *, show_evidence: bool) -> None:
    print(
        f"  {finding.severity.value:8} {finding.id:5} {finding.rule_id:24} "
        f"{finding.location}",
        file=out,
    )
    print(f"           {finding.title}", file=out)
    if show_evidence and finding.evidence:
        for item in finding.evidence[:2]:
            snippet = item.snippet.strip()
            if len(snippet) > 90:
                snippet = snippet[:87] + "..."
            if snippet:
                print(f"           | {snippet}", file=out)
    print(
        f"           confidence {finding.confidence:.2f} "
        f"({finding.state.value.lower()})",
        file=out,
    )
    print(file=out)


def _render_graph(graph: AttackGraph, out: TextIO) -> None:
    _heading("ATTACK GRAPH", out)
    print(f"  nodes             : {len(graph.nodes)}", file=out)
    print(f"  edges             : {len(graph.edges)}", file=out)
    types = ", ".join(f"{k}={v}" for k, v in graph.summary().items())
    print(f"  node types        : {types}", file=out)
    if graph.rejected_edges:
        print(
            f"  edges refused     : {len(graph.rejected_edges)} "
            f"(no evidence to support them)",
            file=out,
        )


def _render_paths(paths: list[AttackPath], result: ScanResult, out: TextIO) -> None:
    _heading(f"ATTACK PATHS ({len(paths)})", out)
    if not paths:
        print(
            "  No complete attack path was found.\n"
            "  The findings above stand on their own; the graph did not connect\n"
            "  them into a route from an entry point to an asset.",
            file=out,
        )
        return

    print(
        "  Each path below is a route that EXISTS IN THE CONFIGURATION.\n"
        "  The tool has not established that anyone has taken it.\n",
        file=out,
    )

    for path in paths:
        print(_rule("-"), file=out)
        print(
            f"  {path.id}  {path.severity.value}  {path.verdict.value}  "
            f"confidence {path.confidence:.2f}",
            file=out,
        )
        print(f"  {path.title}", file=out)
        print(file=out)
        for index, step in enumerate(path.narrative, start=1):
            connector = "  " if index == 1 else "  ↓ "
            print(f"  {index}. {step}", file=out)
        print(file=out)
        if path.justifying_ids:
            print(f"  evidence  : {', '.join(path.justifying_ids)}", file=out)
        elif path.evidence_ids:
            print(f"  evidence  : {', '.join(path.evidence_ids[:8])}", file=out)
        if path.missing:
            print("  unknown   :", file=out)
            for item in path.missing:
                print(f"              - {item}", file=out)
        print(file=out)


def _render_correlation(correlation: CorrelationResult, out: TextIO) -> None:
    _heading("LLM CORRELATION", out)

    if correlation.skipped_reason:
        print(f"  skipped: {correlation.skipped_reason}", file=out)
        return

    if not correlation.ok:
        print("  The model produced no usable analysis:", file=out)
        for error in correlation.errors:
            print(f"    - {error}", file=out)
        print(
            "\n  The deterministic findings above are unaffected: they were\n"
            "  produced without the model and do not depend on it.",
            file=out,
        )
        return

    print(
        f"  model {correlation.model}, {correlation.findings_sent} findings and "
        f"{correlation.paths_sent} path(s) sent\n"
        f"  This section is the model's INTERPRETATION of the evidence above.\n"
        f"  It is not itself evidence.\n",
        file=out,
    )
    for line in correlation.analysis.render().splitlines():
        print(f"  {line}", file=out)

    if correlation.hallucinated_ids:
        print(
            f"\n  NOTE: the model cited "
            f"{', '.join(correlation.hallucinated_ids)}, which were not in its "
            f"context. Those citations were removed.",
            file=out,
        )
    elif correlation.errors:
        for error in correlation.errors:
            print(f"\n  NOTE: {error}", file=out)


def _render_footer(result: ScanResult, out: TextIO) -> None:
    print(_rule(), file=out)
    print(
        "OBSERVED facts come from the repository. INFERRED judgements and attack\n"
        "paths are the tool's reasoning over them. Verify a finding by opening\n"
        "the file and line it cites.",
        file=out,
    )


__all__ = ["render_scan"]
