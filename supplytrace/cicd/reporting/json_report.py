"""JSON and Markdown reports.

The JSON report is the machine contract: findings, paths, graph summary and the
LLM's analysis, each with the evidence behind it. It is what a CI job would gate
on, so it also carries an ``exit_criteria`` block making the counts explicit
rather than requiring the consumer to re-derive them.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from supplytrace import __version__
from supplytrace.cicd.evidence.collector import ScanResult
from supplytrace.cicd.evidence.models import Severity
from supplytrace.cicd.graph.builder import AttackGraph
from supplytrace.cicd.graph.correlation import AttackPath
from supplytrace.cicd.llm.gemini import CorrelationResult


def build_report(
    result: ScanResult,
    *,
    graph: AttackGraph | None = None,
    paths: list[AttackPath] | None = None,
    correlation: CorrelationResult | None = None,
) -> dict[str, Any]:
    """The complete result as a plain dictionary."""

    counts = result.severity_counts()
    report: dict[str, Any] = {
        "format": "supplytrace.cicd-report/1",
        "tool_version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repository": result.repo_path,
        "scope": {
            "workflows_found": len(result.workflows),
            "workflows_parsed": len(result.workflows) - len(result.parse_failures),
            "workflows_unparsed": [
                {"path": w.path, "error": w.parse_error} for w in result.parse_failures
            ],
            "commits_analysed": (
                result.history.stats.commit_count if result.history else 0
            ),
            "workflow_commits": (
                result.history.stats.commits_touching_workflows if result.history else 0
            ),
            "rule_errors": list(result.rule_errors),
        },
        "severity_counts": counts,
        "findings": [
            finding.model_dump(mode="json") for finding in result.findings
        ],
        "attack_paths": [path.to_dict() for path in (paths or [])],
        "exit_criteria": {
            "critical": counts.get(Severity.CRITICAL.value, 0),
            "high": counts.get(Severity.HIGH.value, 0),
            "attack_paths": len(paths or []),
        },
    }

    if graph is not None:
        report["graph"] = {
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "by_type": graph.summary(),
            "rejected_edges": list(graph.rejected_edges),
        }

    if result.workflow_history is not None:
        report["workflow_history"] = [
            {
                "commit": change.commit_sha,
                "short_sha": change.short_sha,
                "author": f"{change.author_name} <{change.author_email}>",
                "timestamp": change.timestamp,
                "subject": change.subject,
                "path": change.path,
                "kind": change.kind.value,
                "detail": change.detail,
            }
            for change in result.workflow_history.ordered()
        ]

    if correlation is not None:
        report["llm"] = {
            "model": correlation.model,
            "skipped_reason": correlation.skipped_reason,
            "errors": list(correlation.errors),
            "hallucinated_ids": list(correlation.hallucinated_ids),
            "findings_sent": correlation.findings_sent,
            "paths_sent": correlation.paths_sent,
            "usage": dict(correlation.usage),
            "analysis": (
                correlation.analysis.model_dump(mode="json")
                if correlation.analysis
                else None
            ),
        }

    return report


def write_json(
    result: ScanResult,
    destination: str | Path,
    *,
    graph: AttackGraph | None = None,
    paths: list[AttackPath] | None = None,
    correlation: CorrelationResult | None = None,
) -> Path:
    """Write the JSON report to ``destination``."""

    payload = build_report(result, graph=graph, paths=paths, correlation=correlation)
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path


def render_markdown(
    result: ScanResult,
    *,
    graph: AttackGraph | None = None,
    paths: list[AttackPath] | None = None,
    correlation: CorrelationResult | None = None,
) -> str:
    """A Markdown report, suitable for a pull request comment."""

    counts = result.severity_counts()
    lines = [
        "# CI/CD security analysis",
        "",
        f"**Repository:** `{result.repo_path}`  ",
        f"**Workflows:** {len(result.workflows) - len(result.parse_failures)}"
        f" of {len(result.workflows)} parsed  ",
        "**Findings:** "
        + (", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none"),
        "",
    ]

    if result.parse_failures:
        lines += [
            "> **Not analysed.** "
            + ", ".join(f"`{w.path}`" for w in result.parse_failures)
            + " could not be parsed, so nothing was checked in them.",
            "",
        ]

    lines += ["## Findings", "", "| Severity | ID | Rule | Location | Finding |", "|---|---|---|---|---|"]
    for finding in result.findings:
        if finding.severity is Severity.INFO:
            continue
        title = finding.title.replace("|", "\\|")
        lines.append(
            f"| {finding.severity.value} | {finding.id} | `{finding.rule_id}` | "
            f"`{finding.location}` | {title} |"
        )
    lines.append("")

    lines += ["## Attack paths", ""]
    if not paths:
        lines.append("No complete attack path was found in the graph.")
    else:
        lines.append(
            "Each route below exists in the configuration. The tool has **not** "
            "established that any of them was taken."
        )
        lines.append("")
        for path in paths:
            lines += [
                f"### {path.id} — {path.title}",
                "",
                f"**{path.severity.value}** · {path.verdict.value} · "
                f"confidence {path.confidence:.2f}",
                "",
                "```",
            ]
            for index, step in enumerate(path.narrative, start=1):
                lines.append(f"{index}. {step}")
            lines += ["```", ""]
            if path.justifying_ids:
                lines += [f"Evidence: {', '.join(path.justifying_ids)}", ""]
            if path.missing:
                lines.append("Not established:")
                lines += [f"- {item}" for item in path.missing]
                lines.append("")

    if correlation is not None and correlation.analysis is not None:
        analysis = correlation.analysis
        lines += [
            "## LLM correlation",
            "",
            f"*Interpretation by {correlation.model}. Not itself evidence.*",
            "",
            f"**Verdict:** {analysis.verdict.value} "
            f"(confidence {analysis.confidence.value})",
            "",
        ]
        if analysis.summary:
            lines += [analysis.summary, ""]
        if analysis.attack_chain:
            lines.append("**Chain:**")
            lines += [f"{i}. {s}" for i, s in enumerate(analysis.attack_chain, 1)]
            lines.append("")
        if analysis.recommended_actions:
            lines.append("**Recommended:**")
            lines += [f"- {s}" for s in analysis.recommended_actions]
            lines.append("")

    return "\n".join(lines)


__all__ = ["build_report", "render_markdown", "write_json"]
