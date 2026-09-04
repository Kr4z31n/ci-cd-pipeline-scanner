"""Build the evidence package sent to the model.

The rule the spec sets is that the LLM correlates, it does not scan. So it never
receives the repository. It receives what the deterministic pass already
established: the findings with their ids, the workflow snippets those findings
point at, the attack paths the graph found, and the Git history around them.

Two consequences shape everything here:

* the model can only cite ids that appear in this package, which is what makes
  :func:`~supplytrace.cicd.llm.schemas.validate_response` able to catch
  invention; and
* the package is bounded. A repository with 400 findings would otherwise
  produce a prompt that is mostly INFO noise, and the model would correlate the
  noise. Findings are selected by severity, and snippets are capped.
"""

from __future__ import annotations

from dataclasses import dataclass

from supplytrace.cicd.evidence.collector import ScanResult
from supplytrace.cicd.evidence.models import Finding, Severity
from supplytrace.cicd.graph.builder import AttackGraph
from supplytrace.cicd.graph.correlation import AttackPath
from supplytrace.cicd.llm.schemas import RESPONSE_TEMPLATE

SYSTEM_PROMPT = """\
You are a CI/CD security analyst reviewing the output of a static analyser that \
has already examined a repository's GitHub Actions workflows and Git history.

Your job is correlation, not detection. You are given findings that were \
produced deterministically, each with an id, a location, and a verbatim source \
snippet. Decide whether they combine into a coherent attack chain, and explain \
it.

Rules you must follow exactly:

1. Ground every statement in the evidence provided. Cite finding ids.
2. Never invent a file, line, commit, command, permission, secret, action or \
step that does not appear in the context below. If something is not there, it \
does not exist for the purposes of your answer.
3. Do not claim an attack has occurred. The evidence describes configuration \
that permits an attack; it cannot show that anyone exploited it. Use \
POTENTIAL_ATTACK_CHAIN, never a past-tense claim of compromise.
4. If the findings do not chain, say ISOLATED_WEAKNESSES. A short honest answer \
is worth more than an invented narrative.
5. State what you cannot determine in missing_evidence.
6. Reply with a single JSON object and nothing else.\
"""


@dataclass
class EvidencePackage:
    """The prompt and the exact ids it contains."""

    prompt: str
    allowed_ids: set[str]
    finding_count: int
    path_count: int

    def __len__(self) -> int:
        return len(self.prompt)


#: Severity order in which findings are admitted to the prompt.
_PRIORITY = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)


def select_findings(result: ScanResult, limit: int = 40) -> list[Finding]:
    """The findings worth correlating, most serious first.

    INFO findings are excluded unless nothing else exists: they are inventory
    records, and feeding a model thirty of them invites it to build a story out
    of routine facts.
    """

    chosen: list[Finding] = []
    for severity in _PRIORITY:
        for finding in result.findings:
            if finding.severity is severity:
                chosen.append(finding)
            if len(chosen) >= limit:
                return chosen
    if not chosen:
        chosen = result.findings[:limit]
    return chosen[:limit]


def _render_finding(finding: Finding) -> str:
    lines = [
        f"[{finding.id}] {finding.severity.value} {finding.rule_id} "
        f"(detection confidence {finding.confidence:.2f}, {finding.state.value})",
        f"  where      : {finding.file}:{finding.line}"
        + (f" job={finding.job}" if finding.job else "")
        + (f" step={finding.step}" if finding.step else ""),
        f"  what       : {finding.title}",
        f"  detail     : {finding.description}",
    ]
    if finding.commit:
        lines.append(f"  commit     : {finding.commit[:12]}")
    for item in finding.evidence[:3]:
        snippet = item.snippet.strip()
        if len(snippet) > 200:
            snippet = snippet[:197] + "..."
        lines.append(
            f"  evidence   : {item.file}:{item.line}"
            + (f" ({item.label})" if item.label else "")
            + (f"\n               | {snippet}" if snippet else "")
        )
    return "\n".join(lines)


def _render_path(path: AttackPath) -> str:
    lines = [
        f"[{path.id}] {path.verdict.value} severity={path.severity.value} "
        f"confidence={path.confidence:.2f}",
        f"  pattern    : {path.pattern}",
        f"  reading    : {path.title}",
        f"  entry      : {path.entry_point}",
        f"  impact     : {path.impact}",
        "  route      :",
    ]
    lines.extend(f"      {index}. {step}" for index, step in enumerate(path.narrative, 1))
    if path.justifying_ids:
        lines.append(f"  justified by: {', '.join(path.justifying_ids)}")
    if path.missing:
        lines.append("  not established by the graph:")
        lines.extend(f"      - {item}" for item in path.missing)
    return "\n".join(lines)


def _render_history(result: ScanResult, limit: int = 12) -> str:
    history = result.workflow_history
    if history is None or not history.changes:
        return "No Git history was analysed for this scan."

    lines = ["Workflow-affecting commits, oldest first:"]
    for change in history.ordered()[:limit]:
        lines.append(
            f"  {change.timestamp[:19]}  {change.short_sha}  "
            f"{change.author_name} <{change.author_email}>"
        )
        lines.append(f"      {change.kind.value}: {change.detail}  [{change.path}]")
        if change.subject:
            lines.append(f'      commit subject: "{change.subject}"')
    if len(history.changes) > limit:
        lines.append(f"  ... {len(history.changes) - limit} further changes not listed")
    if history.unreadable:
        lines.append(
            "  NOTE: some commit diffs could not be read: "
            + "; ".join(history.unreadable[:3])
        )
    return "\n".join(lines)


def build_evidence_package(
    result: ScanResult,
    graph: AttackGraph | None = None,
    paths: list[AttackPath] | None = None,
    *,
    finding_limit: int = 40,
    path_limit: int = 6,
) -> EvidencePackage:
    """Assemble the correlation prompt and the ids it is allowed to cite."""

    findings = select_findings(result, finding_limit)
    selected_paths = (paths or [])[:path_limit]
    allowed = {finding.id for finding in findings}
    # A path's justifying ids must be citable even if the finding itself fell
    # below the selection cut, or the model would be told about a chain and
    # then forbidden from referencing what supports it.
    for path in selected_paths:
        allowed.update(path.evidence_ids)

    extra = [
        f
        for f in result.findings
        if f.id in allowed and f.id not in {x.id for x in findings}
    ]

    counts = result.severity_counts()
    sections = [
        "## REPOSITORY",
        f"path: {result.repo_path}",
        f"workflows analysed: {len(result.workflows)} "
        f"({len(result.parse_failures)} could not be parsed)",
        "finding counts by severity: "
        + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"),
        "",
        "## DETERMINISTIC FINDINGS",
        "Each was produced by a rule, with the source snippet it matched.",
        "",
    ]
    sections.extend(_render_finding(f) + "\n" for f in findings + extra)

    sections.append("## ATTACK PATHS FOUND IN THE GRAPH")
    if selected_paths:
        sections.append(
            "The graph builder connected the findings above. These routes exist "
            "in the configuration; the tool has NOT established that any of them "
            "was taken.\n"
        )
        sections.extend(_render_path(p) + "\n" for p in selected_paths)
    else:
        sections.append("No complete attack path was found in the graph.\n")

    sections.append("## GIT HISTORY")
    sections.append(_render_history(result))
    sections.append("")

    sections.append("## YOUR TASK")
    sections.append(
        "Correlate the findings above. Identify the most plausible entry point, "
        "what an attacker would gain, and the order of steps. Cite only the "
        "finding ids listed above; there are no others. If the findings do not "
        "form a chain, say so.\n\n"
        "Respond with exactly this JSON structure:\n"
        f"{RESPONSE_TEMPLATE}"
    )

    return EvidencePackage(
        prompt="\n".join(sections),
        allowed_ids=allowed,
        finding_count=len(findings) + len(extra),
        path_count=len(selected_paths),
    )


__all__ = [
    "EvidencePackage",
    "SYSTEM_PROMPT",
    "build_evidence_package",
    "select_findings",
]
