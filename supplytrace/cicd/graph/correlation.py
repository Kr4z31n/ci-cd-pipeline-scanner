"""Find attack paths in the graph, and refuse to overstate them.

The spec names three chains to look for:

A. untrusted PR -> privileged trigger -> checkout -> shell -> secret -> network
B. unpinned action -> runner -> GITHUB_TOKEN -> contents:write -> repository
C. untrusted code -> artifact -> release -> publishing credential

Rather than hard-coding three literal node sequences -- which would break the
moment a workflow expressed the same idea slightly differently -- each pattern
is defined as an ordered set of *roles* plus the evidence it requires. A path
qualifies when it crosses the roles in order and the findings backing it satisfy
the pattern's requirements.

Everything found here is named ``POTENTIAL_ATTACK_PATH``. The graph shows that a
route exists in the configuration; it cannot show that anyone walked it. Calling
it anything stronger would be a claim the evidence does not support, and the
distinction is the whole point of separating observation from inference.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

import networkx as nx

from supplytrace.cicd.evidence.models import Finding, Severity
from supplytrace.cicd.graph.builder import AttackGraph
from supplytrace.cicd.graph.models import EdgeType, Node, NodeRole, NodeType


class PathVerdict(str, Enum):
    """What the tool is willing to say about a path.

    There is deliberately no "CONFIRMED ATTACK" value. A static read of a
    repository cannot establish that an attack occurred; it can only establish
    that the configuration permits one.
    """

    POTENTIAL_ATTACK_PATH = "POTENTIAL_ATTACK_PATH"
    """A complete route exists, backed by findings at each stage."""
    PARTIAL_PATH = "PARTIAL_PATH"
    """Most of a route exists but a stage is missing or unevidenced."""


@dataclass
class AttackPath:
    """One route through the graph, with everything backing it."""

    id: str
    pattern: str
    title: str
    verdict: PathVerdict
    severity: Severity
    confidence: float
    nodes: list[Node]
    evidence_ids: list[str] = field(default_factory=list)
    narrative: list[str] = field(default_factory=list)
    """One line per hop, in the reader's language rather than the graph's."""
    missing: list[str] = field(default_factory=list)
    """What would have to be checked to raise or drop this path."""
    justifying_ids: list[str] = field(default_factory=list)
    """The subset of ``evidence_ids`` whose rules this pattern requires.

    These are the findings that make the chain a chain, as opposed to findings
    that merely happen to sit on a node along it.
    """

    @property
    def entry_point(self) -> str:
        return self.nodes[0].label if self.nodes else ""

    @property
    def impact(self) -> str:
        return self.nodes[-1].label if self.nodes else ""

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "pattern": self.pattern,
            "title": self.title,
            "verdict": self.verdict.value,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 2),
            "entry_point": self.entry_point,
            "impact": self.impact,
            "nodes": [
                {
                    "id": n.id,
                    "type": n.type.value,
                    "role": n.role.value,
                    "label": n.label,
                    "file": n.file,
                    "line": n.line,
                }
                for n in self.nodes
            ],
            "narrative": list(self.narrative),
            "evidence_ids": list(self.evidence_ids),
            "justifying_evidence_ids": list(self.justifying_ids),
            "missing_evidence": list(self.missing),
        }


@dataclass(frozen=True)
class PathPattern:
    """A named chain, expressed as roles plus the evidence it needs."""

    key: str
    title: str
    roles: tuple[NodeRole, ...]
    """Roles the path must cross, in order. Extra nodes between them are fine."""
    required_rules: frozenset[str] = frozenset()
    """At least one finding from each of these rule ids must back the path."""
    required_end_types: frozenset[NodeType] = frozenset()
    base_severity: Severity = Severity.HIGH


#: The three chains from the specification, plus the token-abuse variant that
#: falls out of the same machinery.
PATTERNS: tuple[PathPattern, ...] = (
    PathPattern(
        key="AP_CREDENTIAL_EXFILTRATION",
        title="Untrusted input reaches execution, then a secret leaves the runner",
        roles=(NodeRole.ENTRY_POINT, NodeRole.EXECUTION, NodeRole.PRIVILEGE, NodeRole.IMPACT),
        required_rules=frozenset({"SCRIPT_INJECTION", "UNTRUSTED_CODE_EXECUTION", "SECRET_EXPOSURE"}),
        required_end_types=frozenset({NodeType.EXTERNAL_HOST}),
        base_severity=Severity.CRITICAL,
    ),
    PathPattern(
        key="AP_SUPPLY_CHAIN_TAKEOVER",
        title="A mutable third-party action reaches a token that can write the repository",
        roles=(NodeRole.EXECUTION, NodeRole.PRIVILEGE, NodeRole.ASSET),
        required_rules=frozenset({"ACTION_UNPINNED"}),
        required_end_types=frozenset({NodeType.REPOSITORY, NodeType.PACKAGE, NodeType.RELEASE}),
        base_severity=Severity.HIGH,
    ),
    PathPattern(
        key="AP_RELEASE_COMPROMISE",
        title="Untrusted execution reaches a publishing step",
        roles=(NodeRole.ENTRY_POINT, NodeRole.EXECUTION, NodeRole.ASSET),
        required_rules=frozenset(
            {"RELEASE_RISK", "ARTIFACT_TAMPERING", "UNTRUSTED_CODE_EXECUTION"}
        ),
        required_end_types=frozenset({NodeType.PACKAGE, NodeType.RELEASE, NodeType.ARTIFACT}),
        base_severity=Severity.HIGH,
    ),
    PathPattern(
        key="AP_SECRET_EXFILTRATION",
        title="Code running in the job can send a secret to an external host",
        roles=(NodeRole.EXECUTION, NodeRole.PRIVILEGE, NodeRole.IMPACT),
        required_rules=frozenset({"SECRET_EXPOSURE", "REMOTE_CODE_FETCH"}),
        required_end_types=frozenset({NodeType.EXTERNAL_HOST}),
        base_severity=Severity.HIGH,
    ),
    PathPattern(
        key="AP_PRIVILEGED_PWN_REQUEST",
        title="A fork's code executes with the base repository's privileges",
        roles=(NodeRole.ENTRY_POINT, NodeRole.EXECUTION, NodeRole.PRIVILEGE),
        required_rules=frozenset({"UNTRUSTED_CODE_EXECUTION", "DANGEROUS_TRIGGER"}),
        base_severity=Severity.CRITICAL,
    ),
)

#: How each edge type reads in a narrative line.
_EDGE_PHRASING: dict[EdgeType, str] = {
    EdgeType.TRIGGERS: "starts",
    EdgeType.SUPPLIES: "supplies a value to",
    EdgeType.INTERPOLATED_INTO: "is interpolated into",
    EdgeType.CONTAINS: "contains",
    EdgeType.INVOKES: "invokes",
    EdgeType.EXECUTES: "executes on",
    EdgeType.ACCESSES: "has access to",
    EdgeType.GRANTS: "grants",
    EdgeType.READS: "reads",
    EdgeType.DOWNLOADS: "downloads from",
    EdgeType.SENDS_TO: "can be sent to",
    EdgeType.MODIFIES: "modifies",
    EdgeType.MODIFIES_ARTIFACT: "can modify",
    EdgeType.ENABLES: "enables writing to",
    EdgeType.PUBLISHES: "publishes",
    EdgeType.DEPENDS_ON: "depends on",
    EdgeType.PRECEDES: "precedes",
    EdgeType.FLOWS_TO: "flows to",
    EdgeType.AUTHORED: "authored",
    EdgeType.EVIDENCES: "evidences",
}


def _roles_in_order(path_nodes: list[Node], roles: tuple[NodeRole, ...]) -> bool:
    """True when ``path_nodes`` crosses ``roles`` in the given order."""

    remaining = list(roles)
    for node in path_nodes:
        if remaining and node.role is remaining[0]:
            remaining.pop(0)
    return not remaining


def _narrative(graph: AttackGraph, path: list[str]) -> list[str]:
    """Turn a node path into readable lines."""

    lines: list[str] = []
    for source, target in zip(path, path[1:]):
        edge = next(
            (e for e in graph.edges if e.source == source and e.target == target), None
        )
        source_node, target_node = graph.nodes[source], graph.nodes[target]
        phrase = _EDGE_PHRASING.get(edge.type, edge.type.value) if edge else "reaches"
        detail = f" ({edge.label})" if edge and edge.label and len(edge.label) < 90 else ""
        location = f" [{target_node.file}:{target_node.line}]" if target_node.line else ""
        lines.append(
            f"{source_node.type.value} '{source_node.label}' {phrase} "
            f"{target_node.type.value} '{target_node.label}'{detail}{location}"
        )
    return lines


def _supporting_rules(graph: AttackGraph, evidence_ids: Iterable[str]) -> set[str]:
    return {
        graph.findings[fid].rule_id
        for fid in evidence_ids
        if fid in graph.findings
    }


def _score(
    pattern: PathPattern, findings: list[Finding], hop_count: int
) -> tuple[Severity, float]:
    """Severity and confidence for a path, from the findings that justify it.

    Only findings whose rule the pattern actually requires are scored. Every
    finding attached to any node along the route is collected as evidence, but
    scoring on all of them would let one unrelated CRITICAL elsewhere in the
    job promote an otherwise unremarkable path -- which is how a scanner ends
    up reporting that everything is critical.

    Confidence is the mean of those findings' confidences, reduced for longer
    paths: each extra hop is one more inference that has to hold.
    """

    justifying = [f for f in findings if f.rule_id in pattern.required_rules] or findings
    if not justifying:
        return pattern.base_severity, 0.3

    mean_confidence = sum(f.confidence for f in justifying) / len(justifying)
    length_penalty = min(0.05 * max(hop_count - 3, 0), 0.25)
    confidence = max(mean_confidence - length_penalty, 0.2)

    # The chain is only as strong as its most severe justifying finding, and
    # never stronger than the pattern's own ceiling.
    strongest = min(justifying, key=lambda f: f.severity.rank).severity
    severity = (
        strongest if strongest.rank > pattern.base_severity.rank else pattern.base_severity
    )
    return severity, round(confidence, 2)


def _missing_evidence(pattern: PathPattern, present_rules: set[str]) -> list[str]:
    """What is absent that would strengthen or weaken this path."""

    gaps: list[str] = []
    absent = pattern.required_rules - present_rules
    if absent:
        gaps.append(
            "no finding from " + ", ".join(sorted(absent)) + " backs this route"
        )
    gaps.append(
        "whether the workflow has ever run on an outsider-supplied event "
        "(run history is not in the repository)"
    )
    if "ACTION_UNPINNED" in present_rules:
        gaps.append(
            "whether the referenced tag currently points at the reviewed revision "
            "(requires resolving the tag against the action's repository)"
        )
    return gaps


def find_attack_paths(
    graph: AttackGraph, *, max_paths: int = 25, cutoff: int = 8
) -> list[AttackPath]:
    """Search the graph for routes matching the known attack patterns."""

    found: list[AttackPath] = []
    counter = 0

    # Entry candidates: anything an outsider supplies, every third-party action
    # (a compromised publisher is an entry in its own right), and any step that
    # a rule actually flagged. Steps are restricted to evidenced ones on
    # purpose -- admitting all of them would make the search quadratic in step
    # count and would open chains from steps nothing is wrong with.
    entry_nodes = [
        n
        for n in graph.nodes.values()
        if n.role is NodeRole.ENTRY_POINT
        or n.type is NodeType.ACTION
        or (n.type is NodeType.STEP and n.evidence_ids)
    ]

    target_roles = {NodeRole.IMPACT, NodeRole.ASSET, NodeRole.PRIVILEGE}
    target_nodes = [n for n in graph.nodes.values() if n.role in target_roles]

    # Collapse the multigraph: path search only needs reachability, and
    # simple_paths on a MultiDiGraph would enumerate the same node sequence
    # once per parallel edge.
    simple = nx.DiGraph()
    simple.add_nodes_from(graph.graph.nodes())
    simple.add_edges_from((u, v) for u, v, _ in graph.graph.edges(keys=True))

    seen_sequences: set[tuple[str, ...]] = set()

    for pattern in PATTERNS:
        for source in entry_nodes:
            for target in target_nodes:
                if source.id == target.id:
                    continue
                if pattern.required_end_types and target.type not in pattern.required_end_types:
                    continue
                if not simple.has_node(source.id) or not simple.has_node(target.id):
                    continue

                try:
                    routes = nx.all_simple_paths(
                        simple, source.id, target.id, cutoff=cutoff
                    )
                    for route in routes:
                        sequence = tuple(route)
                        if sequence in seen_sequences:
                            continue

                        path_nodes = [graph.nodes[n] for n in route]
                        if not _roles_in_order(path_nodes, pattern.roles):
                            continue

                        evidence_ids = graph.evidence_for_path(route)
                        present_rules = _supporting_rules(graph, evidence_ids)
                        # A path with no finding behind it is just structure.
                        if not present_rules:
                            continue
                        if pattern.required_rules and not (
                            pattern.required_rules & present_rules
                        ):
                            continue

                        seen_sequences.add(sequence)
                        counter += 1
                        findings = [
                            graph.findings[fid]
                            for fid in evidence_ids
                            if fid in graph.findings
                        ]
                        severity, confidence = _score(pattern, findings, len(route))
                        complete = bool(pattern.required_rules & present_rules)

                        found.append(
                            AttackPath(
                                id=f"AP{counter:03d}",
                                pattern=pattern.key,
                                title=pattern.title,
                                verdict=(
                                    PathVerdict.POTENTIAL_ATTACK_PATH
                                    if complete
                                    else PathVerdict.PARTIAL_PATH
                                ),
                                severity=severity,
                                confidence=confidence,
                                nodes=path_nodes,
                                evidence_ids=evidence_ids,
                                narrative=_narrative(graph, route),
                                missing=_missing_evidence(pattern, present_rules),
                                justifying_ids=[
                                    f.id
                                    for f in findings
                                    if f.rule_id in pattern.required_rules
                                ],
                            )
                        )
                        if len(found) >= max_paths * 4:
                            break
                except nx.NetworkXNoPath:  # pragma: no cover - defensive
                    continue

    found.sort(key=lambda p: (p.severity.rank, -p.confidence, len(p.nodes)))
    return _deduplicate(found)[:max_paths]


def _deduplicate(paths: list[AttackPath]) -> list[AttackPath]:
    """Keep the best-evidenced route for each (pattern, entry, impact) triple.

    One weakness yields many routes that differ only by which structural hops
    they take, and listing them all would read as many problems rather than
    one. Of those, the *best* route is not the shortest: a chain that passes
    through the injected input and the shell command explains the finding,
    while the shortcut from job straight to token merely asserts it. So the
    survivor is the one with the most justifying findings, and length is only
    the tie-break -- longer, because more hops means more of the story shown.
    """

    def rank(path: AttackPath) -> tuple[int, int, int]:
        """How good a representative this route is for its (pattern, impact).

        An entry node that carries justifying evidence matters most: a chain
        that starts at the step a rule actually flagged explains the problem,
        while one that starts at an unrelated pinned action merely happens to
        reach the same place through the same runner.
        """

        justifying = set(path.justifying_ids)
        entry_is_implicated = bool(justifying & set(path.nodes[0].evidence_ids))
        return (int(entry_is_implicated), len(justifying), len(path.nodes))

    # Group by (pattern, impact): the destination is what distinguishes one
    # real problem from another, not which of several execution nodes the
    # search happened to start from.
    best: dict[tuple[str, str], AttackPath] = {}
    for path in paths:
        if not path.nodes:
            continue
        key = (path.pattern, path.nodes[-1].id)
        incumbent = best.get(key)
        if incumbent is None or rank(path) > rank(incumbent):
            best[key] = path

    # Second pass: drop any route that is a prefix of one already kept, or
    # identical to it. Two things produce these. One weakness naturally yields
    # "...-> token", "...-> token -> contents:write" and "...-> token ->
    # contents:write -> repository" -- one finding told to three depths, of
    # which only the deepest reaches the actual asset. And two *different*
    # patterns can match the same route, which would otherwise print the same
    # chain twice under two names.
    #
    # So the comparison ignores the pattern. Longest first, and among equal
    # lengths the most severe and best-evidenced, so the survivor is the
    # strongest reading of the route.
    candidates = sorted(
        best.values(),
        key=lambda p: (-len(p.nodes), p.severity.rank, -len(p.justifying_ids)),
    )
    kept: list[AttackPath] = []
    for path in candidates:
        ids = [n.id for n in path.nodes]
        subsumed = any(
            [n.id for n in existing.nodes][: len(ids)] == ids for existing in kept
        )
        if not subsumed:
            kept.append(path)

    kept.sort(key=lambda p: (p.severity.rank, -p.confidence, -len(p.justifying_ids)))
    return kept


__all__ = ["AttackPath", "PATTERNS", "PathPattern", "PathVerdict", "find_attack_paths"]
