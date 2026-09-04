"""Export the attack graph to JSON, GraphML and DOT.

Every export carries the evidence ids along with the nodes and edges. An
exported graph that dropped them would be a picture of conclusions with no way
back to the facts, which is the failure mode this whole design is built to
avoid.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import networkx as nx

from supplytrace.cicd.graph.builder import AttackGraph
from supplytrace.cicd.graph.correlation import AttackPath
from supplytrace.cicd.graph.models import NodeRole, NodeType

#: A colour per role, used by the DOT export.
_ROLE_COLOURS: dict[NodeRole, str] = {
    NodeRole.ENTRY_POINT: "#d94801",
    NodeRole.EXECUTION: "#2171b5",
    NodeRole.PRIVILEGE: "#6a51a3",
    NodeRole.ASSET: "#238b45",
    NodeRole.IMPACT: "#cb181d",
    NodeRole.CONTEXT: "#969696",
}

_ROLE_SHAPES: dict[NodeRole, str] = {
    NodeRole.ENTRY_POINT: "invhouse",
    NodeRole.EXECUTION: "box",
    NodeRole.PRIVILEGE: "hexagon",
    NodeRole.ASSET: "cylinder",
    NodeRole.IMPACT: "doubleoctagon",
    NodeRole.CONTEXT: "ellipse",
}


def graph_to_dict(
    graph: AttackGraph, paths: list[AttackPath] | None = None
) -> dict[str, Any]:
    """The whole graph as a plain dictionary, ready for ``json.dump``."""

    return {
        "format": "supplytrace.attack-graph/1",
        "summary": {
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "by_type": graph.summary(),
            "rejected_edges": len(graph.rejected_edges),
        },
        "nodes": [node.to_dict() for node in graph.nodes.values()],
        "edges": [edge.to_dict() for edge in graph.edges],
        "attack_paths": [path.to_dict() for path in (paths or [])],
        "findings": {
            finding_id: {
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "confidence": finding.confidence,
                "title": finding.title,
                "file": finding.file,
                "line": finding.line,
            }
            for finding_id, finding in sorted(graph.findings.items())
        },
        "rejected_edges": list(graph.rejected_edges),
    }


def write_json(
    graph: AttackGraph, destination: str | Path, paths: list[AttackPath] | None = None
) -> Path:
    """Write ``attack_graph.json``."""

    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(graph_to_dict(graph, paths), indent=2, default=str), encoding="utf-8"
    )
    return path


def _graphml_safe(graph: AttackGraph) -> nx.MultiDiGraph:
    """A copy whose attributes GraphML can actually represent.

    GraphML has no list or dict type, so evidence ids and any structured
    attribute are flattened to strings rather than silently dropped.
    """

    export = nx.MultiDiGraph()
    for identifier, node in graph.nodes.items():
        attributes = {
            key: (
                ",".join(str(item) for item in value)
                if isinstance(value, (list, tuple, set))
                else json.dumps(value)
                if isinstance(value, dict)
                else "" if value is None else value
            )
            for key, value in node.to_dict().items()
        }
        export.add_node(identifier, **attributes)

    for edge in graph.edges:
        attributes = {
            key: (
                ",".join(str(item) for item in value)
                if isinstance(value, (list, tuple, set))
                else json.dumps(value)
                if isinstance(value, dict)
                else "" if value is None else value
            )
            for key, value in edge.to_dict().items()
            if key not in ("source", "target")
        }
        export.add_edge(edge.source, edge.target, key=edge.type.value, **attributes)
    return export


def write_graphml(graph: AttackGraph, destination: str | Path) -> Path:
    """Write ``attack_graph.graphml`` for Gephi, yEd or Cytoscape."""

    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    nx.write_graphml(_graphml_safe(graph), path)
    return path


def write_dot(
    graph: AttackGraph, destination: str | Path, paths: list[AttackPath] | None = None
) -> Path:
    """Write a Graphviz DOT file that reads entry point -> impact.

    DOT is written by hand rather than through pydot so that visualisation
    needs no extra dependency: ``dot -Tsvg attack_graph.dot`` is enough.
    """

    highlighted: set[str] = set()
    highlighted_edges: set[tuple[str, str]] = set()
    for path in paths or []:
        ids = [node.id for node in path.nodes]
        highlighted.update(ids)
        highlighted_edges.update(zip(ids, ids[1:]))

    lines = [
        "digraph attack_graph {",
        "  rankdir=LR;",
        "  graph [fontname=\"Helvetica\", splines=true, overlap=false];",
        "  node [fontname=\"Helvetica\", style=filled, fillcolor=white, fontsize=10];",
        "  edge [fontname=\"Helvetica\", fontsize=8, color=\"#888888\"];",
    ]

    # Group by role so the drawing reads left to right in attack order.
    for role in (
        NodeRole.ENTRY_POINT,
        NodeRole.EXECUTION,
        NodeRole.PRIVILEGE,
        NodeRole.ASSET,
        NodeRole.IMPACT,
    ):
        members = [n for n in graph.nodes.values() if n.role is role]
        if not members:
            continue
        lines.append(f"  subgraph cluster_{role.value.lower()} {{")
        lines.append(f'    label="{role.value.replace("_", " ").title()}";')
        lines.append('    style=dashed; color="#cccccc";')
        for node in members:
            lines.append(f"    {_dot_node(node, node.id in highlighted)}")
        lines.append("  }")

    for node in graph.nodes.values():
        if node.role is NodeRole.CONTEXT:
            lines.append(f"  {_dot_node(node, node.id in highlighted)}")

    for edge in graph.edges:
        on_path = (edge.source, edge.target) in highlighted_edges
        style = (
            ' [color="#cb181d", penwidth=2.2, label="%s"]' % _escape(edge.type.value)
            if on_path
            else ' [label="%s"]' % _escape(edge.type.value)
        )
        lines.append(f'  "{_escape(edge.source)}" -> "{_escape(edge.target)}"{style};')

    lines.append("}")

    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _dot_node(node, highlighted: bool) -> str:
    colour = _ROLE_COLOURS.get(node.role, "#969696")
    shape = _ROLE_SHAPES.get(node.role, "ellipse")
    label = _escape(node.label[:40])
    if node.line:
        label += rf"\n{_escape(Path(node.file).name)}:{node.line}"
    if node.evidence_ids:
        label += rf"\n[{_escape(','.join(node.evidence_ids[:3]))}]"
    border = ', penwidth=2.5, color="#cb181d"' if highlighted else f', color="{colour}"'
    return (
        f'"{_escape(node.id)}" [label="{label}", shape={shape}, '
        f'fillcolor="{colour}22"{border}];'
    )


def _escape(text: str) -> str:
    return str(text).replace("\\", "\\\\").replace('"', '\\"')


def export_all(
    graph: AttackGraph,
    directory: str | Path,
    paths: list[AttackPath] | None = None,
) -> dict[str, Path]:
    """Write every supported format into ``directory``."""

    target = Path(directory)
    written = {
        "json": write_json(graph, target / "attack_graph.json", paths),
        "dot": write_dot(graph, target / "attack_graph.dot", paths),
    }
    try:
        written["graphml"] = write_graphml(graph, target / "attack_graph.graphml")
    except (nx.NetworkXError, TypeError, ValueError) as exc:  # pragma: no cover
        # GraphML is the strictest format; losing it must not cost the others.
        written["graphml_error"] = Path(str(exc))
    return written


__all__ = [
    "export_all",
    "graph_to_dict",
    "write_dot",
    "write_graphml",
    "write_json",
]
