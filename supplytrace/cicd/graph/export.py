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


# -- SVG -----------------------------------------------------------------------
#
# Written by hand rather than shelled out to Graphviz. `dot` is not installed on
# most machines, and a diagram nobody can render is not a diagram. This keeps
# the picture a first-class output with no system dependency.

#: Columns, left to right. This is the attack narrative's own order, so a
#: reader follows the diagram the same way they read the path text.
_SVG_COLUMNS: tuple[NodeRole, ...] = (
    NodeRole.ENTRY_POINT,
    NodeRole.CONTEXT,
    NodeRole.EXECUTION,
    NodeRole.PRIVILEGE,
    NodeRole.ASSET,
    NodeRole.IMPACT,
)

_SVG_FILL: dict[NodeRole, str] = {
    NodeRole.ENTRY_POINT: "#d94801",
    NodeRole.CONTEXT: "#8a9aa3",
    NodeRole.EXECUTION: "#1f6f8b",
    NodeRole.PRIVILEGE: "#6b4c9a",
    NodeRole.ASSET: "#2f7d4f",
    NodeRole.IMPACT: "#a11d33",
}


def _xml(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def write_svg(
    graph: AttackGraph,
    destination: str | Path,
    paths: list[AttackPath] | None = None,
    *,
    only_paths: bool = True,
) -> Path:
    """Render the graph as a standalone SVG.

    By default only the nodes lying on an attack path are drawn. A full export
    of a real repository runs to hundreds of nodes and thousands of edges,
    which renders as a hairball that communicates nothing; the paths are the
    part worth looking at.
    """

    paths = paths or []
    on_path: set[str] = {n.id for p in paths for n in p.nodes}
    path_edges: set[tuple[str, str]] = set()
    for path in paths:
        ids = [n.id for n in path.nodes]
        path_edges.update(zip(ids, ids[1:]))

    if only_paths and on_path:
        node_ids = on_path
    else:
        node_ids = set(graph.nodes)

    nodes = [graph.nodes[i] for i in node_ids if i in graph.nodes]
    edges = [
        e for e in graph.edges if e.source in node_ids and e.target in node_ids
    ]

    columns: dict[NodeRole, list] = {role: [] for role in _SVG_COLUMNS}
    for node in sorted(nodes, key=lambda n: n.label):
        columns.setdefault(node.role, []).append(node)
    active = [role for role in _SVG_COLUMNS if columns.get(role)]

    box_w, box_h = 210, 52
    gap_x, gap_y = 96, 26
    pad = 34
    header = 58

    placed: dict[str, tuple[float, float]] = {}
    for column_index, role in enumerate(active):
        members = columns[role]
        x = pad + column_index * (box_w + gap_x)
        for row, node in enumerate(members):
            y = header + pad + row * (box_h + gap_y)
            placed[node.id] = (x, y)

    tallest = max((len(columns[r]) for r in active), default=1)
    width = pad * 2 + len(active) * box_w + max(len(active) - 1, 0) * gap_x
    height = header + pad * 2 + tallest * box_h + max(tallest - 1, 0) * gap_y

    out: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
        f'height="{height}" viewBox="0 0 {width} {height}" '
        f'font-family="ui-sans-serif, system-ui, sans-serif">',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        '<defs>',
        '<marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
        'markerHeight="7" orient="auto-start-reverse">'
        '<path d="M0,0 L10,5 L0,10 z" fill="#9aa7ad"/></marker>',
        '<marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" '
        'markerHeight="8" orient="auto-start-reverse">'
        '<path d="M0,0 L10,5 L0,10 z" fill="#a11d33"/></marker>',
        '</defs>',
        f'<text x="{pad}" y="30" font-size="16" font-weight="600" fill="#10171c">'
        f'Attack graph — {len(paths)} path(s), {len(nodes)} nodes shown</text>',
        f'<text x="{pad}" y="47" font-size="11" fill="#6b7a82">'
        f'Routes that exist in the configuration. Not evidence that any was taken.'
        f'</text>',
    ]

    # Column headings.
    for column_index, role in enumerate(active):
        x = pad + column_index * (box_w + gap_x)
        out.append(
            f'<text x="{x}" y="{header + 12}" font-size="10" font-weight="600" '
            f'letter-spacing="1.4" fill="{_SVG_FILL.get(role, "#8a9aa3")}">'
            f'{_xml(role.value.replace("_", " "))}</text>'
        )

    # Edges first, so boxes sit on top of the lines.
    for edge in edges:
        if edge.source not in placed or edge.target not in placed:
            continue
        sx, sy = placed[edge.source]
        tx, ty = placed[edge.target]
        x1, y1 = sx + box_w, sy + box_h / 2
        x2, y2 = tx, ty + box_h / 2
        highlighted = (edge.source, edge.target) in path_edges
        mid = (x1 + x2) / 2
        out.append(
            f'<path d="M{x1:.0f},{y1:.0f} C{mid:.0f},{y1:.0f} {mid:.0f},{y2:.0f} '
            f'{x2:.0f},{y2:.0f}" fill="none" '
            f'stroke="{"#a11d33" if highlighted else "#c7d0d4"}" '
            f'stroke-width="{2.0 if highlighted else 1.0}" '
            f'marker-end="url(#{"ah" if highlighted else "a"})"/>'
        )
        if highlighted:
            out.append(
                f'<text x="{mid:.0f}" y="{(y1 + y2) / 2 - 5:.0f}" font-size="9" '
                f'text-anchor="middle" fill="#a11d33">{_xml(edge.type.value)}</text>'
            )

    # Nodes.
    for node in nodes:
        if node.id not in placed:
            continue
        x, y = placed[node.id]
        fill = _SVG_FILL.get(node.role, "#8a9aa3")
        label = node.label if len(node.label) <= 30 else node.label[:29] + "…"
        out.append(
            f'<rect x="{x}" y="{y}" width="{box_w}" height="{box_h}" rx="5" '
            f'fill="{fill}14" stroke="{fill}" stroke-width="1.5"/>'
        )
        out.append(
            f'<text x="{x + 11}" y="{y + 20}" font-size="12" font-weight="600" '
            f'fill="#10171c">{_xml(label)}</text>'
        )
        detail = node.type.value
        if node.line:
            detail += f" · {Path(node.file).name}:{node.line}"
        out.append(
            f'<text x="{x + 11}" y="{y + 35}" font-size="9.5" fill="#6b7a82">'
            f'{_xml(detail[:38])}</text>'
        )
        if node.evidence_ids:
            out.append(
                f'<text x="{x + 11}" y="{y + 46}" font-size="9" '
                f'font-family="ui-monospace, monospace" fill="{fill}">'
                f'{_xml(",".join(node.evidence_ids[:4]))}</text>'
            )

    out.append("</svg>")

    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(out), encoding="utf-8")
    return path


def export_all(
    graph: AttackGraph,
    directory: str | Path,
    paths: list[AttackPath] | None = None,
) -> dict[str, Path]:
    """Write every supported format into ``directory``."""

    target = Path(directory)
    written = {
        "json": write_json(graph, target / "attack_graph.json", paths),
        "svg": write_svg(graph, target / "attack_graph.svg", paths),
        "dot": write_dot(graph, target / "attack_graph.dot", paths),
    }
    try:
        written["graphml"] = write_graphml(graph, target / "attack_graph.graphml")
    except (nx.NetworkXError, TypeError, ValueError) as exc:  # pragma: no cover
        # GraphML is the strictest format; losing it must not cost the others.
        written["graphml_error"] = Path(str(exc))
    return written


__all__ = [
    "write_svg",
    "export_all",
    "graph_to_dict",
    "write_dot",
    "write_graphml",
    "write_json",
]
