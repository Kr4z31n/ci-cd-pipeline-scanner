"""Node and edge vocabulary for the attack graph.

The graph exists to be *reasoned over*, not drawn. That constraint decides the
vocabulary: node types name things an attacker interacts with (a trigger, a
token, a secret, a host), and edge types name the relation that makes a step
possible (``grants``, ``flows_to``, ``executes``).

Two rules hold everywhere in this package:

1. Every node and edge carries the finding IDs that justify it. An edge with no
   evidence is a claim the tool cannot support, and the builder refuses to add
   one.
2. Nodes carry a :class:`NodeRole`, which is what lets the correlator ask
   "does this path go entry point -> execution -> privilege -> asset?" without
   hard-coding particular node types into the search.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeType(str, Enum):
    """What a node represents."""

    COMMIT = "commit"
    AUTHOR = "author"
    WORKFLOW = "workflow"
    TRIGGER = "trigger"
    JOB = "job"
    STEP = "step"
    ACTION = "action"
    PERMISSION = "permission"
    RUNNER = "runner"
    INPUT = "input"
    SECRET = "secret"
    GITHUB_TOKEN = "github_token"
    SHELL_COMMAND = "shell_command"
    ARTIFACT = "artifact"
    REPOSITORY = "repository"
    EXTERNAL_HOST = "external_host"
    PACKAGE = "package"
    RELEASE = "release"
    FINDING = "finding"


class EdgeType(str, Enum):
    """How one node relates to another."""

    MODIFIES = "modifies"
    AUTHORED = "authored"
    TRIGGERS = "triggers"
    CONTAINS = "contains"
    INVOKES = "invokes"
    EXECUTES = "executes"
    ACCESSES = "accesses"
    GRANTS = "grants"
    READS = "reads"
    DOWNLOADS = "downloads"
    SENDS_TO = "sends_to"
    MODIFIES_ARTIFACT = "modifies_artifact"
    DEPENDS_ON = "depends_on"
    PRECEDES = "precedes"
    FLOWS_TO = "flows_to"
    SUPPLIES = "supplies"
    INTERPOLATED_INTO = "interpolated_into"
    ENABLES = "enables"
    PUBLISHES = "publishes"
    EVIDENCES = "evidences"


class NodeRole(str, Enum):
    """The node's position in an attack narrative.

    An attack path is only interesting when it crosses these in order, so the
    correlator searches on roles rather than on specific node types. That way a
    new node type slots into the search by declaring its role.
    """

    ENTRY_POINT = "ENTRY_POINT"
    """Where an outsider supplies something: a trigger, an input, a fork PR."""
    EXECUTION = "EXECUTION"
    """Where something runs: a step, a runner, an action, a shell command."""
    PRIVILEGE = "PRIVILEGE"
    """A capability gained: a permission, a token, a secret."""
    ASSET = "ASSET"
    """Something of value: the repository, an artifact, a package, a release."""
    IMPACT = "IMPACT"
    """Where value leaves or integrity breaks: an external host, a release."""
    CONTEXT = "CONTEXT"
    """Structure that carries no attack meaning of its own."""


#: Default role for each node type. The builder may override per node.
DEFAULT_ROLES: dict[NodeType, NodeRole] = {
    NodeType.TRIGGER: NodeRole.ENTRY_POINT,
    NodeType.INPUT: NodeRole.ENTRY_POINT,
    # Context, not an entry point: see the note in builder._add_history.
    NodeType.COMMIT: NodeRole.CONTEXT,
    NodeType.AUTHOR: NodeRole.CONTEXT,
    NodeType.WORKFLOW: NodeRole.CONTEXT,
    NodeType.JOB: NodeRole.CONTEXT,
    NodeType.STEP: NodeRole.EXECUTION,
    NodeType.ACTION: NodeRole.EXECUTION,
    NodeType.RUNNER: NodeRole.EXECUTION,
    NodeType.SHELL_COMMAND: NodeRole.EXECUTION,
    NodeType.PERMISSION: NodeRole.PRIVILEGE,
    NodeType.SECRET: NodeRole.PRIVILEGE,
    NodeType.GITHUB_TOKEN: NodeRole.PRIVILEGE,
    NodeType.REPOSITORY: NodeRole.ASSET,
    NodeType.ARTIFACT: NodeRole.ASSET,
    NodeType.PACKAGE: NodeRole.ASSET,
    NodeType.RELEASE: NodeRole.ASSET,
    NodeType.EXTERNAL_HOST: NodeRole.IMPACT,
    NodeType.FINDING: NodeRole.CONTEXT,
}


@dataclass
class Node:
    """One node in the attack graph."""

    id: str
    type: NodeType
    label: str
    role: NodeRole = NodeRole.CONTEXT
    file: str = ""
    line: int = 0
    evidence_ids: list[str] = field(default_factory=list)
    """Finding IDs supporting this node's existence."""
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "label": self.label,
            "role": self.role.value,
            "file": self.file,
            "line": self.line,
            "evidence_ids": list(self.evidence_ids),
            **self.attributes,
        }


@dataclass
class Edge:
    """One directed relationship, with the evidence that justifies it."""

    source: str
    target: str
    type: EdgeType
    evidence_ids: list[str] = field(default_factory=list)
    label: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.source, self.target, self.type.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.type.value,
            "label": self.label or self.type.value,
            "evidence_ids": list(self.evidence_ids),
            **self.attributes,
        }


def node_id(kind: NodeType, *parts: str) -> str:
    """Build a stable, readable node id.

    Ids are derived from what the node *is* rather than from a counter, so the
    same repository always produces the same graph and two runs can be diffed.
    """

    cleaned = [str(part).replace("|", "/").strip() for part in parts if str(part).strip()]
    return f"{kind.value}:" + "|".join(cleaned)


__all__ = [
    "DEFAULT_ROLES",
    "Edge",
    "EdgeType",
    "Node",
    "NodeRole",
    "NodeType",
    "node_id",
]
