"""Build the attack graph from parsed workflows, findings and Git history.

The graph has two layers over the same nodes:

*Structural* edges come from the workflow files themselves -- this workflow
contains that job, that job runs on this runner, that step invokes this action.
They are OBSERVED and always true.

*Security* edges come from findings -- this trigger supplies untrusted input to
that shell command, that step's secret flows to this external host. They exist
only where a rule produced evidence, and they carry that rule's finding IDs.

Keeping both in one graph is what lets the correlator answer a question neither
layer can answer alone: an entry point is only reachable through structure, and
only dangerous through a security edge.

The one invariant enforced throughout: :meth:`AttackGraph.add_edge` refuses an
edge with no evidence ids unless it is explicitly marked structural. Without
that, the graph would quietly accumulate relationships nobody can check.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

import networkx as nx

from supplytrace.cicd.evidence.collector import ScanResult
from supplytrace.cicd.evidence.models import Finding, FindingType, Severity
from supplytrace.cicd.graph.models import (
    DEFAULT_ROLES,
    Edge,
    EdgeType,
    Node,
    NodeRole,
    NodeType,
    node_id,
)
from supplytrace.cicd.parser.shell import ShellBehaviour, analyse_run_block, host_of
from supplytrace.cicd.parser.workflow import ParsedJob, ParsedStep, ParsedWorkflow
from supplytrace.cicd.rules.base import job_writes, untrusted_triggers
from supplytrace.cicd.rules.history import WorkflowHistory, WorkflowChangeKind


@dataclass
class AttackGraph:
    """A directed graph of the pipeline, its weaknesses, and their evidence."""

    graph: nx.MultiDiGraph = field(default_factory=nx.MultiDiGraph)
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    findings: dict[str, Finding] = field(default_factory=dict)
    rejected_edges: list[str] = field(default_factory=list)
    """Edges refused for lack of evidence, kept so the gap is visible."""

    # -- construction ----------------------------------------------------------

    def add_node(
        self,
        kind: NodeType,
        *parts: str,
        label: str = "",
        role: NodeRole | None = None,
        file: str = "",
        line: int = 0,
        evidence_ids: Iterable[str] = (),
        **attributes: object,
    ) -> str:
        """Add or update a node, returning its id."""

        identifier = node_id(kind, *parts)
        existing = self.nodes.get(identifier)
        if existing is None:
            node = Node(
                id=identifier,
                type=kind,
                label=label or (parts[-1] if parts else kind.value),
                role=role or DEFAULT_ROLES.get(kind, NodeRole.CONTEXT),
                file=file,
                line=line,
                evidence_ids=sorted(set(evidence_ids)),
                attributes=dict(attributes),
            )
            self.nodes[identifier] = node
            self.graph.add_node(identifier, **node.to_dict())
            return identifier

        # Merge: a node can be reached from several rules, and each may know a
        # different piece of it.
        merged = sorted(set(existing.evidence_ids) | set(evidence_ids))
        existing.evidence_ids = merged
        existing.attributes.update(attributes)
        if role is not None:
            existing.role = role
        if file and not existing.file:
            existing.file, existing.line = file, line
        self.graph.add_node(identifier, **existing.to_dict())
        return identifier

    def add_edge(
        self,
        source: str,
        target: str,
        kind: EdgeType,
        *,
        evidence_ids: Iterable[str] = (),
        label: str = "",
        structural: bool = False,
        **attributes: object,
    ) -> bool:
        """Add a relationship. Returns False if it was refused.

        A security edge without evidence is refused: the whole report rests on
        every asserted relationship being checkable, and an unevidenced edge
        would let the correlator build a path nobody can verify. Structural
        edges are exempt because the workflow file itself is the evidence.
        """

        ids = sorted(set(evidence_ids))
        if not structural and not ids:
            self.rejected_edges.append(f"{source} -[{kind.value}]-> {target}: no evidence")
            return False
        if source not in self.nodes or target not in self.nodes:
            self.rejected_edges.append(
                f"{source} -[{kind.value}]-> {target}: endpoint missing"
            )
            return False

        edge = Edge(
            source=source,
            target=target,
            type=kind,
            evidence_ids=ids,
            label=label,
            attributes=dict(attributes),
        )
        self.edges.append(edge)
        self.graph.add_edge(source, target, key=kind.value, **edge.to_dict())
        return True

    # -- queries ---------------------------------------------------------------

    def nodes_with_role(self, role: NodeRole) -> list[Node]:
        return [node for node in self.nodes.values() if node.role is role]

    def nodes_of_type(self, kind: NodeType) -> list[Node]:
        return [node for node in self.nodes.values() if node.type is kind]

    def evidence_for_path(self, path: list[str]) -> list[str]:
        """Every finding id justifying the nodes and edges along ``path``."""

        ids: set[str] = set()
        for identifier in path:
            node = self.nodes.get(identifier)
            if node:
                ids.update(node.evidence_ids)
        for source, target in zip(path, path[1:]):
            for edge in self.edges:
                if edge.source == source and edge.target == target:
                    ids.update(edge.evidence_ids)
        return sorted(ids)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for node in self.nodes.values():
            counts[node.type.value] = counts.get(node.type.value, 0) + 1
        return dict(sorted(counts.items()))


# -- building ------------------------------------------------------------------


def _findings_at(findings: list[Finding], *, file: str, job: str | None = None) -> list[Finding]:
    return [
        f for f in findings if f.file == file and (job is None or f.job == job)
    ]


def build_graph(result: ScanResult) -> AttackGraph:
    """Construct the attack graph for one scan."""

    graph = AttackGraph(findings={f.id: f for f in result.findings})

    repository = graph.add_node(
        NodeType.REPOSITORY,
        result.repo_path,
        label="this repository",
        role=NodeRole.ASSET,
    )

    for workflow in result.workflows:
        if workflow.is_parsed:
            _add_workflow(graph, result, workflow, repository)

    _add_history(graph, result)
    _add_finding_nodes(graph, result)
    return graph


def _add_workflow(
    graph: AttackGraph, result: ScanResult, workflow: ParsedWorkflow, repository: str
) -> None:
    workflow_findings = [f for f in result.findings if f.file == workflow.path]

    workflow_node = graph.add_node(
        NodeType.WORKFLOW,
        workflow.path,
        label=workflow.display_name,
        file=workflow.path,
        line=1,
        evidence_ids=[f.id for f in workflow_findings],
        path=workflow.path,
    )

    untrusted = set(untrusted_triggers(workflow))
    for name in workflow.trigger_names:
        trigger_findings = [
            f
            for f in workflow_findings
            if f.metadata.get("trigger") == name
            or name in (f.metadata.get("triggers") or [])
        ]
        trigger_node = graph.add_node(
            NodeType.TRIGGER,
            workflow.path,
            name,
            label=name,
            role=NodeRole.ENTRY_POINT if name in untrusted else NodeRole.CONTEXT,
            file=workflow.path,
            line=workflow.trigger_lines.get(name, 0),
            evidence_ids=[f.id for f in trigger_findings],
            outsider_reachable=name in untrusted,
        )
        graph.add_edge(
            trigger_node, workflow_node, EdgeType.TRIGGERS, structural=True
        )

    for job in workflow.jobs:
        _add_job(graph, result, workflow, job, workflow_node, repository)


def _add_job(
    graph: AttackGraph,
    result: ScanResult,
    workflow: ParsedWorkflow,
    job: ParsedJob,
    workflow_node: str,
    repository: str,
) -> None:
    job_findings = _findings_at(result.findings, file=workflow.path, job=job.id)

    job_node = graph.add_node(
        NodeType.JOB,
        workflow.path,
        job.id,
        label=job.id,
        file=workflow.path,
        line=job.location.line,
        evidence_ids=[f.id for f in job_findings],
        runs_on=job.runs_on,
    )
    graph.add_edge(workflow_node, job_node, EdgeType.CONTAINS, structural=True)

    # The runner is keyed per job, not per `runs-on` label. Sharing one
    # "ubuntu-latest" node across every job in the repository would connect
    # unrelated workflows through it and invent paths that do not exist.
    runner_node = graph.add_node(
        NodeType.RUNNER,
        workflow.path,
        job.id,
        job.runs_on or "unspecified",
        label=f"{job.runs_on or 'unspecified'} ({job.id})",
        self_hosted=job.is_self_hosted,
        runs_on=job.runs_on,
    )
    graph.add_edge(job_node, runner_node, EdgeType.EXECUTES, structural=True)

    for upstream in job.needs:
        upstream_node = node_id(NodeType.JOB, workflow.path, upstream)
        if upstream_node in graph.nodes:
            graph.add_edge(job_node, upstream_node, EdgeType.DEPENDS_ON, structural=True)

    # -- privileges the job holds ---------------------------------------------
    permissions = workflow.effective_permissions(job)
    writes = job_writes(permissions)
    token_node = ""
    if writes or permissions is None:
        permission_findings = [
            f
            for f in job_findings
            if f.type is FindingType.PRIVILEGE
        ]
        token_node = graph.add_node(
            NodeType.GITHUB_TOKEN,
            workflow.path,
            job.id,
            label="GITHUB_TOKEN",
            file=workflow.path,
            line=workflow.permissions_origin(job)[1] or job.location.line,
            evidence_ids=[f.id for f in permission_findings],
        )
        graph.add_edge(
            job_node,
            token_node,
            EdgeType.ACCESSES,
            evidence_ids=[f.id for f in permission_findings],
            structural=not permission_findings,
        )
        # The causal edge, and the reason the graph can reason at all: the
        # token is mounted into the runner's environment, so *anything* that
        # executes there reaches it -- a step, a third-party action, or an
        # injected command. Without this the graph shows privileges hanging
        # off a job with no route from the code that could abuse them.
        graph.add_edge(
            runner_node,
            token_node,
            EdgeType.ACCESSES,
            evidence_ids=[f.id for f in permission_findings],
            label="any code on this runner can use the token",
            structural=not permission_findings,
        )

        for scope in sorted(writes):
            scope_findings = [f for f in permission_findings if f.metadata.get("scope") == scope]
            permission_node = graph.add_node(
                NodeType.PERMISSION,
                workflow.path,
                job.id,
                scope,
                label=f"{scope}: write",
                file=workflow.path,
                line=workflow.permissions_origin(job)[1],
                evidence_ids=[f.id for f in scope_findings],
                scope=scope,
                level="write",
            )
            graph.add_edge(
                token_node,
                permission_node,
                EdgeType.GRANTS,
                evidence_ids=[f.id for f in scope_findings],
                structural=not scope_findings,
            )
            # contents:write is the scope that reaches the repository itself.
            if scope in {"contents", "actions"}:
                graph.add_edge(
                    permission_node,
                    repository,
                    EdgeType.ENABLES,
                    evidence_ids=[f.id for f in scope_findings],
                    label="can modify the repository",
                    structural=not scope_findings,
                )

    # -- secrets ---------------------------------------------------------------
    for secret in workflow.secrets_in_scope(job):
        # GITHUB_TOKEN already has a dedicated node above, carrying the
        # permission scopes that make it interesting. Adding a second node for
        # it here would model one credential twice and duplicate every path
        # that passes through it.
        if secret == "GITHUB_TOKEN" and token_node:
            continue
        secret_findings = [
            f for f in job_findings if secret in (f.metadata.get("secrets") or [])
            or f.metadata.get("secret") == secret
        ]
        # Scoped per job for the same reason as the runner: one shared
        # "GITHUB_TOKEN" node would join every job that uses it, and a path
        # could enter through one workflow and exfiltrate through another.
        # The cross-repository view of a secret comes from the findings.
        secret_node = graph.add_node(
            NodeType.SECRET,
            workflow.path,
            job.id,
            secret,
            label=secret,
            evidence_ids=[f.id for f in secret_findings],
            secret_name=secret,
        )
        graph.add_edge(
            job_node,
            secret_node,
            EdgeType.ACCESSES,
            evidence_ids=[f.id for f in secret_findings],
            structural=not secret_findings,
        )
        # Same reasoning as the token: a secret in scope is in the environment
        # of everything running in the job.
        graph.add_edge(
            runner_node,
            secret_node,
            EdgeType.ACCESSES,
            evidence_ids=[f.id for f in secret_findings],
            label="in scope for any code on this runner",
            structural=not secret_findings,
        )

    for step in job.steps:
        _add_step(graph, result, workflow, job, step, job_node, runner_node)


def _add_step(
    graph: AttackGraph,
    result: ScanResult,
    workflow: ParsedWorkflow,
    job: ParsedJob,
    step: ParsedStep,
    job_node: str,
    runner_node: str,
) -> None:
    step_findings = [
        f
        for f in result.findings
        if f.file == workflow.path and f.job == job.id and f.step == step.label
    ]

    step_node = graph.add_node(
        NodeType.STEP,
        workflow.path,
        job.id,
        str(step.index),
        label=step.label,
        file=workflow.path,
        line=step.location.line,
        evidence_ids=[f.id for f in step_findings],
        step_index=step.index,
    )
    graph.add_edge(job_node, step_node, EdgeType.CONTAINS, structural=True)
    graph.add_edge(step_node, runner_node, EdgeType.EXECUTES, structural=True)

    # -- the action this step invokes -----------------------------------------
    if step.uses and not step.uses.is_local:
        action = step.uses
        # Scope the evidence to *this* call site. Matching on the action repo
        # alone would attach findings raised against the same action in other
        # workflows, making a clean call site look implicated.
        action_findings = [
            f
            for f in result.findings
            if (
                f.metadata.get("action_repo") == action.repo
                or f.metadata.get("action") == action.raw
            )
            and f.file == workflow.path
            and (f.job is None or f.job == job.id)
        ]
        # One action node per call site, not one per dependency. A single
        # shared `actions/checkout` node would be a hub joining every workflow
        # that uses it, and path search would happily enter through one
        # workflow's step and leave through another's runner -- a route that
        # does not exist. The cross-repository view ("who else uses this?")
        # comes from the THIRD_PARTY_ACTION finding, which lists every call
        # site; the `repo` attribute here lets a consumer regroup them.
        action_node = graph.add_node(
            NodeType.ACTION,
            workflow.path,
            job.id,
            str(step.index),
            action.repo,
            action.ref or "unversioned",
            label=action.raw,
            file=workflow.path,
            line=step.location.line,
            evidence_ids=[f.id for f in action_findings],
            repo=action.repo,
            ref=action.ref,
            pinned=action.is_pinned,
            first_party=action.is_first_party,
        )
        graph.add_edge(step_node, action_node, EdgeType.INVOKES, structural=True)
        # The action node is intentionally shared across call sites -- one node
        # per dependency is what makes "who else uses this?" answerable. That
        # sharing means the *execution* edge must point back at this specific
        # step, never straight at a runner: an `action -> runner` edge would
        # merge every call site and let a path enter one workflow's action and
        # leave through another workflow's runner.
        graph.add_edge(
            action_node,
            step_node,
            EdgeType.EXECUTES,
            evidence_ids=[f.id for f in action_findings if f.rule_id == "ACTION_UNPINNED"],
            label="this action's code runs as this step",
            structural=True,
        )

    # -- what the shell does ---------------------------------------------------
    if step.run:
        _add_shell(graph, result, workflow, job, step, step_node, step_findings)

    # -- untrusted input reaching this step -----------------------------------
    for finding in step_findings:
        if finding.rule_id != "SCRIPT_INJECTION":
            continue
        context_name = str(finding.metadata.get("context", "untrusted input"))
        input_node = graph.add_node(
            NodeType.INPUT,
            context_name,
            label=context_name,
            role=NodeRole.ENTRY_POINT,
            file=finding.file,
            line=finding.line,
            evidence_ids=[finding.id],
            trust=finding.metadata.get("trust"),
        )
        command_node = graph.add_node(
            NodeType.SHELL_COMMAND,
            workflow.path,
            job.id,
            str(step.index),
            "run",
            label=f"run: {step.label}",
            file=workflow.path,
            line=finding.line,
            evidence_ids=[finding.id],
        )
        graph.add_edge(
            input_node,
            command_node,
            EdgeType.INTERPOLATED_INTO,
            evidence_ids=[finding.id],
            label="expanded into the script before the shell parses it",
        )
        graph.add_edge(
            command_node, runner_node, EdgeType.EXECUTES, evidence_ids=[finding.id]
        )
        # Connect the trigger that lets an outsider supply the value.
        for trigger in finding.metadata.get("triggers") or []:
            trigger_node = node_id(NodeType.TRIGGER, workflow.path, str(trigger))
            if trigger_node in graph.nodes:
                graph.add_edge(
                    trigger_node,
                    input_node,
                    EdgeType.SUPPLIES,
                    evidence_ids=[finding.id],
                    label="an outsider controls this value",
                )


def _add_shell(
    graph: AttackGraph,
    result: ScanResult,
    workflow: ParsedWorkflow,
    job: ParsedJob,
    step: ParsedStep,
    step_node: str,
    step_findings: list[Finding],
) -> None:
    """Network and publishing behaviour of one run block."""

    hits = analyse_run_block(step.run)
    if not hits:
        return

    network_findings = [
        f for f in step_findings if f.rule_id in {"REMOTE_CODE_FETCH", "SECRET_EXPOSURE"}
    ]

    for hit in hits:
        if hit.behaviour in (ShellBehaviour.DOWNLOAD, ShellBehaviour.PIPE_TO_SHELL):
            host = host_of(hit.detail) if hit.detail else ""
            if not host:
                continue
            host_node = graph.add_node(
                NodeType.EXTERNAL_HOST,
                host,
                label=host,
                evidence_ids=[f.id for f in network_findings],
                url=hit.detail,
            )
            graph.add_edge(
                step_node,
                host_node,
                EdgeType.DOWNLOADS,
                evidence_ids=[f.id for f in network_findings],
                label=hit.snippet(80),
                structural=not network_findings,
            )

        elif hit.behaviour is ShellBehaviour.PACKAGE_PUBLISH:
            release_findings = [f for f in step_findings if f.rule_id == "RELEASE_RISK"]
            package_node = graph.add_node(
                NodeType.PACKAGE,
                workflow.path,
                job.id,
                label="published package",
                role=NodeRole.ASSET,
                file=workflow.path,
                line=step.location.line,
                evidence_ids=[f.id for f in release_findings],
            )
            graph.add_edge(
                step_node,
                package_node,
                EdgeType.PUBLISHES,
                evidence_ids=[f.id for f in release_findings],
                label=hit.snippet(80),
                structural=not release_findings,
            )

    # A secret leaving the run block toward a host is the exfiltration edge.
    for finding in step_findings:
        if finding.type is not FindingType.SECRET_EXFILTRATION:
            continue
        secret_name = str(finding.metadata.get("secret", "secret"))
        secret_node = node_id(NodeType.SECRET, workflow.path, job.id, secret_name)
        if secret_node not in graph.nodes:
            secret_node = graph.add_node(
                NodeType.SECRET,
                workflow.path,
                job.id,
                secret_name,
                label=secret_name,
                evidence_ids=[finding.id],
                secret_name=secret_name,
            )
        for host in finding.metadata.get("external_hosts") or []:
            host_name = host_of(str(host)) or str(host)
            host_node = graph.add_node(
                NodeType.EXTERNAL_HOST,
                host_name,
                label=host_name,
                evidence_ids=[finding.id],
            )
            graph.add_edge(
                secret_node,
                host_node,
                EdgeType.SENDS_TO,
                evidence_ids=[finding.id],
                label="value can leave the runner here",
            )


def _add_history(graph: AttackGraph, result: ScanResult) -> None:
    """Commits, their authors, and what they changed -- the temporal layer."""

    history: WorkflowHistory | None = result.workflow_history
    if history is None:
        return

    history_findings = [f for f in result.findings if f.type is FindingType.HISTORY]
    by_commit: dict[str, list[Finding]] = {}
    for finding in history_findings:
        if finding.commit:
            by_commit.setdefault(finding.commit, []).append(finding)

    ordered = history.ordered()
    previous_commit_node = ""

    for change in ordered:
        commit_findings = by_commit.get(change.commit_sha, [])
        # A commit is temporal context, not an attacker's entry vector. Rolling
        # it in as an ENTRY_POINT makes every path start at whichever commit
        # last touched the file, producing a separate near-identical "attack
        # path" per commit for what is really one weakness. The commit still
        # appears in the graph, in the report's history section, and as an
        # intermediate node -- it just does not open a chain.
        commit_node = graph.add_node(
            NodeType.COMMIT,
            change.commit_sha,
            label=change.short_sha,
            role=NodeRole.CONTEXT,
            file=change.path,
            evidence_ids=[f.id for f in commit_findings],
            subject=change.subject,
            timestamp=change.timestamp,
            author=f"{change.author_name} <{change.author_email}>",
        )

        author_node = graph.add_node(
            NodeType.AUTHOR,
            change.author_email or change.author_name,
            label=f"{change.author_name} <{change.author_email}>",
        )
        graph.add_edge(author_node, commit_node, EdgeType.AUTHORED, structural=True)

        workflow_node = node_id(NodeType.WORKFLOW, change.path)
        if workflow_node in graph.nodes:
            graph.add_edge(
                commit_node,
                workflow_node,
                EdgeType.MODIFIES,
                evidence_ids=[f.id for f in commit_findings],
                label=change.describe()[:120],
                structural=not commit_findings,
                change_kind=change.kind.value,
            )

        # Chronological order, so the correlator can show a build-up.
        if previous_commit_node and previous_commit_node != commit_node:
            graph.add_edge(
                previous_commit_node,
                commit_node,
                EdgeType.PRECEDES,
                structural=True,
            )
        previous_commit_node = commit_node

        # A commit that introduced an action links to that action directly.
        if change.kind in (
            WorkflowChangeKind.ACTION_ADDED,
            WorkflowChangeKind.ACTION_VERSION_CHANGED,
        ):
            repo, _, _ = change.detail.partition("@")
            # Action nodes are per call site, so a commit that introduced an
            # action links to every place that action is now used in the file
            # it touched.
            for node in graph.nodes.values():
                if (
                    node.type is NodeType.ACTION
                    and node.attributes.get("repo") == repo
                    and node.file == change.path
                ):
                    graph.add_edge(
                        commit_node,
                        node.id,
                        EdgeType.MODIFIES,
                        evidence_ids=[f.id for f in commit_findings],
                        label=(
                            f"{change.kind.value.lower().replace('_', ' ')}: "
                            f"{change.detail}"
                        ),
                        structural=not commit_findings,
                    )


def _add_finding_nodes(graph: AttackGraph, result: ScanResult) -> None:
    """Attach the highest-severity findings as nodes of their own.

    Only CRITICAL and HIGH get a node: the point is to make the serious ones
    visible in an exported graph without burying it under every INFO record.
    """

    for finding in result.findings:
        if finding.severity not in (Severity.CRITICAL, Severity.HIGH):
            continue
        finding_node = graph.add_node(
            NodeType.FINDING,
            finding.id,
            label=f"{finding.id} {finding.rule_id}",
            file=finding.file,
            line=finding.line,
            evidence_ids=[finding.id],
            severity=finding.severity.value,
            confidence=finding.confidence,
            rule_id=finding.rule_id,
            title=finding.title,
        )
        # Point the finding at the most specific node it describes.
        for candidate in (
            node_id(NodeType.STEP, finding.file, finding.job or "", "0"),
            node_id(NodeType.JOB, finding.file, finding.job or ""),
            node_id(NodeType.WORKFLOW, finding.file),
        ):
            if candidate in graph.nodes:
                graph.add_edge(
                    finding_node,
                    candidate,
                    EdgeType.EVIDENCES,
                    evidence_ids=[finding.id],
                    label=finding.title[:80],
                )
                break


__all__ = ["AttackGraph", "build_graph"]
