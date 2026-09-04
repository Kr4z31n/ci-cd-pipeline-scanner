"""Parse GitHub Actions workflow files into a located, typed model.

"Located" is the point: every job, step and action keeps the file and line it
came from, so a rule that fires can always be traced back to the YAML a
reviewer would read.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import yaml

from supplytrace.cicd.parser.expressions import (
    ExpressionRef,
    find_expressions,
    secret_references,
)
from supplytrace.cicd.parser.yamlsrc import LineDict, line_of, load_workflow_yaml

#: A 40-hex-character Git object name. Only this counts as a pinned action.
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

#: Triggers that run with the *base* repository's secrets and token while the
#: event itself originates from outside the repository.
FORK_REACHABLE_PRIVILEGED_TRIGGERS = frozenset(
    {
        "pull_request_target",
        "workflow_run",
        "issue_comment",
        "issues",
        "discussion",
        "discussion_comment",
        "pull_request_review",
        "pull_request_review_comment",
    }
)

#: Triggers that carry outsider-authored content. ``pull_request`` is included
#: because the content is untrusted even though the token is not privileged.
FORK_REACHABLE_TRIGGERS = frozenset({"pull_request"}) | FORK_REACHABLE_PRIVILEGED_TRIGGERS

#: GITHUB_TOKEN permission scopes whose write access grants real power.
WRITE_PERMISSION_IMPACT: dict[str, str] = {
    "contents": "push commits, tags and releases to this repository",
    "actions": "modify or cancel workflow runs and workflow files",
    "packages": "publish or overwrite packages in the registry",
    "deployments": "create deployments to protected environments",
    "id-token": "mint an OIDC token and assume a cloud role",
    "pull-requests": "open, edit, merge or comment on pull requests",
    "issues": "open, edit or comment on issues",
    "checks": "create or update check runs",
    "statuses": "set commit statuses that branch protection may trust",
    "security-events": "write code scanning results",
    "attestations": "create provenance attestations",
    "pages": "publish to GitHub Pages",
    "discussions": "create or edit discussions",
    "repository-projects": "modify repository projects",
}


@dataclass(frozen=True)
class Location:
    """Where something was found."""

    file: str
    line: int = 0
    workflow: str | None = None
    job: str | None = None
    step: str | None = None

    def describe(self) -> str:
        parts = [f"{self.file}:{self.line}"]
        if self.job:
            parts.append(f"job={self.job}")
        if self.step:
            parts.append(f"step={self.step}")
        return " ".join(parts)


@dataclass
class ActionRef:
    """A ``uses:`` reference to a reusable action."""

    raw: str
    owner: str = ""
    name: str = ""
    ref: str = ""
    """Whatever followed the ``@``: a tag, a branch, or a full SHA."""
    path: str = ""
    """Subdirectory, for ``owner/repo/sub/dir@ref``."""
    is_local: bool = False
    is_docker: bool = False

    @property
    def repo(self) -> str:
        return f"{self.owner}/{self.name}" if self.owner else self.name

    @property
    def is_pinned(self) -> bool:
        """True only for a full 40-character commit SHA.

        A tag is not a pin: ``v35`` is a mutable pointer that the action's owner
        -- or anyone who compromises them -- can move, which is exactly how the
        tj-actions/changed-files compromise reached its downstream consumers.
        """

        return bool(FULL_SHA_RE.match(self.ref or ""))

    @property
    def is_first_party(self) -> bool:
        """Published by GitHub itself."""

        return self.owner.lower() in {"actions", "github"}

    def __str__(self) -> str:
        return self.raw


def parse_action_ref(raw: str) -> ActionRef:
    """Split a ``uses:`` value into owner, name, subpath and ref."""

    text = (raw or "").strip()
    if text.startswith("./") or text.startswith("../"):
        return ActionRef(raw=text, name=text, is_local=True)
    if text.startswith("docker://"):
        target = text[len("docker://") :]
        image, _, tag = target.partition(":")
        return ActionRef(raw=text, name=image, ref=tag, is_docker=True)

    target, _, ref = text.partition("@")
    segments = [s for s in target.split("/") if s]
    if len(segments) < 2:
        return ActionRef(raw=text, name=target, ref=ref)
    owner, name = segments[0], segments[1]
    path = "/".join(segments[2:])
    return ActionRef(raw=text, owner=owner, name=name, ref=ref, path=path)


@dataclass
class ParsedStep:
    """One step inside a job."""

    index: int
    location: Location
    id: str = ""
    name: str = ""
    uses: ActionRef | None = None
    run: str = ""
    shell: str = ""
    with_: dict[str, Any] = field(default_factory=dict)
    env: dict[str, Any] = field(default_factory=dict)
    if_condition: str = ""
    working_directory: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    run_content_line: int = 0
    """File line of the first line *inside* the ``run:`` block.

    For ``run: |`` the script starts on the following line; for a one-line
    ``run: echo hi`` it starts on the same line. Without this distinction every
    finding inside a block scalar is reported one line off.
    """

    def line_for_run_offset(self, offset: int) -> int:
        """Translate a 0-based line index inside ``run:`` to a file line.

        Searching the file for the matching text instead would collide whenever
        two steps contain the same command, which is common ("echo done").
        """

        if not self.run_content_line:
            return self.location.line
        return self.run_content_line + max(offset, 0)

    @property
    def label(self) -> str:
        """Best available human label for this step."""

        if self.name:
            return self.name
        if self.uses:
            return self.uses.raw
        if self.run:
            return self.run.strip().splitlines()[0][:60]
        return f"step[{self.index}]"

    @property
    def is_checkout(self) -> bool:
        return bool(self.uses and self.uses.repo.lower() == "actions/checkout")

    @property
    def checkout_ref(self) -> str:
        """The ``ref:`` input given to a checkout step, if any."""

        return str(self.with_.get("ref", "") or "")

    def searchable_text(self) -> str:
        """Everything in this step an expression could hide in."""

        chunks: list[str] = [self.run, self.if_condition, self.working_directory]
        for mapping in (self.with_, self.env):
            for key, value in mapping.items():
                chunks.append(f"{key}: {value}")
        if self.uses:
            chunks.append(self.uses.raw)
        return "\n".join(chunk for chunk in chunks if chunk)

    def expressions(self) -> list[ExpressionRef]:
        return find_expressions(self.searchable_text())

    def secrets_used(self) -> list[str]:
        return secret_references(self.searchable_text())


@dataclass
class ParsedJob:
    """One job inside a workflow."""

    id: str
    location: Location
    name: str = ""
    runs_on: str = ""
    needs: list[str] = field(default_factory=list)
    permissions: dict[str, str] | None = None
    """``None`` means the job declared none and inherits the workflow's."""
    permissions_line: int = 0
    env: dict[str, Any] = field(default_factory=dict)
    if_condition: str = ""
    steps: list[ParsedStep] = field(default_factory=list)
    uses_workflow: str = ""
    """Set for a job that calls a reusable workflow instead of running steps."""
    secrets_inherit: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_self_hosted(self) -> bool:
        return "self-hosted" in (self.runs_on or "").lower()

    def action_steps(self) -> list[ParsedStep]:
        return [step for step in self.steps if step.uses is not None]

    def run_steps(self) -> list[ParsedStep]:
        return [step for step in self.steps if step.run]

    def checkout_steps(self) -> list[ParsedStep]:
        return [step for step in self.steps if step.is_checkout]

    def secrets_used(self) -> list[str]:
        names = secret_references("\n".join(f"{k}: {v}" for k, v in self.env.items()))
        for step in self.steps:
            for name in step.secrets_used():
                if name not in names:
                    names.append(name)
        return names


@dataclass
class ParsedWorkflow:
    """One ``.github/workflows/*.yml`` file."""

    path: str
    """Repository-relative path, POSIX separators."""
    name: str = ""
    triggers: dict[str, Any] = field(default_factory=dict)
    trigger_lines: dict[str, int] = field(default_factory=dict)
    permissions: dict[str, str] | None = None
    permissions_line: int = 0
    env: dict[str, Any] = field(default_factory=dict)
    jobs: list[ParsedJob] = field(default_factory=list)
    defaults: dict[str, Any] = field(default_factory=dict)
    concurrency: Any = None
    raw: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    parse_error: str = ""
    """Non-empty when the file could not be read or parsed."""

    @property
    def display_name(self) -> str:
        return self.name or Path(self.path).name

    @property
    def is_parsed(self) -> bool:
        return not self.parse_error

    @property
    def trigger_names(self) -> list[str]:
        return sorted(self.triggers)

    def job(self, job_id: str) -> ParsedJob | None:
        return next((j for j in self.jobs if j.id == job_id), None)

    def all_steps(self) -> Iterator[tuple[ParsedJob, ParsedStep]]:
        for job in self.jobs:
            for step in job.steps:
                yield job, step

    def effective_permissions(self, job: ParsedJob) -> dict[str, str] | None:
        """Permissions actually in force for ``job``.

        A job-level ``permissions:`` block replaces the workflow-level one
        outright -- GitHub does not merge the two -- so a job setting wins
        whenever it exists.
        """

        return job.permissions if job.permissions is not None else self.permissions

    def secrets_in_scope(self, job: ParsedJob) -> list[str]:
        """Every secret available to ``job``, including workflow-level ``env:``.

        A secret set once in the workflow's own ``env:`` block is in the
        environment of every step of every job, so asking the job alone what it
        uses under-reports what an attacker who lands in it would find.
        """

        names = secret_references(
            "\n".join(f"{k}: {v}" for k, v in self.env.items())
        )
        for name in job.secrets_used():
            if name not in names:
                names.append(name)
        return names

    def permissions_origin(self, job: ParsedJob) -> tuple[str, int]:
        """Where the effective permissions came from: job, workflow, or default."""

        if job.permissions is not None:
            return "job", job.permissions_line
        if self.permissions is not None:
            return "workflow", self.permissions_line
        return "default", 0

    def line_of_source(self, needle: str, default: int = 0) -> int:
        """First line in the raw source containing ``needle``.

        Used where the YAML tree cannot give a position -- for example one line
        inside a multi-line ``run:`` block.
        """

        if not needle or not self.source:
            return default
        for number, line in enumerate(self.source.splitlines(), start=1):
            if needle in line:
                return number
        return default


# -- coercion helpers ----------------------------------------------------------


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _as_mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [_as_str(item) for item in value]
    return [_as_str(value)]


def _normalise_runs_on(value: Any) -> str:
    if isinstance(value, dict):
        labels = value.get("labels", value.get("group", ""))
        return ", ".join(_as_list(labels))
    return ", ".join(_as_list(value))


# -- parsing -------------------------------------------------------------------


def _extract_triggers(document: Any) -> tuple[dict[str, Any], dict[str, int]]:
    """Pull the ``on:`` block out of a workflow document.

    YAML 1.1 resolves the bare word ``on`` to the boolean ``True``, so a
    workflow's most important key arrives as ``document[True]``.  Both spellings
    are accepted; missing this is why a naive parser reports zero triggers for
    every workflow ever written.
    """

    key: Any = None
    for candidate in ("on", True, "True"):
        if candidate in document:
            key = candidate
            break
    if key is None:
        return {}, {}

    raw = document[key]
    base_line = document.line_of(key) if isinstance(document, LineDict) else 0
    lines: dict[str, int] = {}

    if isinstance(raw, str):
        return {raw: None}, {raw: base_line}
    if isinstance(raw, list):
        triggers = {_as_str(item): None for item in raw}
        return triggers, {name: base_line for name in triggers}
    if isinstance(raw, dict):
        triggers = {}
        for name, config in raw.items():
            trigger_name = _as_str(name)
            triggers[trigger_name] = config
            lines[trigger_name] = (
                raw.key_line_of(name, base_line)
                if isinstance(raw, LineDict)
                else base_line
            )
        return triggers, lines
    return {}, {}


def _extract_permissions(node: Any) -> dict[str, str] | None:
    """Normalise a ``permissions:`` block into scope -> level.

    Three shapes are legal: a mapping, the shorthand ``read-all``/``write-all``,
    and ``{}`` meaning "no permissions at all".  ``{}`` has to survive as an
    empty dict rather than collapse to ``None``, because an empty block is a
    deliberate hardening choice and the exact opposite of an absent one.
    """

    if node is None:
        return None
    if isinstance(node, str):
        shorthand = node.strip().lower()
        if shorthand == "write-all":
            return {scope: "write" for scope in WRITE_PERMISSION_IMPACT}
        if shorthand == "read-all":
            return {scope: "read" for scope in WRITE_PERMISSION_IMPACT}
        return {}
    if isinstance(node, dict):
        return {_as_str(k): _as_str(v).lower() for k, v in node.items()}
    return None


def _run_content_line(node: Any, source_lines: list[str]) -> int:
    """Where the text of a ``run:`` block actually begins.

    ``run: |`` puts the script on the next line; ``run: echo hi`` puts it on the
    same one. The YAML node reports the same position for both, so the source
    line is inspected for a block indicator to tell them apart.
    """

    if not isinstance(node, LineDict) or "run" not in node:
        return 0
    key_line = node.line_of("run")
    if key_line < 1 or key_line > len(source_lines):
        return key_line
    text = source_lines[key_line - 1]
    _, _, after = text.partition("run:")
    # A block scalar header is `|`, `>`, or those with chomping/indent
    # indicators such as `|-`, `>2`. Anything else is inline content.
    return key_line + 1 if after.strip().rstrip("-+0123456789") in ("|", ">") else key_line


def _parse_step(
    node: Any,
    index: int,
    file: str,
    workflow_name: str,
    job_id: str,
    source_lines: list[str],
) -> ParsedStep:
    mapping = _as_mapping(node)
    line = line_of(node)
    uses_raw = mapping.get("uses")
    step = ParsedStep(
        index=index,
        location=Location(file=file, line=line, workflow=workflow_name, job=job_id),
        id=_as_str(mapping.get("id")),
        name=_as_str(mapping.get("name")),
        uses=parse_action_ref(_as_str(uses_raw)) if uses_raw else None,
        run=_as_str(mapping.get("run")),
        shell=_as_str(mapping.get("shell")),
        with_=_as_mapping(mapping.get("with")),
        env=_as_mapping(mapping.get("env")),
        if_condition=_as_str(mapping.get("if")),
        working_directory=_as_str(mapping.get("working-directory")),
        raw=mapping,
        run_content_line=_run_content_line(node, source_lines),
    )

    # Point at the line that identifies the step, rather than at the step's
    # first key, so a reported location lands on `uses:` or `run:`.
    anchor = line
    if isinstance(node, LineDict):
        for key in ("uses", "run", "name"):
            if key in node:
                anchor = node.line_of(key, line)
                break
    step.location = Location(
        file=file, line=anchor, workflow=workflow_name, job=job_id, step=step.label
    )
    return step


def _parse_job(
    job_id: str,
    node: Any,
    file: str,
    workflow_name: str,
    line: int,
    source_lines: list[str],
) -> ParsedJob:
    mapping = _as_mapping(node)
    sentinel = object()
    permissions_node = mapping.get("permissions", sentinel)
    has_permissions = permissions_node is not sentinel

    job = ParsedJob(
        id=job_id,
        location=Location(file=file, line=line, workflow=workflow_name, job=job_id),
        name=_as_str(mapping.get("name")),
        runs_on=_normalise_runs_on(mapping.get("runs-on")),
        needs=_as_list(mapping.get("needs")),
        permissions=_extract_permissions(permissions_node) if has_permissions else None,
        permissions_line=(
            node.line_of("permissions", line)
            if isinstance(node, LineDict) and has_permissions
            else 0
        ),
        env=_as_mapping(mapping.get("env")),
        if_condition=_as_str(mapping.get("if")),
        uses_workflow=_as_str(mapping.get("uses")),
        secrets_inherit=_as_str(mapping.get("secrets")).lower() == "inherit",
        raw=mapping,
    )

    steps_node = mapping.get("steps") or []
    if isinstance(steps_node, list):
        job.steps = [
            _parse_step(step_node, index, file, workflow_name, job_id, source_lines)
            for index, step_node in enumerate(steps_node)
        ]
    return job


def parse_workflow_text(text: str, path: str) -> ParsedWorkflow:
    """Parse one workflow's YAML source.

    A file that cannot be parsed comes back as a ``ParsedWorkflow`` with
    ``parse_error`` set rather than raising.  A workflow the tool could not read
    is a reportable gap in coverage, not a reason to abandon the scan.
    """

    workflow = ParsedWorkflow(path=path, source=text)
    try:
        document = load_workflow_yaml(text)
    except yaml.YAMLError as exc:
        problem = getattr(exc, "problem", None) or str(exc)
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}" if mark else ""
        workflow.parse_error = f"invalid YAML{where}: {problem}"
        return workflow

    if document is None:
        workflow.parse_error = "file is empty"
        return workflow
    if not isinstance(document, dict):
        workflow.parse_error = (
            f"top level of a workflow must be a mapping, found {type(document).__name__}"
        )
        return workflow

    workflow.raw = dict(document)
    workflow.name = _as_str(document.get("name"))
    workflow.triggers, workflow.trigger_lines = _extract_triggers(document)

    if "permissions" in document:
        workflow.permissions = _extract_permissions(document.get("permissions"))
        workflow.permissions_line = (
            document.line_of("permissions") if isinstance(document, LineDict) else 0
        )

    workflow.env = _as_mapping(document.get("env"))
    workflow.defaults = _as_mapping(document.get("defaults"))
    workflow.concurrency = document.get("concurrency")

    jobs_node = document.get("jobs")
    source_lines = text.splitlines()
    if isinstance(jobs_node, dict):
        for job_id, job_node in jobs_node.items():
            job_line = (
                jobs_node.line_of(job_id)
                if isinstance(jobs_node, LineDict)
                else line_of(job_node)
            )
            workflow.jobs.append(
                _parse_job(
                    _as_str(job_id), job_node, path, workflow.name, job_line, source_lines
                )
            )
    elif jobs_node is not None:
        workflow.parse_error = "'jobs:' must be a mapping of job id to job definition"

    return workflow


def workflow_paths(repo_root: Path) -> list[Path]:
    """Every workflow file under ``.github/workflows``, sorted for stable output."""

    directory = Path(repo_root) / ".github" / "workflows"
    if not directory.is_dir():
        return []
    found = {
        path
        for pattern in ("*.yml", "*.yaml")
        for path in directory.glob(pattern)
        if path.is_file()
    }
    return sorted(found)


def parse_repository_workflows(repo_root: str | Path) -> list[ParsedWorkflow]:
    """Parse every workflow in a repository checkout."""

    root = Path(repo_root)
    workflows: list[ParsedWorkflow] = []
    for path in workflow_paths(root):
        relative = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            broken = ParsedWorkflow(path=relative)
            broken.parse_error = f"could not read file: {exc}"
            workflows.append(broken)
            continue
        workflows.append(parse_workflow_text(text, relative))
    return workflows


__all__ = [
    "ActionRef",
    "FORK_REACHABLE_PRIVILEGED_TRIGGERS",
    "FORK_REACHABLE_TRIGGERS",
    "Location",
    "ParsedJob",
    "ParsedStep",
    "ParsedWorkflow",
    "WRITE_PERMISSION_IMPACT",
    "parse_action_ref",
    "parse_repository_workflows",
    "parse_workflow_text",
    "workflow_paths",
]
