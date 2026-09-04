"""GitHub Actions expression extraction and trust classification.

A ``${{ ... }}`` expression is where most Actions vulnerabilities begin, but the
interesting question is never "is there an expression?" -- almost every workflow
has some.  It is "can an outsider choose what this expands to?".

So expressions are split three ways:

``UNTRUSTED``
    An outsider can set the value directly.  A pull request title is free text
    typed by whoever opened the PR.

``ATTACKER_INFLUENCED``
    An outsider has partial or indirect control: a branch name is constrained by
    Git's ref rules but still largely attacker-chosen, and a third-party action's
    output is only as trustworthy as that action.

``TRUSTED``
    Set by GitHub or the repository owner: ``github.repository``, ``runner.os``.

Only the first two make an interpolation into a shell command a finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

#: Matches one ``${{ ... }}`` interpolation, non-greedy so adjacent
#: expressions on one line stay separate.
EXPRESSION_RE = re.compile(r"\$\{\{\s*(?P<body>.*?)\s*\}\}", re.DOTALL)


class Trust(str, Enum):
    """How much control an outsider has over an expression's value."""

    UNTRUSTED = "UNTRUSTED"
    ATTACKER_INFLUENCED = "ATTACKER_INFLUENCED"
    TRUSTED = "TRUSTED"


#: Contexts an outsider fills in with free text.  These are the ones that turn
#: a ``run:`` block into remote code execution when interpolated unquoted.
#: Sourced from GitHub's own "untrusted input" guidance.
_UNTRUSTED_CONTEXTS: tuple[str, ...] = (
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.discussion_comment.body",
    "github.event.commits",
    "github.event.head_commit.message",
    "github.event.head_commit.author.name",
    "github.event.head_commit.author.email",
    "github.event.commits.*.message",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.event.pull_request.head.ref",
)

#: Partially attacker-controlled: constrained in form, but still chosen by an
#: outsider, or produced by code the repository does not own.
_INFLUENCED_CONTEXTS: tuple[str, ...] = (
    "github.head_ref",
    "github.ref_name",
    "github.ref",
    "github.actor",
    "github.triggering_actor",
    "github.event.pull_request.number",
    "github.event.pull_request.head.sha",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_sha",
)

#: Contexts whose value the repository owner controls.
_TRUSTED_PREFIXES: tuple[str, ...] = (
    "github.repository",
    "github.repository_owner",
    "github.workspace",
    "github.sha",
    "github.run_id",
    "github.run_number",
    "github.workflow",
    "github.job",
    "github.api_url",
    "github.server_url",
    "runner.",
    "matrix.",
    "strategy.",
    "job.",
    "vars.",
    "env.",
)


@dataclass(frozen=True)
class ExpressionRef:
    """One ``${{ ... }}`` occurrence and what it refers to."""

    raw: str
    """The full interpolation as written, e.g. ``${{ github.head_ref }}``."""
    body: str
    """The inner text, e.g. ``github.head_ref``."""
    trust: Trust
    context: str
    """The dotted context path this reference is classified on."""
    line_offset: int = 0
    """0-based line within the enclosing scalar where this appeared."""

    @property
    def is_dangerous(self) -> bool:
        return self.trust is not Trust.TRUSTED


def _normalise(body: str) -> str:
    return body.strip().lower()


def _classify_context(body: str) -> tuple[Trust, str]:
    """Classify one expression body, returning its trust and matched context."""

    text = _normalise(body)

    # A step output comes from whatever action produced it. `changed-files`
    # returning a filename with a `;` in it is exactly the GHSL-2023-271 bug,
    # so outputs are treated as influenced rather than trusted.
    if "steps." in text and ".outputs." in text:
        match = re.search(r"steps\.[\w\-]+\.outputs\.[\w\-]+", text)
        return Trust.ATTACKER_INFLUENCED, match.group(0) if match else "steps.*.outputs.*"

    # `needs.<job>.outputs.<name>` carries whatever an upstream job computed.
    if text.startswith("needs.") and ".outputs." in text:
        match = re.search(r"needs\.[\w\-]+\.outputs\.[\w\-]+", text)
        return Trust.ATTACKER_INFLUENCED, match.group(0) if match else "needs.*.outputs.*"

    for context in _UNTRUSTED_CONTEXTS:
        if context in text:
            return Trust.UNTRUSTED, context

    for context in _INFLUENCED_CONTEXTS:
        if re.search(rf"\b{re.escape(context)}\b", text):
            return Trust.ATTACKER_INFLUENCED, context

    # `inputs.*` on workflow_dispatch/workflow_call is supplied by the caller.
    if re.search(r"\b(inputs|github\.event\.inputs)\.[\w\-]+", text):
        match = re.search(r"\b(?:inputs|github\.event\.inputs)\.[\w\-]+", text)
        return Trust.ATTACKER_INFLUENCED, match.group(0) if match else "inputs.*"

    for prefix in _TRUSTED_PREFIXES:
        if text.startswith(prefix):
            return Trust.TRUSTED, prefix.rstrip(".")

    # An unrecognised `github.event.*` path is still event payload, and event
    # payload is attacker-shaped on any fork-reachable trigger. Defaulting this
    # to trusted would silently miss whatever GitHub adds next.
    if text.startswith("github.event."):
        match = re.search(r"github\.event\.[\w.\[\]\*\-]+", text)
        return Trust.ATTACKER_INFLUENCED, match.group(0) if match else "github.event.*"

    return Trust.TRUSTED, text.split("(")[0].strip() or "unknown"


def find_expressions(text: str) -> list[ExpressionRef]:
    """Every ``${{ ... }}`` in ``text``, classified by trust."""

    if not text or "${{" not in text:
        return []

    refs: list[ExpressionRef] = []
    for match in EXPRESSION_RE.finditer(text):
        body = match.group("body")
        trust, context = _classify_context(body)
        refs.append(
            ExpressionRef(
                raw=match.group(0),
                body=body.strip(),
                trust=trust,
                context=context,
                line_offset=text.count("\n", 0, match.start()),
            )
        )
    return refs


def dangerous_expressions(text: str) -> list[ExpressionRef]:
    """Only the expressions an outsider can influence."""

    return [ref for ref in find_expressions(text) if ref.is_dangerous]


def secret_references(text: str) -> list[str]:
    """Names of every secret referenced in ``text``.

    ``secrets.GITHUB_TOKEN`` and the bare ``github.token`` are both reported as
    ``GITHUB_TOKEN`` so downstream rules do not have to special-case spelling.
    """

    if not text:
        return []

    names: list[str] = []
    for match in re.finditer(r"secrets\.([A-Za-z_][\w\-]*)", text):
        names.append(match.group(1))
    if re.search(r"\bgithub\.token\b", text, re.IGNORECASE):
        names.append("GITHUB_TOKEN")
    # Preserve first-seen order while removing duplicates.
    seen: set[str] = set()
    ordered: list[str] = []
    for name in names:
        if name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered
