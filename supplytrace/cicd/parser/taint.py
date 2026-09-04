"""Track where a secret's *value* actually goes inside a ``run:`` block.

The naive version of secret-exposure detection asks "does this step have a
secret, and does it contain an ``echo``?". That fires on::

    env:
      TOKEN: ${{ secrets.TOKEN }}
    run: echo "starting build"

which leaks nothing. Reporting it teaches a reader to ignore the tool.

This module answers the narrower question the spec actually asks: does the
secret's value reach a sink? It does that with a small amount of taint
propagation over the script text --

* a shell variable assigned from a secret-bearing name becomes tainted, so
  ``KEY=$(echo $SERVICE_ACCOUNT | jq -r .private_key)`` marks ``KEY``; and
* a line is only a leak if it *references* something tainted.

This is a deliberately shallow analysis over one step. It follows assignment
and command substitution, and does not attempt to model control flow, arrays,
or values crossing between steps -- those are reported as "reachable" by the
coarser rules rather than claimed as flows here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Mapping

from supplytrace.cicd.parser.expressions import secret_references
from supplytrace.cicd.parser.shell import ShellBehaviour, ShellHit, analyse_run_block

#: `NAME=value`, `export NAME=value`, and `declare -r NAME=value`.
_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:export\s+|declare\s+(?:-\w+\s+)*|local\s+|readonly\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.*)$"
)

#: `echo "NAME=$VALUE" >> $GITHUB_ENV` -- a value crossing into later steps.
_GITHUB_ENV_WRITE_RE = re.compile(
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>[^\"']*)[\"']?\s*>>\s*[\"']?"
    r"\$\{?GITHUB_(?:ENV|OUTPUT)\}?",
    re.IGNORECASE,
)


def _references(text: str, names: Iterable[str]) -> list[str]:
    """Which of ``names`` this text reads, as ``$NAME`` or ``${NAME}``."""

    found: list[str] = []
    for name in names:
        if re.search(rf"\$\{{?{re.escape(name)}\b\}}?", text):
            found.append(name)
    return found


@dataclass
class SecretFlow:
    """One place a secret's value reaches a sink."""

    secret: str
    """The secret the value originated from."""
    via: str
    """The variable carrying it at this point, or the secret name itself."""
    behaviour: ShellBehaviour
    line_offset: int
    text: str
    derived: bool = False
    """True when the value passed through at least one assignment.

    A derived value is the dangerous case for logging: GitHub masks the exact
    secret string in log output, but a value that has been decoded, parsed or
    re-encoded no longer matches the mask and prints in the clear.
    """

    def snippet(self, limit: int = 160) -> str:
        return self.text if len(self.text) <= limit else self.text[: limit - 3] + "..."


@dataclass
class TaintResult:
    """What a step's script does with the secrets in scope."""

    flows: list[SecretFlow] = field(default_factory=list)
    tainted: dict[str, str] = field(default_factory=dict)
    """Variable name -> the secret it carries."""

    def by_behaviour(self, *behaviours: ShellBehaviour) -> list[SecretFlow]:
        wanted = set(behaviours)
        return [flow for flow in self.flows if flow.behaviour in wanted]

    @property
    def secrets_reaching_sinks(self) -> list[str]:
        return sorted({flow.secret for flow in self.flows})


#: Sinks a tainted value must not reach, and how bad each is.
_SINK_BEHAVIOURS = (
    ShellBehaviour.PRINT_VALUE,
    ShellBehaviour.OUTBOUND_NETWORK,
    ShellBehaviour.WRITE_FILE,
    ShellBehaviour.ENV_EXPORT,
    ShellBehaviour.PIPE_TO_SHELL,
)


def seed_taint(env_maps: Iterable[Mapping[str, object]]) -> dict[str, str]:
    """Environment variables whose value is a secret.

    ``env: {TOKEN: "${{ secrets.API_KEY }}"}`` seeds ``TOKEN -> API_KEY``.
    """

    seeded: dict[str, str] = {}
    for mapping in env_maps:
        for key, value in mapping.items():
            names = secret_references(str(value))
            if names:
                seeded[str(key)] = names[0]
    return seeded


def track_secret_flows(script: str, seeded: Mapping[str, str]) -> TaintResult:
    """Follow secret values through one ``run:`` block.

    ``seeded`` maps environment variable names to the secret each one holds.
    """

    result = TaintResult(tainted=dict(seeded))
    if not script:
        return result

    hits_by_offset: dict[int, list[ShellHit]] = {}
    for hit in analyse_run_block(script):
        hits_by_offset.setdefault(hit.line_offset, []).append(hit)

    derived: set[str] = set()

    for offset, raw_line in enumerate(script.splitlines()):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # A direct `${{ secrets.X }}` in the line taints the line itself.
        inline_secrets = secret_references(line)

        # Propagate through assignment before checking sinks, so that
        # `KEY=$SECRET` on its own line marks KEY without reporting a leak.
        assignment = _ASSIGNMENT_RE.match(line)
        if assignment:
            name = assignment.group("name")
            value = assignment.group("value")
            sources = _references(value, result.tainted)
            if sources:
                result.tainted[name] = result.tainted[sources[0]]
                derived.add(name)
            elif inline_secrets:
                result.tainted[name] = inline_secrets[0]
                derived.add(name)
            # An assignment whose value is only read, not printed, is not
            # itself a sink -- unless it also redirects somewhere.
            if ">" not in value and "|" not in value:
                continue

        env_write = _GITHUB_ENV_WRITE_RE.search(line)
        if env_write:
            sources = _references(env_write.group("value"), result.tainted)
            if sources:
                result.tainted[env_write.group("name")] = result.tainted[sources[0]]
                derived.add(env_write.group("name"))

        referenced = _references(line, result.tainted)
        if not referenced and not inline_secrets:
            continue

        secret = (
            result.tainted[referenced[0]] if referenced else inline_secrets[0]
        )
        via = referenced[0] if referenced else secret
        was_derived = via in derived

        for hit in hits_by_offset.get(offset, []):
            if hit.behaviour not in _SINK_BEHAVIOURS:
                continue
            result.flows.append(
                SecretFlow(
                    secret=secret,
                    via=via,
                    behaviour=hit.behaviour,
                    line_offset=offset,
                    text=line,
                    derived=was_derived,
                )
            )

    return result


__all__ = ["SecretFlow", "TaintResult", "seed_taint", "track_secret_flows"]
