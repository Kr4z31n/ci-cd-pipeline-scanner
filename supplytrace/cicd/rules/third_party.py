"""RULE 10 -- an inventory of every external action and what it can reach.

Unlike the other rules, this one is not primarily looking for a weakness. The
spec asks for a record of each third-party action together with its pinning
status, the permissions and secrets available to it, and whether Git history
shows it being introduced or changed. That record is what the attack-graph
correlator walks when it asks "if this publisher were compromised, what would
they get?".

One finding is emitted per distinct action repository rather than per use, so an
action referenced by twelve workflows is one entry listing twelve call sites.
Severity stays INFO unless the action's own reachability makes it notable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from supplytrace.cicd.evidence.models import (
    EvidenceItem,
    Finding,
    FindingType,
    RelationshipState,
    Severity,
)
from supplytrace.cicd.parser.shell import ShellBehaviour, analyse_run_block
from supplytrace.cicd.rules.base import Rule, ScanContext, job_writes, untrusted_triggers


@dataclass
class ActionUsage:
    """Everything observed about one third-party action across the repository."""

    repo: str
    refs: set[str] = field(default_factory=set)
    call_sites: list[tuple[str, int, str, str]] = field(default_factory=list)
    """(file, line, job, step label) for each use."""
    pinned_uses: int = 0
    unpinned_uses: int = 0
    write_scopes: set[str] = field(default_factory=set)
    secrets: set[str] = field(default_factory=set)
    triggers: set[str] = field(default_factory=set)
    network_neighbours: int = 0
    """Steps in the same job that touch the network."""

    @property
    def is_fully_pinned(self) -> bool:
        return self.unpinned_uses == 0 and self.pinned_uses > 0


class ThirdPartyActionRule(Rule):
    id = "THIRD_PARTY_ACTION"
    name = "Inventory of external actions and their reach"
    rationale = (
        "Every third-party action is code from another repository running inside "
        "this one, with the job's token and secrets in its environment. Knowing "
        "which they are, and what each could reach, is what makes it possible to "
        "answer 'what happens if this publisher is compromised?'."
    )
    references = (
        "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
    )

    def apply(self, context: ScanContext) -> Iterable[Finding]:
        usages = self._inventory(context)

        for repo in sorted(usages):
            usage = usages[repo]
            severity, confidence = self._grade(usage)

            evidence = [
                EvidenceItem(
                    file=file,
                    line=line,
                    snippet=context.snippet_at(file, line),
                    label=f"used in job '{job}'",
                )
                for file, line, job, _ in usage.call_sites[:5]
            ]

            reach: list[str] = []
            if usage.write_scopes:
                reach.append(f"write permissions ({', '.join(sorted(usage.write_scopes))})")
            if usage.secrets:
                reach.append(f"secrets ({', '.join(sorted(usage.secrets))})")
            if usage.triggers:
                reach.append(f"outsider-reachable triggers ({', '.join(sorted(usage.triggers))})")

            pinning = (
                "pinned to a commit SHA at every call site"
                if usage.is_fully_pinned
                else f"referenced by mutable ref(s) {', '.join(sorted(usage.refs))} "
                f"at {usage.unpinned_uses} of {len(usage.call_sites)} call site(s)"
            )

            yield Finding(
                rule_id=self.id,
                type=FindingType.SUPPLY_CHAIN,
                severity=severity,
                confidence=confidence,
                state=RelationshipState.OBSERVED,
                title=f"External action {repo} ({len(usage.call_sites)} use(s))",
                description=(
                    f"{repo} runs inside this repository's workflows and is "
                    f"{pinning}. Code from {repo} therefore has access to "
                    + (
                        f"{', and '.join(reach)}."
                        if reach
                        else "this repository's runners, though no write "
                        "permissions or secrets were found in the jobs using it."
                    )
                    + (
                        f" {usage.network_neighbours} step(s) in the same job(s) "
                        f"contact the network."
                        if usage.network_neighbours
                        else ""
                    )
                ),
                remediation=(
                    f"Pin {repo} to a full commit SHA and review the pinned "
                    f"revision. Keep it out of jobs holding credentials it does "
                    f"not need."
                    if not usage.is_fully_pinned
                    else f"{repo} is pinned. Re-review the pinned revision when "
                    f"you bump it."
                ),
                references=list(self.references),
                file=usage.call_sites[0][0],
                line=usage.call_sites[0][1],
                evidence=evidence,
                metadata={
                    "action_repo": repo,
                    "refs": sorted(usage.refs),
                    "use_count": len(usage.call_sites),
                    "pinned_uses": usage.pinned_uses,
                    "unpinned_uses": usage.unpinned_uses,
                    "reachable_write_scopes": sorted(usage.write_scopes),
                    "reachable_secrets": sorted(usage.secrets),
                    "reachable_triggers": sorted(usage.triggers),
                    "network_neighbour_steps": usage.network_neighbours,
                    "call_sites": [
                        {"file": f, "line": ln, "job": j, "step": s}
                        for f, ln, j, s in usage.call_sites
                    ],
                },
            )

    def _inventory(self, context: ScanContext) -> dict[str, ActionUsage]:
        usages: dict[str, ActionUsage] = {}

        for workflow, job in context.iter_jobs():
            writes = set(job_writes(workflow.effective_permissions(job)))
            secrets = set(workflow.secrets_in_scope(job))
            triggers = set(untrusted_triggers(workflow))
            network_steps = sum(
                1
                for step in job.run_steps()
                if {hit.behaviour for hit in analyse_run_block(step.run)}
                & {
                    ShellBehaviour.DOWNLOAD,
                    ShellBehaviour.OUTBOUND_NETWORK,
                    ShellBehaviour.PIPE_TO_SHELL,
                }
            )

            for step in job.action_steps():
                action = step.uses
                # Local actions and GitHub's own are not third-party supply
                # chain in the sense this inventory is tracking.
                if action is None or action.is_local or action.is_first_party:
                    continue
                if action.is_docker:
                    continue

                usage = usages.setdefault(action.repo, ActionUsage(repo=action.repo))
                usage.refs.add(action.ref or "(none)")
                usage.call_sites.append(
                    (workflow.path, step.location.line, job.id, step.label)
                )
                if action.is_pinned:
                    usage.pinned_uses += 1
                else:
                    usage.unpinned_uses += 1
                usage.write_scopes |= writes
                usage.secrets |= secrets
                usage.triggers |= triggers
                usage.network_neighbours += network_steps

        return usages

    @staticmethod
    def _grade(usage: ActionUsage) -> tuple[Severity, float]:
        """An inventory entry is INFO unless its reach makes it worth reading.

        The unpinned-action finding already carries the severity for the pinning
        problem itself; raising it again here would double-count the same fact.
        """

        if not usage.is_fully_pinned and (usage.write_scopes or usage.secrets):
            return Severity.LOW, 1.0
        return Severity.INFO, 1.0
