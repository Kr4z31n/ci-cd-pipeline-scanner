"""RULE 1 -- third-party actions referenced by a mutable tag or branch.

``uses: tj-actions/changed-files@v35`` does not name code.  It names a pointer,
and the pointer is under the control of whoever owns that repository.  In March
2025 that pointer was moved on tj-actions/changed-files and every workflow
referencing it by tag began running the attacker's code on the next run, which
is what this rule is for.

Severity is graded by how much the reference can reach, not by the syntax
alone: a branch ref is worse than a version tag, a third party is worse than
GitHub's own org, and an action sitting in a job that holds secrets and write
permissions is worse than one that does not.
"""

from __future__ import annotations

from typing import Iterable

from supplytrace.cicd.evidence.models import (
    EvidenceItem,
    Finding,
    FindingType,
    RelationshipState,
    Severity,
)
from supplytrace.cicd.rules.base import Rule, ScanContext, job_writes

#: Refs that move on every push to the action's default branch.
_BRANCH_REFS = frozenset({"main", "master", "develop", "dev", "trunk", "latest", "HEAD"})


class UnpinnedActionRule(Rule):
    id = "ACTION_UNPINNED"
    name = "Third-party action is not pinned to a commit SHA"
    rationale = (
        "A tag or branch reference is a mutable pointer owned by the action's "
        "publisher. Anyone who can move it -- the publisher, or an attacker who "
        "compromises them -- changes what runs in this repository, with no commit "
        "to this repository and nothing for a reviewer to see."
    )
    references = (
        "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
        "https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066",
    )

    def apply(self, context: ScanContext) -> Iterable[Finding]:
        for workflow, job, step in context.iter_steps():
            action = step.uses
            if action is None or action.is_local or action.is_pinned:
                continue
            # A Docker image tag is a different problem with a different fix
            # (digest pinning); reporting it under this rule's remediation
            # would send the reader to the wrong place.
            if action.is_docker:
                continue
            if not action.ref:
                continue

            permissions = workflow.effective_permissions(job)
            writes = job_writes(permissions)
            secrets = workflow.secrets_in_scope(job)
            is_branch = action.ref in _BRANCH_REFS
            reach: list[str] = []
            if writes:
                reach.append(f"write permissions ({', '.join(sorted(writes))})")
            if secrets:
                reach.append(f"secrets ({', '.join(secrets)})")

            severity, confidence = self._grade(
                is_first_party=action.is_first_party,
                is_branch=is_branch,
                has_reach=bool(reach),
            )

            evidence = [
                EvidenceItem(
                    file=workflow.path,
                    line=step.location.line,
                    snippet=context.snippet_at(workflow.path, step.location.line),
                    label="mutable action reference",
                )
            ]
            _, permissions_line = workflow.permissions_origin(job)
            if writes and permissions_line:
                evidence.append(
                    context.evidence_at(
                        workflow.path,
                        permissions_line,
                        "permissions this action would inherit",
                    )
                )

            kind = "branch" if is_branch else "tag"
            detail = (
                f"Step '{step.label}' in job '{job.id}' uses {action.raw}. "
                f"'{action.ref}' is a {kind}, not an immutable commit. "
                f"{action.repo} can change what this resolves to at any time"
            )
            detail += f", and this job grants it {' and '.join(reach)}." if reach else "."

            yield Finding(
                rule_id=self.id,
                type=FindingType.SUPPLY_CHAIN,
                severity=severity,
                confidence=confidence,
                state=RelationshipState.INFERRED,
                title=f"Unpinned action {action.repo}@{action.ref}",
                description=detail,
                remediation=(
                    f"Pin to a full commit SHA: uses: {action.repo}@<40-char-sha>  "
                    f"# {action.ref}. Keep the tag in a trailing comment so tooling "
                    f"like Dependabot can still offer upgrades."
                ),
                references=list(self.references),
                file=workflow.path,
                line=step.location.line,
                workflow=workflow.display_name,
                job=job.id,
                step=step.label,
                evidence=evidence,
                metadata={
                    "action": action.raw,
                    "action_repo": action.repo,
                    "action_ref": action.ref,
                    "ref_kind": kind,
                    "first_party": action.is_first_party,
                    "job_write_permissions": sorted(writes),
                    "job_secrets": secrets,
                },
            )

    @staticmethod
    def _grade(*, is_first_party: bool, is_branch: bool, has_reach: bool) -> tuple[Severity, float]:
        """Grade the reference by what it can reach.

        Detection confidence stays high throughout -- whether a string is a
        40-character SHA is not a judgement call. What varies is severity.
        """

        if is_first_party:
            # GitHub's own actions are still mutable, but the publisher is the
            # platform the workflow already trusts entirely.
            return (Severity.MEDIUM if is_branch else Severity.LOW), 0.95
        if is_branch and has_reach:
            return Severity.CRITICAL, 0.95
        if is_branch or has_reach:
            return Severity.HIGH, 0.92
        return Severity.MEDIUM, 0.9
