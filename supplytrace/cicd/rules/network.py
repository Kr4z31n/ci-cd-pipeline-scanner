"""RULE 6 -- code fetched from the network and then executed.

Two shapes matter here, and they are the same weakness written differently:

    curl https://host/install.sh | bash          # one line
    curl -o s.sh https://host/i.sh; chmod +x s.sh; ./s.sh   # three

In both, what runs is whatever the host serves at the moment the job runs.
There is no digest, no signature and no review, so the build's integrity is
delegated to that host, its TLS, and its DNS.

A dynamically built URL -- one containing a ``${{ }}`` expression or a shell
variable -- is worse still, because the destination is not fixed even in the
workflow file.
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
from supplytrace.cicd.parser.expressions import find_expressions
from supplytrace.cicd.parser.shell import (
    ShellBehaviour,
    ShellHit,
    analyse_run_block,
    is_common_ci_host,
    urls_in,
)
from supplytrace.cicd.rules.base import Rule, ScanContext, job_writes


class SuspiciousDownloadRule(Rule):
    id = "REMOTE_CODE_FETCH"
    name = "Remote content is downloaded and executed"
    rationale = (
        "Piping a download into a shell executes whatever the server returns at "
        "the moment of the run. The workflow file records the intent but not the "
        "code, so nothing in the repository shows what actually executed."
    )
    references = (
        "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions",
    )

    def apply(self, context: ScanContext) -> Iterable[Finding]:
        for workflow, job, step in context.iter_steps():
            if not step.run:
                continue
            hits = analyse_run_block(step.run)
            if not hits:
                continue

            yield from self._pipe_to_shell(context, workflow, job, step, hits)
            yield from self._download_then_execute(context, workflow, job, step, hits)

    # -- curl | bash -----------------------------------------------------------

    def _pipe_to_shell(
        self, context: ScanContext, workflow, job, step, hits: list[ShellHit]
    ) -> Iterable[Finding]:
        for hit in [h for h in hits if h.behaviour is ShellBehaviour.PIPE_TO_SHELL]:
            line = workflow.line_of_source(hit.text[:60], step.location.line)
            url = hit.detail
            dynamic = self._dynamic_parts(hit.text)
            known_host = bool(url) and is_common_ci_host(url)

            severity, confidence = self._grade(
                known_host=known_host, dynamic=bool(dynamic), writes=bool(job_writes(workflow.effective_permissions(job)))
            )

            description = (
                f"Step '{step.label}' in job '{job.id}' pipes a download straight "
                f"into a shell. What executes is whatever "
                f"{url or 'the remote host'} serves during the run; the repository "
                f"records no digest and no copy of it."
            )
            if dynamic:
                description += (
                    f" The URL is built at run time from {', '.join(dynamic)}, so "
                    f"the destination is not fixed by this file either."
                )
            elif known_host:
                description += (
                    " The host is a well-known CI endpoint, which lowers but does "
                    "not remove the risk."
                )

            yield Finding(
                rule_id=self.id,
                type=FindingType.CODE_EXECUTION,
                severity=severity,
                confidence=confidence,
                state=RelationshipState.OBSERVED,
                title=f"Downloaded script piped to a shell in job '{job.id}'",
                description=description,
                remediation=(
                    "Download to a file, verify a pinned checksum or signature, and "
                    "only then execute it. Better still, install the tool from a "
                    "package manager or a SHA-pinned action."
                ),
                references=list(self.references),
                file=workflow.path,
                line=line,
                workflow=workflow.display_name,
                job=job.id,
                step=step.label,
                evidence=[
                    EvidenceItem(
                        file=workflow.path,
                        line=line,
                        snippet=hit.snippet(),
                        label="fetch piped directly into an interpreter",
                    )
                ],
                metadata={
                    "url": url,
                    "host": url,
                    "dynamic_url_parts": dynamic,
                    "known_ci_host": known_host,
                    "pattern": "pipe_to_shell",
                },
            )

    # -- download, chmod, run --------------------------------------------------

    def _download_then_execute(
        self, context: ScanContext, workflow, job, step, hits: list[ShellHit]
    ) -> Iterable[Finding]:
        # Already reported as the single-line variant; do not report twice.
        if any(h.behaviour is ShellBehaviour.PIPE_TO_SHELL for h in hits):
            return

        downloads = [h for h in hits if h.behaviour is ShellBehaviour.DOWNLOAD]
        executes = [
            h
            for h in hits
            if h.behaviour
            in (ShellBehaviour.MAKE_EXECUTABLE, ShellBehaviour.EXECUTE_LOCAL, ShellBehaviour.EVAL)
        ]
        if not downloads or not executes:
            return

        download = downloads[0]
        execute = executes[0]
        # Order matters: fetching after running is not this pattern.
        if execute.line_offset < download.line_offset:
            return

        url = download.detail
        known_host = bool(url) and is_common_ci_host(url)
        dynamic = self._dynamic_parts(download.text)
        download_line = workflow.line_of_source(download.text[:60], step.location.line)
        execute_line = workflow.line_of_source(execute.text[:60], step.location.line)

        severity, confidence = self._grade(
            known_host=known_host,
            dynamic=bool(dynamic),
            writes=bool(job_writes(workflow.effective_permissions(job))),
        )

        yield Finding(
            rule_id=self.id,
            type=FindingType.CODE_EXECUTION,
            severity=severity,
            # Split across lines, so the link between fetch and execute is an
            # inference about intent rather than a single observed pipeline.
            confidence=max(confidence - 0.1, 0.4),
            state=RelationshipState.INFERRED,
            title=f"Downloaded file made executable and run in job '{job.id}'",
            description=(
                f"Step '{step.label}' in job '{job.id}' fetches "
                f"{url or 'a remote file'} and then runs it "
                f"({execute.behaviour.value.lower().replace('_', ' ')}). No checksum "
                f"or signature verification was found between the two."
                + (
                    f" The URL is built at run time from {', '.join(dynamic)}."
                    if dynamic
                    else ""
                )
            ),
            remediation=(
                "Verify the downloaded file against a checksum pinned in the "
                "repository before executing it."
            ),
            references=list(self.references),
            file=workflow.path,
            line=download_line,
            workflow=workflow.display_name,
            job=job.id,
            step=step.label,
            evidence=[
                EvidenceItem(
                    file=workflow.path,
                    line=download_line,
                    snippet=download.snippet(),
                    label="download",
                ),
                EvidenceItem(
                    file=workflow.path,
                    line=execute_line,
                    snippet=execute.snippet(),
                    label="execution of the downloaded file",
                ),
            ],
            metadata={
                "url": url,
                "dynamic_url_parts": dynamic,
                "known_ci_host": known_host,
                "pattern": "download_then_execute",
                "execute_behaviour": execute.behaviour.value,
            },
        )

    # -- helpers ---------------------------------------------------------------

    @staticmethod
    def _dynamic_parts(text: str) -> list[str]:
        """Expressions or shell variables that make a URL non-constant."""

        parts = [ref.raw for ref in find_expressions(text)]
        for url in urls_in(text):
            if "$" in url:
                parts.append(url)
        return sorted(set(parts))

    @staticmethod
    def _grade(*, known_host: bool, dynamic: bool, writes: bool) -> tuple[Severity, float]:
        if dynamic:
            return Severity.CRITICAL, 0.85
        if known_host:
            # `curl https://sh.rustup.rs | sh` is how the documented installer
            # works. Worth flagging, not worth an alarm.
            return Severity.LOW, 0.9
        if writes:
            return Severity.HIGH, 0.9
        return Severity.MEDIUM, 0.9
