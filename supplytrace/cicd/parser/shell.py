"""Recognise security-relevant behaviour in ``run:`` shell blocks.

This is deliberately pattern matching over text rather than a real shell parse.
A workflow's ``run:`` block is Bash with GitHub expressions spliced in before
the shell ever sees it, so it is frequently not valid shell at parse time.  What
the rules actually need is narrower than a parse: which lines fetch something
from the network, which lines execute what was fetched, and which lines send
data outward.

Each helper returns the *line* it matched on so a finding can cite it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class ShellBehaviour(str, Enum):
    """A category of security-relevant shell activity."""

    DOWNLOAD = "DOWNLOAD"
    PIPE_TO_SHELL = "PIPE_TO_SHELL"
    MAKE_EXECUTABLE = "MAKE_EXECUTABLE"
    EXECUTE_LOCAL = "EXECUTE_LOCAL"
    OUTBOUND_NETWORK = "OUTBOUND_NETWORK"
    PRINT_VALUE = "PRINT_VALUE"
    WRITE_FILE = "WRITE_FILE"
    ENV_EXPORT = "ENV_EXPORT"
    PACKAGE_PUBLISH = "PACKAGE_PUBLISH"
    GIT_PUSH = "GIT_PUSH"
    EVAL = "EVAL"


@dataclass(frozen=True)
class ShellHit:
    """One matched behaviour inside a ``run:`` block."""

    behaviour: ShellBehaviour
    line_offset: int
    """0-based line index within the run block."""
    text: str
    """The matched line, stripped."""
    detail: str = ""
    """What was matched, e.g. the URL or the target file."""

    def snippet(self, limit: int = 160) -> str:
        return self.text if len(self.text) <= limit else self.text[: limit - 3] + "..."


#: Commands that fetch a remote resource.
_DOWNLOAD_RE = re.compile(
    r"\b(?:curl|wget|aria2c|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b", re.IGNORECASE
)

#: A fetch whose output is piped straight into an interpreter. The classic
#: `curl ... | bash`, including the `| sudo bash` and `| python` variants.
_PIPE_TO_SHELL_RE = re.compile(
    r"(?:curl|wget|aria2c|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b[^|\n]*"
    r"\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|k|da|fi)?sh\b"
    r"|(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:python[23]?|perl|ruby|node)\b",
    re.IGNORECASE,
)

#: A URL. Kept loose: the host is what matters, not strict RFC conformance.
_URL_RE = re.compile(r"https?://[^\s'\"<>|)\\]+", re.IGNORECASE)

_CHMOD_EXEC_RE = re.compile(r"\bchmod\s+(?:[+-]?\S*x\S*|[0-7]*[1357][0-7]*)\s+(?P<target>\S+)")

#: Running something from the working directory or /tmp.
_EXECUTE_LOCAL_RE = re.compile(
    r"(?:^|[;&|]\s*)(?:sudo\s+)?(?:\./|/tmp/|\$\{?(?:RUNNER_TEMP|GITHUB_WORKSPACE|HOME)\}?/)\S+"
)

_EVAL_RE = re.compile(r"\beval\s|\bsource\s+/tmp/|\bbash\s+-c\b|\bsh\s+-c\b|\bIEX\b|\bInvoke-Expression\b")

#: Commands that move data outward. `curl -d`, `nc`, DNS lookups used as a
#: side channel, and `mail`.
_EXFIL_RE = re.compile(
    r"\bcurl\b[^\n]*(?:\s-(?:d|F|T|-data\S*|-upload-file|-form)\b)"
    r"|\bwget\b[^\n]*--post-(?:data|file)\b"
    r"|\b(?:nc|ncat|netcat|socat)\b"
    r"|\b(?:dig|nslookup|host)\b"
    r"|\b(?:mail|sendmail|mailx)\b",
    re.IGNORECASE,
)

_PRINT_RE = re.compile(r"^\s*(?:echo|printf|print|cat|Write-Host|Write-Output)\b", re.IGNORECASE)

#: Writing into a file, including the GitHub Actions output/env files.
_WRITE_FILE_RE = re.compile(r">>?\s*(?P<target>[^\s;&|]+)|\btee\s+(?:-a\s+)?(?P<tee>\S+)")

_ENV_EXPORT_RE = re.compile(r">>\s*[\"']?\$(?:\{)?GITHUB_(?:ENV|OUTPUT|PATH)(?:\})?", re.IGNORECASE)

_PUBLISH_RE = re.compile(
    r"\bnpm\s+publish\b|\byarn\s+publish\b|\bpnpm\s+publish\b"
    r"|\btwine\s+upload\b|\bpython\s+-m\s+twine\b|\bflit\s+publish\b|\bpoetry\s+publish\b"
    r"|\bcargo\s+publish\b|\bgem\s+push\b|\bmvn\s+deploy\b|\bgradle\s+publish\b"
    r"|\bdocker\s+push\b|\bgh\s+release\s+(?:create|upload)\b|\bnuget\s+push\b"
    r"|\bhelm\s+push\b|\baws\s+s3\s+(?:cp|sync)\b",
    re.IGNORECASE,
)

_GIT_PUSH_RE = re.compile(r"\bgit\s+push\b|\bgit\s+tag\b[^\n]*\n?[^\n]*\bgit\s+push\b", re.IGNORECASE)

#: Hosts that are ordinary CI infrastructure. A fetch from these is normal and
#: should not, on its own, read as exfiltration.
COMMON_CI_HOSTS: frozenset[str] = frozenset(
    {
        "github.com",
        "api.github.com",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
        "codeload.github.com",
        "ghcr.io",
        "registry.npmjs.org",
        "pypi.org",
        "files.pythonhosted.org",
        "crates.io",
        "static.crates.io",
        "proxy.golang.org",
        "sum.golang.org",
        "repo.maven.apache.org",
        "rubygems.org",
        "packagist.org",
        "deb.debian.org",
        "archive.ubuntu.com",
        "security.ubuntu.com",
        "azure.archive.ubuntu.com",
        "nodejs.org",
        "go.dev",
        "golang.org",
        "sh.rustup.rs",
        "get.docker.com",
    }
)


def host_of(url: str) -> str:
    """Hostname of ``url``, lowercased, without port or credentials."""

    match = re.match(r"https?://(?:[^@/\s]*@)?(?P<host>[^/:\s?#]+)", url, re.IGNORECASE)
    return match.group("host").lower() if match else ""


def is_common_ci_host(url_or_host: str) -> bool:
    """True for hosts a normal build legitimately contacts.

    A subdomain of a known host counts: ``uk.archive.ubuntu.com`` is still
    Ubuntu's mirror network.
    """

    host = host_of(url_or_host) or url_or_host.strip().lower()
    if not host:
        return False
    return any(host == known or host.endswith("." + known) for known in COMMON_CI_HOSTS)


def urls_in(text: str) -> list[str]:
    """Every URL appearing in ``text``."""

    return _URL_RE.findall(text or "")


def _strip_comment(line: str) -> str:
    """Drop a trailing ``#`` comment, ignoring ``#`` inside quotes.

    Without this, the commented-out examples that fill teaching repositories
    would all be reported as live behaviour.
    """

    result: list[str] = []
    quote: str | None = None
    for char in line:
        if quote:
            result.append(char)
            if char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
            result.append(char)
            continue
        if char == "#":
            break
        result.append(char)
    return "".join(result)


def analyse_run_block(script: str) -> list[ShellHit]:
    """Every security-relevant behaviour in one ``run:`` block."""

    if not script:
        return []

    hits: list[ShellHit] = []
    for offset, raw_line in enumerate(script.splitlines()):
        line = _strip_comment(raw_line).strip()
        if not line:
            continue

        def add(behaviour: ShellBehaviour, detail: str = "") -> None:
            hits.append(
                ShellHit(
                    behaviour=behaviour, line_offset=offset, text=line.strip(), detail=detail
                )
            )

        urls = urls_in(line)

        if _PIPE_TO_SHELL_RE.search(line):
            add(ShellBehaviour.PIPE_TO_SHELL, urls[0] if urls else "")
        if _DOWNLOAD_RE.search(line):
            add(ShellBehaviour.DOWNLOAD, urls[0] if urls else "")

        chmod = _CHMOD_EXEC_RE.search(line)
        if chmod:
            add(ShellBehaviour.MAKE_EXECUTABLE, chmod.group("target"))

        if _EXECUTE_LOCAL_RE.search(line):
            add(ShellBehaviour.EXECUTE_LOCAL)
        if _EVAL_RE.search(line):
            add(ShellBehaviour.EVAL)
        if _EXFIL_RE.search(line):
            add(ShellBehaviour.OUTBOUND_NETWORK, urls[0] if urls else "")
        if _PRINT_RE.search(line):
            add(ShellBehaviour.PRINT_VALUE)
        if _ENV_EXPORT_RE.search(line):
            add(ShellBehaviour.ENV_EXPORT)
        elif _WRITE_FILE_RE.search(line):
            match = _WRITE_FILE_RE.search(line)
            target = (match.group("target") or match.group("tee") or "") if match else ""
            add(ShellBehaviour.WRITE_FILE, target)
        if _PUBLISH_RE.search(line):
            add(ShellBehaviour.PACKAGE_PUBLISH)
        if _GIT_PUSH_RE.search(line):
            add(ShellBehaviour.GIT_PUSH)

    return hits


def behaviours_of(script: str) -> set[ShellBehaviour]:
    """The distinct behaviours present in a run block."""

    return {hit.behaviour for hit in analyse_run_block(script)}


def external_urls(script: str) -> list[str]:
    """URLs in ``script`` that are not ordinary CI infrastructure."""

    return [url for url in urls_in(script) if not is_common_ci_host(url)]


__all__ = [
    "COMMON_CI_HOSTS",
    "ShellBehaviour",
    "ShellHit",
    "analyse_run_block",
    "behaviours_of",
    "external_urls",
    "host_of",
    "is_common_ci_host",
    "urls_in",
]
