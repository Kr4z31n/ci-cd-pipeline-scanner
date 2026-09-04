"""Phase 1: Git repository analysis.

Extracts repository metadata, refs, commits, authors and per-commit file changes
using two hardened, NUL-delimited ``git log`` passes:

1. **Metadata pass** - ``git log -z --format=...`` yields one NUL-terminated
   record per commit (SHA, parents, author, committer, timestamps, message).
2. **Diff pass** - ``git log --format=%x0cC%H --raw --numstat -z`` yields, per
   commit, the ``--raw`` entries (status letter + rename similarity score) and
   the ``--numstat`` entries (added/deleted line counts).

Both passes use ``-z`` because repository paths are arbitrary byte strings: they
may contain spaces, newlines, quotes or non-UTF-8 bytes.  Any line-oriented
parse of ``git log`` output is wrong for a hostile repository, and a provenance
tool that mis-attributes a path is worse than useless.

Parsing is positional (a state machine), not pattern-matched, so a file whose
name happens to look like a record header cannot forge a record boundary.
"""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import PurePosixPath

from supplytrace import __version__
from supplytrace.core.config import AnalysisConfig
from supplytrace.core.errors import GitCommandError
from supplytrace.core.git_command import GitRunner
from supplytrace.core.logging import get_logger, get_redacting_filter
from supplytrace.models.commit import CommitRecord, Identity
from supplytrace.models.evidence import (
    Confidence,
    git_diff_evidence,
    git_log_evidence,
)
from supplytrace.models.file import (
    ChangeStatus,
    FileCategory,
    FileChange,
    classify_file,
    rename_confidence,
)
from supplytrace.models.repository import (
    AnalysisStats,
    AuthorSummary,
    BranchRef,
    ParseAnomaly,
    RefKind,
    RepositoryAnalysis,
    RepositoryInfo,
)

logger = get_logger("git_analyzer")

#: Unit separator between fields of one commit-metadata record.
FIELD_SEP = "\x1f"
#: Prefix marking a commit header inside the diff stream.  Form feed is used
#: because it is vanishingly rare in paths, and the header is additionally
#: validated as an exact 40-hex SHA before being accepted.
DIFF_HEADER_PREFIX = "\x0cC"

_METADATA_FORMAT = FIELD_SEP.join(
    ["%H", "%P", "%an", "%ae", "%aI", "%cn", "%ce", "%cI", "%B"]
)
_METADATA_FIELD_COUNT = 9

_HEX = set("0123456789abcdef")


def _is_sha(value: str) -> bool:
    return len(value) == 40 and all(char in _HEX for char in value)


def _decode_path(raw: str) -> tuple[str, bool]:
    """Return a JSON-safe path plus a flag telling whether information was lost.

    Git paths are bytes.  ``GitResult.text`` decodes with ``surrogateescape``,
    so undecodable bytes survive as lone surrogates, which cannot be serialised.
    Rather than silently mangling the path, replace the bad bytes and report the
    loss so the investigator knows the recorded path is approximate.
    """

    try:
        raw.encode("utf-8")
    except UnicodeEncodeError:
        recovered = raw.encode("utf-8", errors="surrogateescape")
        return recovered.decode("utf-8", errors="replace"), True
    return raw, False


def _parse_int(value: str) -> int | None:
    """numstat uses ``-`` for binary files, where line counts do not exist."""

    if value == "-":
        return None
    try:
        return int(value)
    except ValueError:
        return None


class GitAnalyzer:
    """Analyses one Git repository and produces a :class:`RepositoryAnalysis`."""

    def __init__(
        self,
        repo_path: str,
        config: AnalysisConfig | None = None,
        *,
        runner: GitRunner | None = None,
    ) -> None:
        self.config = config or AnalysisConfig()
        self.runner = runner or GitRunner(repo_path, self.config)
        self.anomalies: list[ParseAnomaly] = []

    # -- public API -----------------------------------------------------------

    def analyze(self) -> RepositoryAnalysis:
        """Run the full Phase 1 analysis."""

        started = time.monotonic()
        self.anomalies = []
        self.runner.ensure_repository()

        repository = self.collect_repository_info()
        branches = self.collect_refs()
        commits = self.collect_commits()

        if commits:
            changes_by_sha = self.collect_file_changes()
            commits = self._attach_file_changes(commits, changes_by_sha)

        authors = self._summarize_authors(commits)
        stats = self._compute_stats(commits, branches)

        return RepositoryAnalysis(
            tool_version=__version__,
            config=self.config,
            repository=repository,
            branches=branches,
            commits=commits,
            authors=authors,
            stats=stats,
            anomalies=list(self.anomalies),
            duration_seconds=time.monotonic() - started,
        )

    # -- repository -----------------------------------------------------------

    def collect_repository_info(self) -> RepositoryInfo:
        runner = self.runner
        work_tree = runner.toplevel()
        head_sha = runner.line(["rev-parse", "HEAD"]) or None
        if head_sha and not _is_sha(head_sha):
            head_sha = None
        head_ref = runner.line(["symbolic-ref", "-q", "--short", "HEAD"]) or None

        is_shallow = runner.is_shallow()
        if is_shallow:
            self._record_anomaly(
                "repository",
                "Repository is a shallow clone; commit history is incomplete and "
                "provenance results may be missing the true origin of code.",
            )

        return RepositoryInfo(
            path=str(runner.repo_path),
            git_dir=str(runner.git_dir()),
            work_tree=str(work_tree) if work_tree else None,
            is_bare=runner.is_bare(),
            is_shallow=is_shallow,
            head_sha=head_sha,
            head_ref=head_ref,
            default_branch_guess=self._guess_default_branch(head_ref),
            remotes=self._collect_remotes(),
            git_version=runner.version(),
        )

    def _guess_default_branch(self, head_ref: str | None) -> str | None:
        origin_head = self.runner.line(
            ["symbolic-ref", "-q", "--short", "refs/remotes/origin/HEAD"]
        )
        if origin_head:
            return origin_head.split("/", 1)[-1]
        if head_ref:
            return head_ref
        for candidate in ("main", "master"):
            probe = self.runner.run(
                ["show-ref", "--verify", "--quiet", f"refs/heads/{candidate}"],
                check=False,
            )
            if probe.returncode == 0:
                return candidate
        return None

    def _collect_remotes(self) -> dict[str, str]:
        """Collect remote URLs, redacting any embedded credentials.

        Remote URLs are a common accidental credential leak
        (``https://user:token@host/...``).  They are redacted before they can
        reach a report file or a log line.
        """

        text = self.runner.line(["remote", "-v"])
        redactor = get_redacting_filter()
        remotes: dict[str, str] = {}
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                remotes.setdefault(parts[0], redactor.redact(parts[1]))
        return remotes

    # -- refs -----------------------------------------------------------------

    def collect_refs(self) -> list[BranchRef]:
        """Collect branches, remote branches and tags.

        Ref names cannot contain whitespace or control characters, so
        line-oriented parsing is safe here (unlike for paths).
        """

        result = self.runner.run(
            [
                "for-each-ref",
                f"--format=%(refname){FIELD_SEP}%(objecttype){FIELD_SEP}"
                f"%(objectname){FIELD_SEP}%(*objectname)",
                "refs/heads",
                "refs/remotes",
                "refs/tags",
            ],
            check=False,
        )
        if result.returncode != 0:
            self._record_anomaly("refs", f"for-each-ref failed: {result.stderr.strip()}")
            return []

        head_ref = self.runner.line(["symbolic-ref", "-q", "HEAD"])
        refs: list[BranchRef] = []
        for line in result.text.splitlines():
            if not line.strip():
                continue
            parts = line.split(FIELD_SEP)
            if len(parts) < 4:
                self._record_anomaly("refs", "malformed for-each-ref record", line[:200])
                continue
            refname, objectname, peeled = parts[0], parts[2], parts[3]

            # An annotated tag's own object is not a commit; the peeled value is.
            target = peeled or objectname
            if not _is_sha(target):
                self._record_anomaly("refs", f"ref {refname} has no commit target", line[:200])
                continue

            if refname.startswith("refs/heads/"):
                kind, name = RefKind.BRANCH, refname[len("refs/heads/"):]
            elif refname.startswith("refs/remotes/"):
                kind, name = RefKind.REMOTE_BRANCH, refname[len("refs/remotes/"):]
            elif refname.startswith("refs/tags/"):
                kind, name = RefKind.TAG, refname[len("refs/tags/"):]
            else:  # pragma: no cover - filtered by the ref globs above
                continue

            # Remote HEAD pointers are symbolic aliases, not real branches.
            if kind is RefKind.REMOTE_BRANCH and name.endswith("/HEAD"):
                continue

            refs.append(
                BranchRef(
                    name=name,
                    full_ref=refname,
                    target_sha=target,
                    kind=kind,
                    is_head=refname == head_ref,
                )
            )
        refs.sort(key=lambda ref: (ref.kind.value, ref.name))
        return refs

    # -- commits --------------------------------------------------------------

    def _revision_args(self) -> list[str]:
        args: list[str] = ["--date-order"]
        args.append("--all" if self.config.include_all_refs else "HEAD")
        if self.config.max_commits is not None:
            args += ["--max-count", str(self.config.max_commits)]
        return args

    def collect_commits(self) -> list[CommitRecord]:
        """Metadata pass: one NUL-terminated record per commit."""

        if not self.runner.has_commits() and not self.config.include_all_refs:
            return []

        try:
            result = self.runner.run(
                ["log", "-z", f"--format={_METADATA_FORMAT}", *self._revision_args()]
            )
        except GitCommandError as exc:
            # An initialised repository with no commits is a valid state.
            if "does not have any commits" in exc.stderr:
                return []
            raise

        commits: list[CommitRecord] = []
        for record in result.text.split("\0"):
            if not record.strip("\n"):
                continue
            parsed = self._parse_commit_record(record)
            if parsed is not None:
                commits.append(parsed)
        return commits

    def _parse_commit_record(self, record: str) -> CommitRecord | None:
        # The message is the last field and is attacker-controlled free text, so
        # a bounded split keeps any stray separators inside the message instead
        # of letting them shift the earlier fields.
        fields = record.split(FIELD_SEP, _METADATA_FIELD_COUNT - 1)
        if len(fields) != _METADATA_FIELD_COUNT:
            self._record_anomaly(
                "commits", "malformed commit record (wrong field count)", record[:200]
            )
            return None

        sha, parents_raw, an, ae, ai, cn, ce, ci, message = fields
        sha = sha.strip()
        if not _is_sha(sha):
            self._record_anomaly("commits", "record without a valid SHA", record[:200])
            return None

        authored = self._parse_timestamp(ai, sha, "author")
        if authored is None:
            return None

        parents = [p for p in parents_raw.split() if _is_sha(p)]

        return CommitRecord(
            commit_sha=sha,
            author_name=an,
            author_email=ae,
            committer_name=cn,
            committer_email=ce,
            timestamp=authored,
            committed_timestamp=self._parse_timestamp(ci, sha, "committer"),
            message=message.rstrip("\n"),
            parent_commits=parents,
            evidence=git_log_evidence(commit=sha, command="git log"),
        )

    def _parse_timestamp(self, value: str, sha: str, kind: str) -> datetime | None:
        try:
            return datetime.fromisoformat(value.strip())
        except ValueError:
            self._record_anomaly(
                "commits", f"unparseable {kind} timestamp on {sha}", value[:80]
            )
            return None

    # -- file changes ---------------------------------------------------------

    def collect_file_changes(self) -> dict[str, list[FileChange]]:
        """Diff pass: ``--raw`` (status + similarity) merged with ``--numstat``."""

        args = [
            "log",
            f"--format={DIFF_HEADER_PREFIX}%H",
            "--raw",
            "--numstat",
            "-z",
        ]
        if self.config.detect_renames:
            args.append(f"-M{self.config.rename_threshold}%")
        else:
            args.append("--no-renames")
        if self.config.detect_copies:
            args.append(f"-C{self.config.rename_threshold}%")
        args.append(f"--diff-merges={self.config.diff_merges}")
        args += self._revision_args()

        result = self.runner.run(args)
        return self._parse_diff_stream(result.text)

    def _parse_diff_stream(self, text: str) -> dict[str, list[FileChange]]:
        """Positional parse of the combined raw+numstat NUL-delimited stream.

        Layout per commit::

            \\x0cC<sha>\\0 [\\n] (:<modes> <blobs> <STATUS>\\0<path>\\0[<path2>\\0])*
                              (<add>\\t<del>\\t<path>\\0 | <add>\\t<del>\\t\\0<old>\\0<new>\\0)*

        Path tokens are consumed by position, never by pattern, so no filename
        can be mistaken for a record header.
        """

        tokens = text.split("\0")
        raw_by_commit: dict[str, dict[str, dict]] = defaultdict(dict)
        numstat_by_commit: dict[str, dict[str, tuple[int | None, int | None]]] = defaultdict(dict)
        order: dict[str, list[str]] = defaultdict(list)

        current: str | None = None
        index = 0
        total = len(tokens)

        while index < total:
            token = tokens[index]
            probe = token.lstrip("\n")

            if not probe:
                index += 1
                continue

            if probe.startswith(DIFF_HEADER_PREFIX):
                candidate = probe[len(DIFF_HEADER_PREFIX):]
                if _is_sha(candidate):
                    current = candidate
                    index += 1
                    continue

            if current is None:
                self._record_anomaly("diff", "diff entry before any commit header", probe[:200])
                index += 1
                continue

            if probe.startswith(":"):
                index = self._consume_raw_entry(
                    tokens, index, probe, current, raw_by_commit, order
                )
            else:
                index = self._consume_numstat_entry(
                    tokens, index, probe, current, numstat_by_commit
                )

        return self._merge_diff_records(raw_by_commit, numstat_by_commit, order)

    def _consume_raw_entry(
        self,
        tokens: list[str],
        index: int,
        probe: str,
        commit: str,
        raw_by_commit: dict[str, dict[str, dict]],
        order: dict[str, list[str]],
    ) -> int:
        # ":<src_mode> <dst_mode> <src_sha> <dst_sha> <STATUS>"
        parts = probe[1:].split(" ")
        if len(parts) < 5:
            self._record_anomaly("diff", "malformed raw entry", probe[:200])
            return index + 1

        src_mode, dst_mode, src_blob, dst_blob, status_field = parts[:5]
        letter = status_field[:1]
        score_text = status_field[1:]
        similarity = int(score_text) if score_text.isdigit() else None
        status = ChangeStatus.from_git_letter(letter)
        path_count = 2 if status in {ChangeStatus.RENAMED, ChangeStatus.COPIED} else 1

        paths = tokens[index + 1 : index + 1 + path_count]
        if len(paths) < path_count:
            self._record_anomaly("diff", "raw entry truncated before its paths", probe[:200])
            return index + 1 + len(paths)

        decoded = [_decode_path(p) for p in paths]
        if any(lossy for _, lossy in decoded):
            self._record_anomaly(
                "diff",
                f"path in commit {commit} is not valid UTF-8; recorded approximately",
                decoded[-1][0][:200],
            )
        clean = [value for value, _ in decoded]
        key = clean[-1]

        raw_by_commit[commit][key] = {
            "status": status,
            "similarity": similarity,
            "old_mode": src_mode if src_mode != "000000" else None,
            "new_mode": dst_mode if dst_mode != "000000" else None,
            "old_blob": src_blob if set(src_blob) != {"0"} else None,
            "new_blob": dst_blob if set(dst_blob) != {"0"} else None,
            "old_path": clean[0] if path_count == 2 else None,
            "new_path": clean[1] if path_count == 2 else None,
        }
        if key not in order[commit]:
            order[commit].append(key)
        return index + 1 + path_count

    def _consume_numstat_entry(
        self,
        tokens: list[str],
        index: int,
        probe: str,
        commit: str,
        numstat_by_commit: dict[str, dict[str, tuple[int | None, int | None]]],
    ) -> int:
        # "<added>\t<deleted>\t<path>" or "<added>\t<deleted>\t" + two path tokens
        parts = probe.split("\t")
        if len(parts) < 3:
            self._record_anomaly("diff", "malformed numstat entry", probe[:200])
            return index + 1

        additions = _parse_int(parts[0])
        deletions = _parse_int(parts[1])
        inline_path = "\t".join(parts[2:])

        if inline_path:
            key, _ = _decode_path(inline_path)
            consumed = 1
        else:
            paths = tokens[index + 1 : index + 3]
            if len(paths) < 2:
                self._record_anomaly("diff", "numstat rename truncated", probe[:200])
                return index + 1 + len(paths)
            key, _ = _decode_path(paths[1])
            consumed = 3

        numstat_by_commit[commit][key] = (additions, deletions)
        return index + consumed

    def _merge_diff_records(
        self,
        raw_by_commit: dict[str, dict[str, dict]],
        numstat_by_commit: dict[str, dict[str, tuple[int | None, int | None]]],
        order: dict[str, list[str]],
    ) -> dict[str, list[FileChange]]:
        merged: dict[str, list[FileChange]] = {}
        for commit, entries in raw_by_commit.items():
            counts = numstat_by_commit.get(commit, {})
            changes: list[FileChange] = []
            for key in order[commit]:
                entry = entries[key]
                additions, deletions = counts.get(key, (None, None))
                # numstat prints "-" for binary content; a file present in the
                # raw output but absent from numstat had no countable lines.
                is_binary = key in counts and additions is None and deletions is None
                status = entry["status"]

                if status in {ChangeStatus.RENAMED, ChangeStatus.COPIED}:
                    confidence = rename_confidence(entry["similarity"])
                else:
                    confidence = Confidence.HIGH

                changes.append(
                    FileChange(
                        path=key,
                        status=status,
                        additions=additions,
                        deletions=deletions,
                        old_path=entry["old_path"],
                        new_path=entry["new_path"],
                        is_binary=is_binary,
                        similarity=entry["similarity"],
                        old_mode=entry["old_mode"],
                        new_mode=entry["new_mode"],
                        old_blob=entry["old_blob"],
                        new_blob=entry["new_blob"],
                        category=classify_file(key),
                        extension=PurePosixPath(key).suffix.lower(),
                        evidence=git_diff_evidence(
                            confidence=confidence,
                            commit=commit,
                            status=status.value,
                            similarity=entry["similarity"],
                        ),
                    )
                )
            merged[commit] = changes
        return merged

    def _attach_file_changes(
        self,
        commits: list[CommitRecord],
        changes_by_sha: dict[str, list[FileChange]],
    ) -> list[CommitRecord]:
        """Bind diff-pass results onto metadata-pass commits."""

        merges_excluded = self.config.diff_merges == "off"
        attached: list[CommitRecord] = []
        known = {commit.commit_sha for commit in commits}

        for commit in commits:
            changes = changes_by_sha.get(commit.commit_sha, [])
            truncated = commit.commit_sha not in changes_by_sha and (
                merges_excluded and commit.is_merge
            )
            attached.append(
                commit.model_copy(
                    update={"file_changes": changes, "diff_truncated": truncated}
                )
            )

        for sha in changes_by_sha:
            if sha not in known:
                self._record_anomaly(
                    "diff", f"diff data for commit {sha} had no metadata record"
                )
        return attached

    # -- aggregation ----------------------------------------------------------

    def _summarize_authors(self, commits: list[CommitRecord]) -> list[AuthorSummary]:
        buckets: dict[str, dict] = {}
        for commit in commits:
            identity = commit.author
            key = identity.key
            if not key:
                key = "(unknown)"
            bucket = buckets.setdefault(
                key,
                {
                    "name": identity.name,
                    "email": identity.email,
                    "commit_count": 0,
                    "additions": 0,
                    "deletions": 0,
                    "paths": set(),
                    "first": commit.timestamp,
                    "last": commit.timestamp,
                    "workflow": 0,
                    "dependency": 0,
                },
            )
            bucket["commit_count"] += 1
            bucket["additions"] += commit.additions
            bucket["deletions"] += commit.deletions
            bucket["paths"].update(change.path for change in commit.file_changes)
            bucket["first"] = min(bucket["first"], commit.timestamp)
            bucket["last"] = max(bucket["last"], commit.timestamp)
            if commit.touches_workflow:
                bucket["workflow"] += 1
            if commit.touches_dependencies:
                bucket["dependency"] += 1

        summaries = [
            AuthorSummary(
                name=data["name"],
                email=data["email"],
                commit_count=data["commit_count"],
                additions=data["additions"],
                deletions=data["deletions"],
                files_touched=len(data["paths"]),
                first_commit_at=data["first"],
                last_commit_at=data["last"],
                workflow_commit_count=data["workflow"],
                dependency_commit_count=data["dependency"],
            )
            for data in buckets.values()
        ]
        summaries.sort(key=lambda item: (-item.commit_count, item.email, item.name))
        return summaries

    def _compute_stats(
        self, commits: list[CommitRecord], branches: list[BranchRef]
    ) -> AnalysisStats:
        categories: Counter[FileCategory] = Counter()
        paths: set[str] = set()
        authors: set[str] = set()
        committers: set[str] = set()
        additions = deletions = binary = renames = change_count = 0
        workflow_commits = dependency_commits = merges = roots = 0
        first_at: datetime | None = None
        last_at: datetime | None = None

        for commit in commits:
            authors.add(commit.author.key)
            committers.add(Identity(name=commit.committer_name, email=commit.committer_email).key)
            merges += 1 if commit.is_merge else 0
            roots += 1 if commit.is_root else 0
            workflow_commits += 1 if commit.touches_workflow else 0
            dependency_commits += 1 if commit.touches_dependencies else 0
            first_at = commit.timestamp if first_at is None else min(first_at, commit.timestamp)
            last_at = commit.timestamp if last_at is None else max(last_at, commit.timestamp)

            for change in commit.file_changes:
                change_count += 1
                paths.add(change.path)
                categories[change.category] += 1
                additions += change.additions or 0
                deletions += change.deletions or 0
                binary += 1 if change.is_binary else 0
                renames += 1 if change.status is ChangeStatus.RENAMED else 0

        return AnalysisStats(
            commit_count=len(commits),
            merge_commit_count=merges,
            root_commit_count=roots,
            author_count=len({a for a in authors if a}),
            committer_count=len({c for c in committers if c}),
            branch_count=sum(1 for ref in branches if ref.kind is not RefKind.TAG),
            tag_count=sum(1 for ref in branches if ref.kind is RefKind.TAG),
            file_change_count=change_count,
            distinct_path_count=len(paths),
            total_additions=additions,
            total_deletions=deletions,
            binary_change_count=binary,
            rename_count=renames,
            commits_touching_workflows=workflow_commits,
            commits_touching_dependencies=dependency_commits,
            category_counts=dict(categories),
            first_commit_at=first_at,
            last_commit_at=last_at,
            commit_limit_reached=self._limit_reached(len(commits)),
        )

    def _limit_reached(self, collected: int) -> bool:
        """True when the configured limit hid part of the history."""

        limit = self.config.max_commits
        if limit is None or collected < limit:
            return False
        args = ["rev-list", "--count"]
        args.append("--all" if self.config.include_all_refs else "HEAD")
        total_text = self.runner.line(args)
        try:
            return int(total_text) > collected
        except ValueError:
            return True

    # -- helpers --------------------------------------------------------------

    def _record_anomaly(self, stage: str, detail: str, raw_excerpt: str = "") -> None:
        logger.warning("[%s] %s", stage, detail)
        self.anomalies.append(
            ParseAnomaly(stage=stage, detail=detail, raw_excerpt=raw_excerpt)
        )


def analyze_repository(
    repo_path: str, config: AnalysisConfig | None = None
) -> RepositoryAnalysis:
    """Convenience wrapper: analyse ``repo_path`` and return the report."""

    return GitAnalyzer(repo_path, config).analyze()
