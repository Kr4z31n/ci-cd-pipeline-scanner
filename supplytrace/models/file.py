"""File-level models: change status, file classification, and file changes."""

from __future__ import annotations

from enum import Enum
from pathlib import PurePosixPath

from pydantic import BaseModel, ConfigDict, Field

from supplytrace.models.evidence import Confidence, Evidence


class ChangeStatus(str, Enum):
    """Status letter reported by ``git log --raw``, expanded to a name."""

    ADDED = "ADDED"
    COPIED = "COPIED"
    DELETED = "DELETED"
    MODIFIED = "MODIFIED"
    RENAMED = "RENAMED"
    TYPE_CHANGED = "TYPE_CHANGED"
    UNMERGED = "UNMERGED"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_git_letter(cls, letter: str) -> "ChangeStatus":
        return {
            "A": cls.ADDED,
            "C": cls.COPIED,
            "D": cls.DELETED,
            "M": cls.MODIFIED,
            "R": cls.RENAMED,
            "T": cls.TYPE_CHANGED,
            "U": cls.UNMERGED,
        }.get(letter.upper(), cls.UNKNOWN)


class FileCategory(str, Enum):
    """What role a file plays in the supply chain.

    This classification is what lets later phases jump straight from a commit to
    the workflow definitions and dependency manifests it touched.
    """

    WORKFLOW = "WORKFLOW"
    DEPENDENCY_MANIFEST = "DEPENDENCY_MANIFEST"
    LOCKFILE = "LOCKFILE"
    CI_CONFIG = "CI_CONFIG"
    BUILD = "BUILD"
    SOURCE = "SOURCE"
    TEST = "TEST"
    DOCUMENTATION = "DOCUMENTATION"
    CONFIG = "CONFIG"
    OTHER = "OTHER"


#: Exact filenames that identify a dependency manifest.
_MANIFEST_NAMES = {
    "requirements.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "pipfile",
    "package.json",
    "go.mod",
    "cargo.toml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gemfile",
    "composer.json",
}

#: Exact filenames that identify a resolved lockfile.
_LOCKFILE_NAMES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pipfile.lock",
    "uv.lock",
    "cargo.lock",
    "go.sum",
    "composer.lock",
    "gemfile.lock",
}

_BUILD_NAMES = {"dockerfile", "makefile", "cmakelists.txt"}

_CI_DIR_MARKERS = (
    ".circleci/",
    ".gitlab-ci.yml",
    "azure-pipelines.yml",
    ".travis.yml",
    "jenkinsfile",
)

_SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".kt", ".rb",
    ".php", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".swift", ".scala",
    ".sh", ".bash", ".zsh", ".ps1", ".pl", ".lua", ".m", ".mm", ".sql",
}

_DOC_EXTENSIONS = {".md", ".rst", ".txt", ".adoc"}
_CONFIG_EXTENSIONS = {".yml", ".yaml", ".toml", ".ini", ".cfg", ".json", ".env", ".conf"}


def normalize_repo_path(path: str) -> str:
    """Normalise a repository-relative path for classification.

    Only a leading ``./`` is removed.  ``str.lstrip("./")`` must not be used
    here: it strips *characters*, which would turn ``.github/workflows/ci.yml``
    into ``github/workflows/ci.yml`` and hide every workflow file.
    """

    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def is_workflow_path(path: str) -> bool:
    """True for a GitHub Actions workflow definition file."""

    normalized = normalize_repo_path(path).lower()
    if not normalized.startswith(".github/workflows/"):
        return False
    return normalized.endswith((".yml", ".yaml"))


def classify_file(path: str) -> FileCategory:
    """Classify a repository-relative path into a supply-chain role.

    Order matters: workflow and dependency files are checked before generic
    extension rules so that ``.github/workflows/build.yml`` is a WORKFLOW rather
    than a CONFIG file.
    """

    if not path:
        return FileCategory.OTHER

    normalized = normalize_repo_path(path)
    lowered = normalized.lower()
    name = PurePosixPath(lowered).name
    suffix = PurePosixPath(lowered).suffix

    if is_workflow_path(normalized):
        return FileCategory.WORKFLOW
    if lowered.startswith(".github/actions/") and name in {"action.yml", "action.yaml"}:
        return FileCategory.WORKFLOW
    if name in _LOCKFILE_NAMES:
        return FileCategory.LOCKFILE
    if name in _MANIFEST_NAMES:
        return FileCategory.DEPENDENCY_MANIFEST
    if any(marker in lowered for marker in _CI_DIR_MARKERS):
        return FileCategory.CI_CONFIG
    if name in _BUILD_NAMES or name.startswith("dockerfile"):
        return FileCategory.BUILD
    if "test" in lowered.split("/") or name.startswith("test_") or name.endswith(
        ("_test.py", ".test.js", ".test.ts", "_test.go", ".spec.js", ".spec.ts")
    ):
        return FileCategory.TEST
    if suffix in _SOURCE_EXTENSIONS:
        return FileCategory.SOURCE
    if suffix in _DOC_EXTENSIONS:
        return FileCategory.DOCUMENTATION
    if suffix in _CONFIG_EXTENSIONS:
        return FileCategory.CONFIG
    return FileCategory.OTHER


def rename_confidence(similarity: int | None) -> Confidence:
    """Map Git's rename/copy similarity score to a confidence level.

    Git reports how similar the two blobs are.  A 100% match is an exact content
    move; a score near the detection threshold is a guess the investigator should
    verify.  Never claim certainty the underlying data does not support.
    """

    if similarity is None:
        return Confidence.UNKNOWN
    if similarity >= 95:
        return Confidence.HIGH
    if similarity >= 75:
        return Confidence.MEDIUM
    return Confidence.LOW


class FileChange(BaseModel):
    """One file touched by one commit."""

    model_config = ConfigDict(frozen=True)

    path: str = Field(description="Path after the change (or the deleted path).")
    status: ChangeStatus
    additions: int | None = Field(
        default=None, description="Added lines; None for binary files."
    )
    deletions: int | None = Field(
        default=None, description="Deleted lines; None for binary files."
    )
    old_path: str | None = None
    new_path: str | None = None
    is_binary: bool = False
    similarity: int | None = Field(
        default=None, description="Git rename/copy similarity score, 0-100."
    )
    old_mode: str | None = None
    new_mode: str | None = None
    old_blob: str | None = None
    new_blob: str | None = None
    category: FileCategory = FileCategory.OTHER
    extension: str = ""
    evidence: Evidence | None = None

    @property
    def is_workflow_file(self) -> bool:
        return self.category is FileCategory.WORKFLOW

    @property
    def is_dependency_file(self) -> bool:
        return self.category in {
            FileCategory.DEPENDENCY_MANIFEST,
            FileCategory.LOCKFILE,
        }

