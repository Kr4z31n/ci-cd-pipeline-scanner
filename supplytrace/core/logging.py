"""Logging setup with credential redaction.

A supply-chain tool handles GitHub tokens.  Phase 20 of the specification
requires that tokens are never logged, so redaction is implemented as a logging
filter rather than left to individual call sites.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Iterable

LOGGER_NAME = "supplytrace"

#: Patterns for well-known GitHub credential formats.
_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    # ghp_ (classic PAT), gho_ (OAuth), ghu_/ghs_ (app), ghr_ (refresh)
    re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}"),
    # fine-grained PAT
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    # basic-auth style credentials embedded in a URL
    re.compile(r"(https?://)[^/\s:@]+:[^/\s@]+@"),
)

REDACTED = "***REDACTED***"


class RedactingFilter(logging.Filter):
    """Replace credential-looking substrings in log records.

    Extra literal secrets (for example the token actually in use) can be
    registered so that they are redacted even if their format is unknown.
    """

    def __init__(self, extra_secrets: Iterable[str] = ()) -> None:
        super().__init__()
        self._literals: list[str] = [s for s in extra_secrets if s and len(s) >= 8]

    def add_secret(self, secret: str | None) -> None:
        if secret and len(secret) >= 8 and secret not in self._literals:
            self._literals.append(secret)

    def redact(self, text: str) -> str:
        for literal in self._literals:
            text = text.replace(literal, REDACTED)
        for pattern in _TOKEN_PATTERNS:
            if pattern.groups:
                text = pattern.sub(rf"\1{REDACTED}@", text)
            else:
                text = pattern.sub(REDACTED, text)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    key: self.redact(value) if isinstance(value, str) else value
                    for key, value in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    self.redact(value) if isinstance(value, str) else value
                    for value in record.args
                )
        return True


_redacting_filter = RedactingFilter()


def get_redacting_filter() -> RedactingFilter:
    """Return the process-wide redaction filter."""

    return _redacting_filter


def configure_logging(verbosity: int = 0, *, stream=None) -> logging.Logger:
    """Configure and return the SupplyTrace logger.

    ``verbosity`` maps 0 -> WARNING, 1 -> INFO, 2+ -> DEBUG.  Logs go to stderr
    so that machine-readable output on stdout stays clean.
    """

    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False
    for existing in list(logger.handlers):
        logger.removeHandler(existing)

    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    )
    handler.addFilter(_redacting_filter)
    logger.addHandler(handler)
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a child logger under the SupplyTrace namespace."""

    return logging.getLogger(LOGGER_NAME if name is None else f"{LOGGER_NAME}.{name}")
