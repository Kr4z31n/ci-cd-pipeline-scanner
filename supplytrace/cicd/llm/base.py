"""The LLM boundary.

The provider interface is deliberately tiny -- one method that takes a prompt
and returns text -- because the interesting work is not the call. It is what
goes in (:mod:`supplytrace.cicd.llm.prompts`) and what is allowed back out
(:mod:`supplytrace.cicd.llm.schemas`).

Two invariants hold at this boundary:

* the deterministic analysis never depends on it. Every command works with
  ``--no-llm``, and the tests never touch a network; and
* nothing the model returns is trusted. The response is parsed, validated, and
  checked against the evidence that was actually sent, before a single word of
  it reaches the report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


class LLMError(Exception):
    """The provider could not be used, or returned something unusable."""


@dataclass
class LLMResponse:
    """Raw text back from a provider, with whatever the caller may need."""

    text: str
    model: str = ""
    finish_reason: str = ""
    usage: dict[str, int] = field(default_factory=dict)


class LLMProvider(Protocol):
    """Anything that can turn a prompt into text."""

    name: str

    def is_available(self) -> bool:
        """True when the provider is configured and usable."""
        ...

    def generate(self, prompt: str, *, system: str = "") -> LLMResponse:
        """Send ``prompt`` and return the response. Raises :class:`LLMError`."""
        ...


class NullProvider:
    """A provider that is never available.

    Used when ``--no-llm`` is set, so the calling code follows one path whether
    or not an LLM is in play rather than branching on a ``None``.
    """

    name = "none"

    def is_available(self) -> bool:
        return False

    def generate(self, prompt: str, *, system: str = "") -> LLMResponse:
        raise LLMError("LLM analysis is disabled (--no-llm)")


__all__ = ["LLMError", "LLMProvider", "LLMResponse", "NullProvider"]
