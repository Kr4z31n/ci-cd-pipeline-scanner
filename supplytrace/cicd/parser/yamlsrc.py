"""YAML loading that keeps the line number of every value.

Every finding this package emits has to point at a place a human can open.
``yaml.safe_load`` throws that away: it returns plain dicts, so by the time a
rule sees ``uses: actions/checkout@v4`` there is no way back to line 18.

The loader below returns ordinary ``dict`` and ``list`` subclasses that carry
their source position as *attributes* rather than extra keys.  Attributes are
used deliberately: an extra ``__line__`` key would show up in every iteration
over a job's steps and every rule would have to remember to skip it.
"""

from __future__ import annotations

from typing import Any

import yaml


class LineDict(dict):
    """A mapping that remembers where it, and each of its values, came from."""

    __slots__ = ("start_line", "value_lines", "key_lines")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.start_line: int = 0
        #: line where each value begins, keyed by the mapping key
        self.value_lines: dict[Any, int] = {}
        #: line where each key token appears, keyed by the mapping key
        self.key_lines: dict[Any, int] = {}

    def line_of(self, key: Any, default: int = 0) -> int:
        """Line of ``key``'s value, falling back to the key, then ``default``."""

        if key in self.value_lines:
            return self.value_lines[key]
        if key in self.key_lines:
            return self.key_lines[key]
        return default or self.start_line

    def key_line_of(self, key: Any, default: int = 0) -> int:
        """Line of the ``key`` token itself.

        For a nested block the value begins on the *following* line, so citing
        the value would point a reader at ``types:`` when what identifies the
        entry is ``pull_request_target:`` above it.
        """

        if key in self.key_lines:
            return self.key_lines[key]
        if key in self.value_lines:
            return self.value_lines[key]
        return default or self.start_line


class LineList(list):
    """A sequence that remembers where it, and each of its items, came from."""

    __slots__ = ("start_line", "item_lines")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.start_line: int = 0
        self.item_lines: list[int] = []

    def line_of(self, index: int, default: int = 0) -> int:
        if 0 <= index < len(self.item_lines):
            return self.item_lines[index]
        return default or self.start_line


def line_of(node: Any, default: int = 0) -> int:
    """Start line of any node the loader produced, or ``default``."""

    return getattr(node, "start_line", default) or default


class _LineLoader(yaml.SafeLoader):
    """SafeLoader that produces :class:`LineDict` / :class:`LineList`.

    SafeLoader is the base on purpose.  A workflow file is untrusted input, and
    ``yaml.Loader`` can instantiate arbitrary Python objects from it.
    """


def _construct_mapping(loader: _LineLoader, node: yaml.MappingNode) -> LineDict:
    loader.flatten_mapping(node)
    mapping = LineDict()
    mapping.start_line = node.start_mark.line + 1
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        value = loader.construct_object(value_node, deep=True)
        try:
            mapping[key] = value
        except TypeError:  # unhashable key, e.g. a mapping used as a key
            continue
        mapping.key_lines[key] = key_node.start_mark.line + 1
        mapping.value_lines[key] = value_node.start_mark.line + 1
    return mapping


def _construct_sequence(loader: _LineLoader, node: yaml.SequenceNode) -> LineList:
    sequence = LineList()
    sequence.start_line = node.start_mark.line + 1
    for item_node in node.value:
        sequence.append(loader.construct_object(item_node, deep=True))
        sequence.item_lines.append(item_node.start_mark.line + 1)
    return sequence


_LineLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)
_LineLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG, _construct_sequence
)


def load_workflow_yaml(text: str) -> Any:
    """Parse workflow YAML, preserving line numbers.

    Raises ``yaml.YAMLError`` on malformed input.  Callers are expected to
    record that as a parse anomaly rather than discard the file silently.
    """

    return yaml.load(text, Loader=_LineLoader)  # noqa: S506 - _LineLoader is a SafeLoader
