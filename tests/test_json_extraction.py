"""Unit tests for robust LLM JSON extraction.

These tests exercise ``_extract_json`` directly and make NO LLM calls, so they
run regardless of whether an LLM provider is configured.
"""

import json

import pytest

from honeymcp.core.dynamic_ghost_tools import (
    _escape_control_chars_in_strings,
    _extract_json,
)


def test_plain_object() -> None:
    assert _extract_json('{"a": 1, "b": 2}') == {"a": 1, "b": 2}


def test_plain_array() -> None:
    assert _extract_json('[{"name": "x"}]') == [{"name": "x"}]


def test_strips_json_code_fence() -> None:
    raw = '```json\n{"domain": "fintech"}\n```'
    assert _extract_json(raw) == {"domain": "fintech"}


def test_strips_bare_code_fence() -> None:
    raw = '```\n{"domain": "fintech"}\n```'
    assert _extract_json(raw) == {"domain": "fintech"}


def test_ignores_surrounding_prose() -> None:
    raw = 'Here is the JSON you asked for:\n{"server_purpose": "bank"}\nHope that helps!'
    assert _extract_json(raw) == {"server_purpose": "bank"}


def test_repairs_trailing_comma() -> None:
    assert _extract_json('{"a": 1, "b": 2,}') == {"a": 1, "b": 2}
    assert _extract_json('[1, 2, 3,]') == [1, 2, 3]


def test_escapes_unescaped_newlines_in_string() -> None:
    """The real failure mode: multi-line mock_response with literal newlines/tabs.

    This is what produced "Expecting ',' delimiter" from the LLM's banking
    mock responses.
    """
    raw = '[{"name": "dump", "mock_response": "line1\nline2\ttabbed\nUsername: admin"}]'
    result = _extract_json(raw)
    assert result[0]["name"] == "dump"
    # Newlines/tabs are preserved as real characters in the parsed value.
    assert result[0]["mock_response"] == "line1\nline2\ttabbed\nUsername: admin"


def test_preserves_properly_escaped_quotes() -> None:
    raw = '{"msg": "he said \\"hi\\" to me"}'
    assert _extract_json(raw) == {"msg": 'he said "hi" to me'}


def test_object_wins_when_before_array() -> None:
    raw = 'noise {"k": [1, 2]} noise'
    assert _extract_json(raw) == {"k": [1, 2]}


def test_array_wins_when_before_object() -> None:
    raw = 'noise [{"k": 1}] noise'
    assert _extract_json(raw) == [{"k": 1}]


def test_raises_on_unrecoverable_input() -> None:
    with pytest.raises(json.JSONDecodeError):
        _extract_json("not json at all {oops")


def test_escape_helper_leaves_structural_whitespace() -> None:
    """Newlines between JSON tokens (not inside strings) must be untouched."""
    text = '{\n  "a": 1,\n  "b": 2\n}'
    # No control chars inside any string value, so output equals input.
    assert _escape_control_chars_in_strings(text) == text
