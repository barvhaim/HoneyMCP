"""Tests for fake-response argument interpolation.

Regression coverage for a crash on the honeypot hot path: ``str.format`` treated
the braces in LLM-generated JSON as format fields and raised instead of
returning bait.
"""

import pytest

from honeymcp.core.dynamic_ghost_tools import (
    DynamicGhostToolGenerator,
    interpolate_fake_response,
)


@pytest.mark.parametrize(
    "template",
    [
        '{"aws_access_key": "AKIA123", "nested": {"deep": true}}',
        "Unbalanced { brace",
        "Trailing brace }",
        "{0} positional",
        "{obj.attr} attribute access",
        "{a!r} conversion",
        "{x:>10} format spec",
        "nested {{double}} braces",
    ],
)
def test_braces_never_raise(template: str) -> None:
    """Any brace shape must pass through instead of raising."""
    assert interpolate_fake_response(template, {"unrelated": "value"}) == template


def test_known_placeholder_is_substituted() -> None:
    result = interpolate_fake_response("reading {path} now", {"path": "/etc/shadow"})
    assert result == "reading /etc/shadow now"


def test_unknown_placeholder_is_left_intact() -> None:
    assert interpolate_fake_response("value={missing}", {"path": "/x"}) == "value={missing}"


def test_json_survives_alongside_placeholder() -> None:
    result = interpolate_fake_response('{path} -> {"ok": 1}', {"path": "/tmp/f"})
    assert result == '/tmp/f -> {"ok": 1}'


def test_non_string_argument_is_coerced() -> None:
    assert interpolate_fake_response("n={count}", {"count": 42}) == "n=42"


def test_none_arguments_are_tolerated() -> None:
    assert interpolate_fake_response('{"a": 1}', None) == '{"a": 1}'


def test_response_generator_handles_json_payload() -> None:
    """The generated response callable must not raise on JSON fake responses."""
    generator = DynamicGhostToolGenerator.__new__(DynamicGhostToolGenerator)
    payload = '{"secrets": [{"key": "AKIA", "region": "us-east-1"}]}'

    respond = generator._create_response_generator(payload)  # pylint: disable=protected-access

    assert respond({"file_path": "/etc/passwd"}) == payload
