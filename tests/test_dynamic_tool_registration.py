"""Unit tests for dynamic ghost tool registration (code generation).

These tests exercise ``_register_dynamic_ghost_tool`` directly against a real
FastMCP server and make NO LLM calls, so they run regardless of whether an LLM
provider is configured.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict

import pytest
from fastmcp import FastMCP

from honeymcp.core.middleware import _register_dynamic_ghost_tool


@dataclass
class _StubSpec:
    """Minimal stand-in for DynamicGhostToolSpec.

    ``_register_dynamic_ghost_tool`` only reads ``name``, ``description``,
    ``parameters`` and ``response_generator``, so a lightweight stub keeps the
    test decoupled from the full dataclass and its LLM-derived fields.
    """

    name: str
    parameters: Dict[str, Any]
    description: str = "generated ghost tool"
    response_generator: Callable[[Dict[str, Any]], str] = field(
        default=lambda kwargs: f"fake:{kwargs!r}"
    )


def _schema(properties: Dict[str, Dict[str, str]], required: list) -> Dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required}


async def _list_tool_names(server: FastMCP) -> list:
    tools = server.list_tools()
    if hasattr(tools, "__await__"):
        tools = await tools
    if isinstance(tools, dict):
        return list(tools.keys())
    return [getattr(t, "name", t) for t in tools]


@pytest.mark.anyio
async def test_required_after_optional_registers() -> None:
    """Regression: a required param listed after an optional one must not
    produce "non-default argument follows default argument".
    """
    server = FastMCP("t")
    spec = _StubSpec(
        name="bypass_transfer_limits",
        parameters=_schema(
            {
                "account_id": {"type": "string"},
                "bypass_duration_hours": {"type": "integer"},
                "override_reason": {"type": "string"},
            },
            # 'override_reason' (required) is declared AFTER an optional param.
            required=["account_id", "override_reason"],
        ),
    )

    _register_dynamic_ghost_tool(server, spec)

    assert "bypass_transfer_limits" in await _list_tool_names(server)


@pytest.mark.anyio
async def test_all_required_registers() -> None:
    server = FastMCP("t")
    spec = _StubSpec(
        name="all_required",
        parameters=_schema(
            {"a": {"type": "string"}, "b": {"type": "string"}},
            required=["a", "b"],
        ),
    )

    _register_dynamic_ghost_tool(server, spec)

    assert "all_required" in await _list_tool_names(server)


@pytest.mark.anyio
async def test_all_optional_registers() -> None:
    server = FastMCP("t")
    spec = _StubSpec(
        name="all_optional",
        parameters=_schema(
            {"x": {"type": "integer"}, "y": {"type": "string"}},
            required=[],
        ),
    )

    _register_dynamic_ghost_tool(server, spec)

    assert "all_optional" in await _list_tool_names(server)


@pytest.mark.anyio
async def test_no_parameters_registers() -> None:
    server = FastMCP("t")
    spec = _StubSpec(name="no_params", parameters=_schema({}, required=[]))

    _register_dynamic_ghost_tool(server, spec)

    assert "no_params" in await _list_tool_names(server)
