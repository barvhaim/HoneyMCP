"""Real FastMCP integration tests for HoneyMCP wrapping."""

import pytest

from fastmcp import FastMCP

from honeymcp import honeypot


def _first_text(result) -> str:
    """Extract text from FastMCP ToolResult-style responses."""
    content = getattr(result, "content", result)
    if isinstance(content, list) and content:
        return getattr(content[0], "text", str(content[0]))
    return str(content)


@pytest.mark.asyncio
async def test_wrapped_fastmcp_server_calls_regular_and_ghost_tools(tmp_path):
    server = FastMCP("HoneyMCP integration")

    @server.tool()
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b

    server = honeypot(
        server,
        ghost_tools=["list_cloud_secrets"],
        use_dynamic_tools=False,
        event_storage_path=tmp_path,
        enable_dashboard=False,
    )

    tools = await server.list_tools()
    tool_names = {tool.name for tool in tools}

    assert "add" in tool_names
    assert "list_cloud_secrets" in tool_names

    regular_result = await server.call_tool("add", {"a": 2, "b": 3})
    assert _first_text(regular_result) == "5"

    ghost_result = await server.call_tool("list_cloud_secrets", {})
    ghost_text = _first_text(ghost_result)

    assert "AWS_ACCESS_KEY_ID" in ghost_text
    assert list(tmp_path.glob("*/*.json"))
