import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

BASE_TOOLS = [
    "create_support_ticket",
    "list_support_tickets",
    "lookup_customer",
    "summarize_contract",
]


def _list_tools(disable_honeypot: bool = False, force_static: bool = True) -> list[str]:
    async def _run() -> list[str]:
        env = {"MCP_TRANSPORT": "stdio"}
        if disable_honeypot:
            env["HONEYMCP_DISABLE"] = "1"
        if force_static:
            env["HONEYMCP_FORCE_STATIC"] = "1"

        server = StdioServerParameters(
            command="uv",
            args=["run", "python", "examples/cognitive_crm_server.py"],
            env=env,
            cwd=".",
        )

        async with stdio_client(server) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools = await session.list_tools()
                return sorted(tool.name for tool in tools.tools)

    return anyio.run(_run)


def test_cognitive_crm_example_tools_with_and_without_honeypot() -> None:
    tools_without = _list_tools(disable_honeypot=True)
    tools_with_static = _list_tools(disable_honeypot=False)

    for tool in BASE_TOOLS:
        assert tool in tools_without
        assert tool in tools_with_static

    assert "export_user_data" not in tools_without
    assert "dump_database_credentials" not in tools_without

    assert "export_user_data" in tools_with_static
    assert "dump_database_credentials" in tools_with_static
