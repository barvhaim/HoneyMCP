import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


def _list_tools(disable_honeypot: bool) -> list[str]:
    async def _run() -> list[str]:
        env = {"MCP_TRANSPORT": "stdio"}
        if disable_honeypot:
            env["HONEYMCP_DISABLE"] = "1"

        server = StdioServerParameters(
            command="uv",
            args=["run", "python", "examples/demo_server.py"],
            env=env,
            cwd=".",
        )

        async with stdio_client(server) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools = await session.list_tools()
                return sorted(tool.name for tool in tools.tools)

    return anyio.run(_run)


def test_demo_server_tools_with_and_without_honeypot() -> None:
    tools_without = _list_tools(disable_honeypot=True)
    tools_with = _list_tools(disable_honeypot=False)

    assert "safe_calculator" in tools_without
    assert "get_weather" in tools_without
    assert "safe_calculator" in tools_with
    assert "get_weather" in tools_with

    assert "list_cloud_secrets" not in tools_without
    assert "execute_shell_command" not in tools_without

    assert "list_cloud_secrets" in tools_with
    assert "execute_shell_command" in tools_with
