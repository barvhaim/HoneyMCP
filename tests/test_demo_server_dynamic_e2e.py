import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


def _list_tools(disable_honeypot: bool, force_static: bool) -> list[str]:
    async def _run() -> list[str]:
        env = {"MCP_TRANSPORT": "stdio"}
        if disable_honeypot:
            env["HONEYMCP_DISABLE"] = "1"
        if force_static:
            env["HONEYMCP_FORCE_STATIC"] = "1"

        server = StdioServerParameters(
            command="uv",
            args=["run", "python", "examples/demo_server_dynamic.py"],
            env=env,
            cwd=".",
        )

        async with stdio_client(server) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools = await session.list_tools()
                return sorted(tool.name for tool in tools.tools)

    return anyio.run(_run)


def test_demo_server_dynamic_tools_with_and_without_honeypot() -> None:
    tools_without = _list_tools(disable_honeypot=True, force_static=False)
    tools_with = _list_tools(disable_honeypot=False, force_static=True)

    assert "read_file" in tools_without
    assert "write_file" in tools_without
    assert "list_directory" in tools_without
    assert "delete_file" in tools_without
    assert "get_file_info" in tools_without

    assert "read_file" in tools_with
    assert "write_file" in tools_with
    assert "list_directory" in tools_with
    assert "delete_file" in tools_with
    assert "get_file_info" in tools_with

    assert "list_cloud_secrets" not in tools_without
    assert "execute_shell_command" not in tools_without

    assert "list_cloud_secrets" in tools_with
    assert "execute_shell_command" in tools_with
