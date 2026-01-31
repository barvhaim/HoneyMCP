"""Demo MCP Server with HoneyMCP integration.

This example shows how to add deception capabilities to any FastMCP server
with just one line of code.

Usage:
    # stdio transport (default - works with all Claude Desktop versions):
    uv run python examples/demo_server.py

    # Streamable HTTP transport (requires Claude Pro/Max/Team/Enterprise):
    MCP_TRANSPORT=http uv run python examples/demo_server.py

Configuration for Claude Desktop:
    Edit: ~/Library/Application Support/Claude/claude_desktop_config.json

    For stdio transport:
    {
      "mcpServers": {
        "honeymcp-demo": {
          "command": "uv",
          "args": ["run", "python", "/path/to/HoneyMCP/examples/demo_server.py"]
        }
      }
    }

    For Streamable HTTP transport:
    {
      "mcpServers": {
        "honeymcp-demo": {
          "url": "http://localhost:8000/mcp"
        }
      }
    }
"""

import os
from fastmcp import FastMCP
from honeymcp import honeypot

# Create MCP server
mcp = FastMCP("HoneyMCP Demo Server")


@mcp.tool()
def safe_calculator(a: int, b: int, operation: str = "add") -> int:
    """Perform safe mathematical operations.

    A legitimate tool that demonstrates normal MCP functionality.

    Args:
        a: First number
        b: Second number
        operation: Operation to perform (add, subtract, multiply, divide)

    Returns:
        Result of the operation
    """
    if operation == "add":
        return a + b
    elif operation == "subtract":
        return a - b
    elif operation == "multiply":
        return a * b
    elif operation == "divide":
        if b == 0:
            raise ValueError("Cannot divide by zero")
        return a // b
    else:
        raise ValueError(f"Unknown operation: {operation}")


@mcp.tool()
def get_weather(city: str) -> str:
    """Get current weather for a city.

    Another legitimate tool for demonstration purposes.

    Args:
        city: City name

    Returns:
        Weather description
    """
    # Fake weather data for demo
    return f"The weather in {city} is sunny with a temperature of 72°F."


# ==============================================================================
# ONE LINE INTEGRATION - Add honeypot capabilities
# ==============================================================================

if os.getenv("HONEYMCP_DISABLE") != "1":
    mcp = honeypot(
        mcp,
        ghost_tools=[
            "list_cloud_secrets",  # High-value target for attackers
            "execute_shell_command",  # Critical RCE honeypot
        ],
        use_dynamic_tools=False,
    )

# ==============================================================================


if __name__ == "__main__":
    # Determine transport mode from environment
    transport = os.getenv("MCP_TRANSPORT", "sse")

    print("🍯 HoneyMCP Demo Server")
    print("=" * 50)
    print(f"Transport: {transport}")
    print("Ghost tools active:")
    print("  - list_cloud_secrets (exfiltration honeypot)")
    print("  - execute_shell_command (RCE honeypot)")
    print("\nLegitimate tools:")
    print("  - safe_calculator")
    print("  - get_weather")
    print("=" * 50)

    if transport == "stdio":
        print("\n📡 Starting stdio server")
        print("Server will communicate via stdin/stdout")
        print("Claude Desktop will spawn this as a subprocess\n")

        mcp.run(transport="stdio")

    elif transport == "http":
        print("\n📡 Starting Streamable HTTP server on http://localhost:8000/mcp")
        print("Configure Claude Desktop with: http://localhost:8000/mcp")
        print("\nNote: Requires Claude Pro, Max, Team, or Enterprise")
        print("      Free Claude Desktop users should use stdio transport instead\n")

        mcp.run(transport="streamable-http", host="localhost", port=8000)

    else:
        # Default: SSE transport
        print("\n📡 Starting SSE server on http://localhost:8000/sse")
        print("MCP Inspector can connect to: http://localhost:8000/sse")
        print("\nSSE transport is ideal for:")
        print("  - MCP Inspector testing")
        print("  - Development and debugging")
        print("  - Remote server connections\n")

        mcp.run(transport="sse", host="localhost", port=8000)
