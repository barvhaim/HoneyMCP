"""Demo MCP server with dynamic ghost tool generation.

This example demonstrates how HoneyMCP automatically generates
context-aware honeypot tools based on your server's real tools.
"""

import os
from fastmcp import FastMCP
from honeymcp import honeypot


# Create a file system MCP server
mcp = FastMCP("FileSystem Demo Server")


@mcp.tool()
def read_file(path: str) -> str:
    """Read contents of a file from the filesystem."""
    return f"Contents of {path}: [file data here]"


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Write content to a file in the filesystem."""
    return f"Successfully wrote {len(content)} bytes to {path}"


@mcp.tool()
def list_directory(path: str) -> list:
    """List files and directories in the specified path."""
    return ["file1.txt", "file2.py", "subdir/"]


@mcp.tool()
def delete_file(path: str) -> str:
    """Delete a file from the filesystem."""
    return f"Successfully deleted {path}"


@mcp.tool()
def get_file_info(path: str) -> dict:
    """Get metadata about a file (size, permissions, timestamps)."""
    return {
        "path": path,
        "size": 1024,
        "permissions": "rw-r--r--",
        "modified": "2026-01-24T12:00:00Z"
    }


# Wrap with honeypot - dynamic tools will be generated automatically
# Based on the file system tools above, it might generate tools like:
# - read_system_credentials (to read sensitive files)
# - execute_privileged_command (to run commands with elevated privileges)
# - bypass_file_permissions (to access restricted files)
if os.getenv("HONEYMCP_DISABLE") == "1":
    print("HoneyMCP disabled via HONEYMCP_DISABLE=1.")
    print()
else:
    print("Initializing HoneyMCP with dynamic ghost tool generation...")
    print("This will analyze your server's tools and generate relevant honeypots using LLM.")
    print()

if os.getenv("HONEYMCP_DISABLE") != "1":
    try:
        force_static = os.getenv("HONEYMCP_FORCE_STATIC") == "1"
        mcp = honeypot(
            mcp,
            use_dynamic_tools=not force_static,
            num_dynamic_tools=3,
            fallback_to_static=True,  # Fallback to static tools if LLM fails
            ghost_tools=(
                ["list_cloud_secrets", "execute_shell_command"] if force_static else None
            ),
        )
        print("✓ HoneyMCP initialized successfully!")
        print()
        print("Your server now has:")
        print("- 5 real tools (read_file, write_file, list_directory, delete_file, get_file_info)")
        if force_static:
            print("- 2 static ghost tools (honeypots)")
        else:
            print("- 3 dynamically generated ghost tools (honeypots)")
        print()
        print("The ghost tools were generated based on your server's context and will")
        print("detect and log any malicious attempts to exploit your system.")
        
    except Exception as e:
        print(f"✗ Failed to initialize HoneyMCP: {e}")
        print()
        print("Make sure you have:")
        print("1. Set up your .env file with WatsonX credentials")
        print("2. Installed all dependencies (pip install -e .)")


if __name__ == "__main__":
    print()
    print("Server is ready! You can now:")

    transport = os.getenv("MCP_TRANSPORT", "sse")
    print(f"Transport: {transport}")
    print("3 Dynamic Ghost tools active:")
    print("Connect to it using an MCP client")
    print()
    print("Starting MCP server...")
    print()
    
    # Run the server
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
