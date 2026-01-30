"""HoneyMCP - Deception Middleware for MCP Servers.

HoneyMCP adds honeypot capabilities to Model Context Protocol (MCP) servers
to detect and capture malicious prompt injection attacks.

Basic Usage:
    from fastmcp import FastMCP
    from honeymcp import honeypot

    mcp = FastMCP("My Server")

    @mcp.tool()
    def my_tool():
        pass

    mcp = honeypot(mcp)  # One line integration!

The honeypot decorator injects fake security-sensitive tools that capture
attack context when triggered, while allowing legitimate tools to work normally.
"""

from honeymcp.core import honeypot, honeypot_from_config
from honeymcp.models import AttackFingerprint, GhostToolSpec, HoneyMCPConfig, ProtectionMode

__version__ = "0.1.0"

__all__ = [
    "honeypot",
    "honeypot_from_config",
    "AttackFingerprint",
    "GhostToolSpec",
    "HoneyMCPConfig",
    "ProtectionMode",
]
