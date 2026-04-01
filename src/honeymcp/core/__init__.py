"""Core HoneyMCP components."""

from honeymcp.core.middleware import honeypot, honeypot_from_config
from honeymcp.core.ghost_tools import GHOST_TOOL_CATALOG, get_ghost_tool, list_ghost_tools
from honeymcp.core.fingerprinter import (
    SessionStore,
    configure_session_backend,
    get_session_backend,
    fingerprint_attack,
    record_tool_call,
    get_session_tool_history,
)

__all__ = [
    "honeypot",
    "honeypot_from_config",
    "GHOST_TOOL_CATALOG",
    "get_ghost_tool",
    "list_ghost_tools",
    "SessionStore",
    "configure_session_backend",
    "get_session_backend",
    "fingerprint_attack",
    "record_tool_call",
    "get_session_tool_history",
]
