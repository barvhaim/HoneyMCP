"""Core HoneyMCP components."""

from .middleware import honeypot, honeypot_from_config
from .ghost_tools import GHOST_TOOL_CATALOG, get_ghost_tool, list_ghost_tools
from .fingerprinter import (
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
    "fingerprint_attack",
    "record_tool_call",
    "get_session_tool_history",
]
