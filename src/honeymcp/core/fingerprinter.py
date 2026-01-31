"""Attack fingerprinting - capture complete attack context."""

from datetime import datetime
from uuid import uuid4
from typing import Any, Dict, List, Optional
from honeymcp.models.events import AttackFingerprint
from honeymcp.models.ghost_tool_spec import GhostToolSpec

# Global session state tracking
_session_tool_history: Dict[str, List[str]] = {}
_attacker_detected: Dict[str, bool] = {}


def mark_attacker_detected(session_id: str) -> None:
    """Mark a session as having triggered a ghost tool (attacker detected)."""
    _attacker_detected[session_id] = True


def is_attacker_detected(session_id: str) -> bool:
    """Check if this session has been flagged as an attacker."""
    return _attacker_detected.get(session_id, False)


def record_tool_call(session_id: str, tool_name: str) -> None:
    """Record a tool call in the session history."""
    if session_id not in _session_tool_history:
        _session_tool_history[session_id] = []
    _session_tool_history[session_id].append(tool_name)


def get_session_tool_history(session_id: str) -> List[str]:
    """Get the tool call history for a session."""
    return _session_tool_history.get(session_id, [])


async def fingerprint_attack(
    tool_name: str,
    arguments: Dict[str, Any],
    context: Any,
    ghost_spec: GhostToolSpec,
) -> AttackFingerprint:
    """Capture complete attack context when a ghost tool is triggered.

    Args:
        tool_name: Name of the ghost tool that was called
        arguments: Arguments passed to the ghost tool
        context: MCP context object (varies by framework)
        ghost_spec: Specification of the triggered ghost tool
    Returns:
        Complete attack fingerprint with all available context
    """
    # Extract session ID from context
    session_id = _extract_session_id(context)

    # Get tool call history
    tool_history = get_session_tool_history(session_id)

    # Try to extract conversation history (may not be available in MCP)
    conversation = _extract_conversation_history(context)

    # Extract client metadata
    client_metadata = _extract_client_metadata(context)

    # Generate fake response
    fake_response = ghost_spec.response_generator(arguments)

    # Create unique event ID
    event_id = f"evt_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:8]}"

    return AttackFingerprint(
        event_id=event_id,
        timestamp=datetime.utcnow(),
        session_id=session_id,
        ghost_tool_called=tool_name,
        arguments=arguments,
        conversation_history=conversation,
        tool_call_sequence=tool_history,
        threat_level=ghost_spec.threat_level,
        attack_category=ghost_spec.attack_category,
        client_metadata=client_metadata,
        response_sent=fake_response,
    )


def _extract_session_id(context: Any) -> str:
    """Extract session ID from MCP context."""
    # Try different attributes that might contain session ID
    for attr in ["session_id", "id", "request_id", "connection_id"]:
        if hasattr(context, attr):
            value = getattr(context, attr)
            if value:
                return str(value)

    # Fallback: generate a session ID
    return f"sess_{uuid4().hex[:12]}"


def _extract_conversation_history(context: Any) -> Optional[List[Dict]]:
    """Extract conversation history from context if available.

    Note: MCP protocol may not provide conversation history to tools.
    This is a limitation of the protocol, not HoneyMCP.
    """
    if hasattr(context, "conversation_history"):
        return getattr(context, "conversation_history")

    if hasattr(context, "messages"):
        return getattr(context, "messages")

    # Not available
    return None


def _extract_client_metadata(context: Any) -> Dict[str, Any]:
    """Extract available client metadata from context."""
    metadata = {}

    # Try to extract user agent
    if hasattr(context, "user_agent"):
        metadata["user_agent"] = getattr(context, "user_agent")

    # Try to extract client info
    if hasattr(context, "client_info"):
        metadata["client_info"] = getattr(context, "client_info")

    # Try to extract request headers
    if hasattr(context, "headers"):
        headers = getattr(context, "headers")
        if isinstance(headers, dict):
            metadata["headers"] = headers

    # If no metadata found, return minimal info
    if not metadata:
        metadata["user_agent"] = "unknown"

    return metadata
