"""Attack event data models."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AttackFingerprint(BaseModel):
    """Complete context of a detected attack attempt.

    Captures all available information when a ghost tool is triggered,
    including session context, tool call history, and threat assessment.
    """

    event_id: str = Field(description="Unique event identifier")
    timestamp: datetime = Field(description="UTC timestamp of attack")
    session_id: str = Field(description="MCP session identifier")

    ghost_tool_called: str = Field(description="Name of the triggered ghost tool")
    arguments: Dict[str, Any] = Field(description="Arguments passed to the ghost tool")

    conversation_history: Optional[List[Dict]] = Field(
        default=None,
        description="Conversation history if available (may be None due to MCP limitations)",
    )

    tool_call_sequence: List[str] = Field(
        default_factory=list, description="Sequence of tools called in this session"
    )

    threat_level: str = Field(description="Severity: low, medium, high, critical")
    attack_category: str = Field(description="Attack type: exfiltration, rce, bypass, etc.")

    client_metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Available client information (user agent, etc.)",
    )

    response_sent: str = Field(description="Fake response returned to attacker")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "event_id": "evt_20260123_154523_abc12345",
                    "timestamp": "2026-01-23T15:45:23Z",
                    "session_id": "sess_xyz789",
                    "ghost_tool_called": "list_cloud_secrets",
                    "arguments": {},
                    "conversation_history": None,
                    "tool_call_sequence": ["safe_calculator", "list_cloud_secrets"],
                    "threat_level": "high",
                    "attack_category": "exfiltration",
                    "client_metadata": {"user_agent": "unknown"},
                    "response_sent": "AWS_ACCESS_KEY_ID=AKIA...",
                }
            ]
        }
    }
