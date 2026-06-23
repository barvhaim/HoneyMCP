"""Data models for attack pattern analysis and correlation."""

from datetime import datetime
from typing import Any, Dict, List
from pydantic import BaseModel, Field


class AttackPattern(BaseModel):
    """Detected attack pattern across multiple events.

    Represents a correlation of multiple attack events that share
    common characteristics, indicating coordinated attacks, campaigns,
    or anomalous behavior.
    """

    pattern_id: str = Field(description="Unique pattern identifier")
    pattern_type: str = Field(
        description="Type of pattern: coordinated, campaign, anomaly, reconnaissance"
    )
    confidence: float = Field(
        description="Confidence score 0.0-1.0 indicating pattern strength",
        ge=0.0,
        le=1.0,
    )

    event_ids: List[str] = Field(description="Event IDs that match this pattern")
    session_ids: List[str] = Field(description="Session IDs involved in this pattern")

    first_seen: datetime = Field(description="Timestamp of first event in pattern")
    last_seen: datetime = Field(description="Timestamp of most recent event in pattern")

    characteristics: Dict[str, Any] = Field(
        default_factory=dict,
        description="Pattern-specific attributes and metrics",
    )

    severity: str = Field(description="Pattern severity: low, medium, high, critical")

    description: str = Field(description="Human-readable pattern description")
    recommendations: List[str] = Field(
        default_factory=list,
        description="Suggested response actions",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "pattern_id": "coord_2026-03-28T12:00:00",
                    "pattern_type": "coordinated",
                    "confidence": 0.85,
                    "event_ids": ["evt_001", "evt_002", "evt_003"],
                    "session_ids": ["sess_a", "sess_b", "sess_c"],
                    "first_seen": "2026-03-28T12:00:00Z",
                    "last_seen": "2026-03-28T12:05:00Z",
                    "characteristics": {
                        "session_count": 3,
                        "common_tools": ["list_cloud_secrets"],
                        "time_window": "5 minutes",
                    },
                    "severity": "high",
                    "description": "Coordinated attack: 3 sessions using list_cloud_secrets",
                    "recommendations": [
                        "Block source IPs if available",
                        "Review authentication logs",
                    ],
                }
            ]
        }
    }


class AttackerProfile(BaseModel):
    """Behavioral profile of an attacker or attack source.

    Aggregates attack behavior over time to build a fingerprint
    of the attacker's techniques, preferences, and sophistication.
    """

    profile_id: str = Field(description="Unique profile identifier")
    session_ids: List[str] = Field(description="Sessions associated with this attacker")

    total_attacks: int = Field(description="Total number of attack attempts")
    unique_tools_used: List[str] = Field(description="List of unique ghost tools triggered")
    attack_categories: Dict[str, int] = Field(
        description="Count of attacks by category (exfiltration, rce, etc.)"
    )

    first_seen: datetime = Field(description="Timestamp of first attack")
    last_seen: datetime = Field(description="Timestamp of most recent attack")

    attack_velocity: float = Field(
        description="Average attacks per hour",
        ge=0.0,
    )

    sophistication_score: float = Field(
        description="Sophistication score 0.0-1.0 based on techniques used",
        ge=0.0,
        le=1.0,
    )

    behavioral_fingerprint: Dict[str, Any] = Field(
        default_factory=dict,
        description="Unique behavioral characteristics and patterns",
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "profile_id": "profile_sess_abc123",
                    "session_ids": ["sess_abc123"],
                    "total_attacks": 15,
                    "unique_tools_used": [
                        "list_cloud_secrets",
                        "execute_shell_command",
                        "dump_database_credentials",
                    ],
                    "attack_categories": {"exfiltration": 10, "rce": 5},
                    "first_seen": "2026-03-28T10:00:00Z",
                    "last_seen": "2026-03-28T12:00:00Z",
                    "attack_velocity": 7.5,
                    "sophistication_score": 0.72,
                    "behavioral_fingerprint": {
                        "tool_sequence": ["list_cloud_secrets", "execute_shell_command"],
                        "preferred_categories": [["exfiltration", 10], ["rce", 5]],
                        "attack_duration_hours": 2.0,
                        "avg_time_between_attacks": 480.0,
                    },
                }
            ]
        }
    }


class PatternSummary(BaseModel):
    """Summary statistics for detected patterns.

    Provides aggregate metrics across all detected patterns
    for dashboard display and reporting.
    """

    total_patterns: int = Field(description="Total number of patterns detected")
    by_type: Dict[str, int] = Field(description="Count of patterns by type")
    by_severity: Dict[str, int] = Field(description="Count of patterns by severity")
    high_confidence_count: int = Field(description="Number of patterns with confidence >= 0.8")
    recent_patterns: List[AttackPattern] = Field(description="Most recent patterns (last 10)")
