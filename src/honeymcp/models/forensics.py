"""Data models for attack replay and forensics."""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from enum import Enum
from pydantic import BaseModel, Field

from honeymcp.models.events import AttackFingerprint


class ReplaySpeed(str, Enum):
    """Replay speed options."""

    REALTIME = "realtime"
    FAST_2X = "2x"
    FAST_5X = "5x"
    FAST_10X = "10x"
    INSTANT = "instant"


class TimelineEvent(BaseModel):
    """Single event in attack timeline."""

    timestamp: datetime = Field(description="Event timestamp")
    elapsed_seconds: float = Field(description="Seconds since session start")
    event_type: str = Field(description="Type of event (tool_call, response, etc.)")

    tool_name: Optional[str] = Field(default=None, description="Ghost tool called")
    arguments: Optional[Dict[str, Any]] = Field(default=None, description="Tool arguments")
    response: Optional[str] = Field(default=None, description="Response sent")

    threat_level: Optional[str] = Field(default=None, description="Threat level")
    attack_category: Optional[str] = Field(default=None, description="Attack category")

    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional event metadata")


class AttackTimeline(BaseModel):
    """Complete timeline of an attack session."""

    session_id: str = Field(description="Session identifier")
    start_time: datetime = Field(description="Session start time")
    end_time: datetime = Field(description="Session end time")
    duration_seconds: float = Field(description="Total session duration")

    events: List[TimelineEvent] = Field(description="Timeline events in order")
    event_count: int = Field(description="Total number of events")

    unique_tools_used: List[str] = Field(description="Unique ghost tools triggered")
    attack_categories: List[str] = Field(description="Attack categories observed")
    max_threat_level: str = Field(description="Highest threat level observed")

    avg_time_between_events: float = Field(description="Average time between events in seconds")
    tool_sequence: List[str] = Field(description="Sequence of tools called")


class ReplaySession(BaseModel):
    """Active replay session state."""

    replay_id: str = Field(description="Unique replay session ID")
    session_id: str = Field(description="Original attack session ID")
    timeline: AttackTimeline = Field(description="Attack timeline")

    current_index: int = Field(default=0, description="Current event index")
    is_playing: bool = Field(default=False, description="Whether replay is playing")
    speed: ReplaySpeed = Field(default=ReplaySpeed.REALTIME, description="Playback speed")

    created_at: datetime = Field(description="When replay session was created")
    last_updated: datetime = Field(description="Last state update time")


class ForensicReport(BaseModel):
    """Forensic analysis report for an attack session."""

    report_id: str = Field(description="Unique report identifier")
    session_id: str = Field(description="Attack session ID")
    generated_at: datetime = Field(description="Report generation timestamp")

    title: str = Field(description="Report title")
    summary: str = Field(description="Executive summary")
    severity: str = Field(description="Overall severity assessment")

    timeline: AttackTimeline = Field(description="Attack timeline")

    attack_vector: str = Field(description="Primary attack vector")
    techniques_used: List[str] = Field(description="Attack techniques observed")
    indicators_of_compromise: List[str] = Field(description="IOCs extracted from attack")

    recommendations: List[str] = Field(description="Security recommendations")
    mitigation_steps: List[str] = Field(description="Specific mitigation actions")

    mitre_tactics: List[str] = Field(default_factory=list, description="MITRE ATT&CK tactics")
    mitre_techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK techniques")

    analyst_notes: Optional[str] = Field(default=None, description="Additional analyst notes")
    tags: List[str] = Field(default_factory=list, description="Report tags for categorization")


class ExportFormat(str, Enum):
    """Supported export formats."""

    JSON = "json"
    CSV = "csv"
    HTML = "html"
    PDF = "pdf"
    STIX = "stix"


class STIXIndicator(BaseModel):
    """STIX 2.1 Indicator object."""

    type: str = Field(default="indicator", description="STIX object type")
    spec_version: str = Field(default="2.1", description="STIX version")
    id: str = Field(description="STIX identifier")
    created: datetime = Field(description="Creation timestamp")
    modified: datetime = Field(description="Modification timestamp")

    name: str = Field(description="Indicator name")
    description: str = Field(description="Indicator description")
    pattern: str = Field(description="STIX pattern")
    pattern_type: str = Field(default="stix", description="Pattern type")
    valid_from: datetime = Field(description="Valid from timestamp")

    labels: List[str] = Field(description="Indicator labels")
    confidence: int = Field(description="Confidence score 0-100")


class STIXBundle(BaseModel):
    """STIX 2.1 Bundle containing indicators."""

    type: str = Field(default="bundle", description="STIX object type")
    id: str = Field(description="Bundle identifier")
    objects: List[STIXIndicator] = Field(description="STIX objects in bundle")


class ReplayControl(BaseModel):
    """Replay control commands."""

    action: str = Field(description="Control action: play, pause, stop, seek, speed")

    # For seek action
    target_index: Optional[int] = Field(default=None, description="Target event index for seek")

    # For speed action
    speed: Optional[ReplaySpeed] = Field(default=None, description="Playback speed")


class ReplayState(BaseModel):
    """Current state of replay session."""

    replay_id: str = Field(description="Replay session ID")
    current_index: int = Field(description="Current event index")
    total_events: int = Field(description="Total events in timeline")
    is_playing: bool = Field(description="Whether replay is playing")
    speed: ReplaySpeed = Field(description="Current playback speed")

    current_event: Optional[TimelineEvent] = Field(
        default=None, description="Current event being displayed"
    )

    progress_percent: float = Field(description="Playback progress percentage")
    elapsed_time: float = Field(description="Elapsed time in replay (seconds)")
    remaining_time: float = Field(description="Remaining time in replay (seconds)")


class ComparisonReport(BaseModel):
    """Side-by-side comparison of multiple attack sessions."""

    report_id: str = Field(description="Comparison report ID")
    session_ids: List[str] = Field(description="Sessions being compared")
    generated_at: datetime = Field(description="Generation timestamp")

    common_tools: List[str] = Field(description="Tools used by all sessions")
    common_categories: List[str] = Field(description="Common attack categories")

    unique_tools_per_session: Dict[str, List[str]] = Field(description="Unique tools per session")

    avg_duration: float = Field(description="Average session duration")
    avg_events_per_session: float = Field(description="Average events per session")

    sophistication_scores: Dict[str, float] = Field(description="Sophistication score per session")

    analysis: str = Field(description="Comparative analysis summary")
    similarities: List[str] = Field(description="Key similarities")
    differences: List[str] = Field(description="Key differences")
