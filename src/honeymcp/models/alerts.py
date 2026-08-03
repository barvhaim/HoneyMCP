"""Data models for alerting and notification system."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from enum import Enum
from pydantic import BaseModel, Field


class AlertChannel(str, Enum):
    """Supported alert channels."""

    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"
    WEBHOOK = "webhook"


class AlertSeverity(str, Enum):
    """Alert severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AlertRule(BaseModel):
    """Configuration for an alert rule.

    Defines conditions under which alerts should be triggered
    and how they should be delivered.
    """

    rule_id: str = Field(description="Unique rule identifier")
    name: str = Field(description="Human-readable rule name")
    description: str = Field(description="Rule description")

    enabled: bool = Field(default=True, description="Whether rule is active")

    event_types: List[str] = Field(
        default_factory=lambda: ["attack"],
        description="Event types to monitor (attack, pattern, etc.)",
    )
    min_threat_level: Optional[str] = Field(
        default=None, description="Minimum threat level (low, medium, high, critical)"
    )
    attack_categories: Optional[List[str]] = Field(
        default=None, description="Filter by attack categories"
    )
    pattern_types: Optional[List[str]] = Field(
        default=None, description="Filter by pattern types (coordinated, campaign, anomaly)"
    )
    min_confidence: Optional[float] = Field(
        default=None, ge=0.0, le=1.0, description="Minimum confidence score for patterns"
    )

    channels: List[AlertChannel] = Field(description="Channels to send alerts to")
    severity: AlertSeverity = Field(
        default=AlertSeverity.WARNING, description="Alert severity level"
    )

    deduplicate: bool = Field(default=True, description="Enable alert deduplication")
    deduplicate_window_seconds: int = Field(
        default=300, description="Deduplication time window in seconds"
    )

    rate_limit_count: Optional[int] = Field(default=None, description="Max alerts per time window")
    rate_limit_window_seconds: int = Field(
        default=3600, description="Rate limit time window in seconds"
    )

    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional rule metadata")


class Alert(BaseModel):
    """An alert notification to be sent.

    Represents a specific alert instance that will be
    delivered through one or more channels.
    """

    alert_id: str = Field(description="Unique alert identifier")
    rule_id: str = Field(description="Rule that triggered this alert")

    timestamp: datetime = Field(description="When alert was created")
    severity: AlertSeverity = Field(description="Alert severity")

    title: str = Field(description="Alert title/subject")
    message: str = Field(description="Alert message body")

    event_id: Optional[str] = Field(default=None, description="Related event ID if applicable")
    pattern_id: Optional[str] = Field(default=None, description="Related pattern ID if applicable")

    channels: List[AlertChannel] = Field(description="Channels to deliver to")

    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional alert context")

    delivery_status: Dict[str, str] = Field(
        default_factory=dict, description="Delivery status per channel (pending, sent, failed)"
    )
    delivery_attempts: Dict[str, int] = Field(
        default_factory=dict, description="Number of delivery attempts per channel"
    )
    last_attempt: Optional[datetime] = Field(
        default=None, description="Timestamp of last delivery attempt"
    )


class AlertConfig(BaseModel):
    """Global alerting configuration."""

    enabled: bool = Field(default=True, description="Enable alerting system")

    slack_webhook_url: Optional[str] = Field(default=None, description="Slack webhook URL")
    slack_channel: Optional[str] = Field(default=None, description="Default Slack channel")

    pagerduty_api_key: Optional[str] = Field(default=None, description="PagerDuty API key")
    pagerduty_routing_key: Optional[str] = Field(default=None, description="PagerDuty routing key")

    smtp_host: Optional[str] = Field(default=None, description="SMTP server host")
    smtp_port: int = Field(default=587, description="SMTP server port")
    smtp_username: Optional[str] = Field(default=None, description="SMTP username")
    smtp_password: Optional[str] = Field(default=None, description="SMTP password")
    smtp_from: Optional[str] = Field(default=None, description="From email address")
    smtp_to: List[str] = Field(
        default_factory=list, description="Default recipient email addresses"
    )

    webhook_urls: List[str] = Field(default_factory=list, description="Generic webhook URLs")

    max_retries: int = Field(default=3, description="Max delivery retry attempts")
    retry_delay_seconds: int = Field(default=60, description="Initial retry delay in seconds")
    retry_backoff_multiplier: float = Field(
        default=2.0, description="Exponential backoff multiplier"
    )

    rules: List[AlertRule] = Field(default_factory=list, description="Configured alert rules")


class StreamEvent(BaseModel):
    """Event for Server-Sent Events (SSE) streaming.

    Wraps events for real-time streaming to clients.
    """

    event_type: str = Field(description="Type of event (attack, pattern, alert)")
    timestamp: datetime = Field(description="Event timestamp")
    data: Dict[str, Any] = Field(description="Event data payload")

    def to_sse_format(self) -> str:
        """Convert to SSE format string.

        Returns:
            SSE-formatted string ready for streaming
        """
        import json

        lines = []
        lines.append(f"event: {self.event_type}")
        lines.append(f"data: {json.dumps(self.data, default=str)}")
        lines.append("")  # Empty line to end event

        return "\n".join(lines) + "\n"
