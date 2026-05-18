"""Alert rules engine and notification system."""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from uuid import uuid4
from collections import defaultdict

from honeymcp.models.alerts import (
    Alert,
    AlertChannel,
    AlertConfig,
    AlertRule,
    AlertSeverity,
)
from honeymcp.models.events import AttackFingerprint
from honeymcp.models.attack_patterns import AttackPattern

logger = logging.getLogger(__name__)


class AlertRulesEngine:
    """Evaluates events against alert rules and triggers notifications.

    Features:
    - Rule-based filtering and matching
    - Alert deduplication
    - Rate limiting
    - Multi-channel delivery
    - Retry with exponential backoff
    """

    def __init__(self, config: AlertConfig) -> None:
        """Initialize alert rules engine.

        Args:
            config: Alert configuration with rules and channel settings
        """
        self.config = config
        self.rules = {rule.rule_id: rule for rule in config.rules}

        # Deduplication tracking
        self._recent_alerts: Dict[str, datetime] = {}

        # Rate limiting tracking
        self._rate_limit_counts: Dict[str, List[datetime]] = defaultdict(list)

        # Pending alerts queue
        self._pending_alerts: List[Alert] = []

        logger.info("Alert rules engine initialized with %d rules", len(self.rules))

    def add_rule(self, rule: AlertRule) -> None:
        """Add or update an alert rule.

        Args:
            rule: Alert rule to add
        """
        self.rules[rule.rule_id] = rule
        logger.info("Added alert rule: %s", rule.name)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove an alert rule.

        Args:
            rule_id: ID of rule to remove

        Returns:
            True if rule was removed, False if not found
        """
        if rule_id in self.rules:
            del self.rules[rule_id]
            logger.info("Removed alert rule: %s", rule_id)
            return True
        return False

    def evaluate_attack_event(
        self,
        event: AttackFingerprint,
    ) -> List[Alert]:
        """Evaluate an attack event against all rules.

        Args:
            event: Attack event to evaluate

        Returns:
            List of alerts to send
        """
        if not self.config.enabled:
            return []

        alerts = []

        for rule in self.rules.values():
            if not rule.enabled:
                continue

            # Check if rule matches this event type
            if "attack" not in rule.event_types:
                continue

            # Apply filters
            if not self._matches_attack_filters(event, rule):
                continue

            # Check rate limiting
            if not self._check_rate_limit(rule):
                logger.debug("Rate limit exceeded for rule %s", rule.rule_id)
                continue

            # Create alert
            alert = self._create_attack_alert(event, rule)

            # Check deduplication
            if rule.deduplicate and self._is_duplicate(alert, rule):
                logger.debug("Duplicate alert suppressed for rule %s", rule.rule_id)
                continue

            alerts.append(alert)
            self._track_alert(alert, rule)

        return alerts

    def evaluate_pattern(
        self,
        pattern: AttackPattern,
    ) -> List[Alert]:
        """Evaluate a detected pattern against all rules.

        Args:
            pattern: Attack pattern to evaluate

        Returns:
            List of alerts to send
        """
        if not self.config.enabled:
            return []

        alerts = []

        for rule in self.rules.values():
            if not rule.enabled:
                continue

            # Check if rule matches pattern events
            if "pattern" not in rule.event_types:
                continue

            # Apply filters
            if not self._matches_pattern_filters(pattern, rule):
                continue

            # Check rate limiting
            if not self._check_rate_limit(rule):
                logger.debug("Rate limit exceeded for rule %s", rule.rule_id)
                continue

            # Create alert
            alert = self._create_pattern_alert(pattern, rule)

            # Check deduplication
            if rule.deduplicate and self._is_duplicate(alert, rule):
                logger.debug("Duplicate alert suppressed for rule %s", rule.rule_id)
                continue

            alerts.append(alert)
            self._track_alert(alert, rule)

        return alerts

    def _matches_attack_filters(
        self,
        event: AttackFingerprint,
        rule: AlertRule,
    ) -> bool:
        """Check if attack event matches rule filters.

        Args:
            event: Attack event to check
            rule: Rule with filter criteria

        Returns:
            True if event matches all filters
        """
        # Check threat level
        if rule.min_threat_level:
            threat_levels = ["low", "medium", "high", "critical"]
            min_index = threat_levels.index(rule.min_threat_level)
            event_index = threat_levels.index(event.threat_level)

            if event_index < min_index:
                return False

        # Check attack categories
        if rule.attack_categories:
            if event.attack_category not in rule.attack_categories:
                return False

        return True

    def _matches_pattern_filters(
        self,
        pattern: AttackPattern,
        rule: AlertRule,
    ) -> bool:
        """Check if pattern matches rule filters.

        Args:
            pattern: Pattern to check
            rule: Rule with filter criteria

        Returns:
            True if pattern matches all filters
        """
        # Check pattern types
        if rule.pattern_types:
            if pattern.pattern_type not in rule.pattern_types:
                return False

        # Check confidence threshold
        if rule.min_confidence is not None:
            if pattern.confidence < rule.min_confidence:
                return False

        return True

    def _check_rate_limit(self, rule: AlertRule) -> bool:
        """Check if rule has exceeded rate limit.

        Args:
            rule: Rule to check

        Returns:
            True if within rate limit, False if exceeded
        """
        if rule.rate_limit_count is None:
            return True

        now = datetime.utcnow()
        window_start = now - timedelta(seconds=rule.rate_limit_window_seconds)

        # Clean old timestamps
        self._rate_limit_counts[rule.rule_id] = [
            ts for ts in self._rate_limit_counts[rule.rule_id] if ts > window_start
        ]

        # Check count
        count = len(self._rate_limit_counts[rule.rule_id])
        return count < rule.rate_limit_count

    def _is_duplicate(self, alert: Alert, rule: AlertRule) -> bool:
        """Check if alert is a duplicate within deduplication window.

        Args:
            alert: Alert to check
            rule: Rule with deduplication settings

        Returns:
            True if duplicate, False otherwise
        """
        # Create deduplication key based on alert content
        dedup_key = f"{rule.rule_id}:{alert.title}"

        if dedup_key in self._recent_alerts:
            last_time = self._recent_alerts[dedup_key]
            window = timedelta(seconds=rule.deduplicate_window_seconds)

            if datetime.utcnow() - last_time < window:
                return True

        return False

    def _track_alert(self, alert: Alert, rule: AlertRule) -> None:
        """Track alert for deduplication and rate limiting.

        Args:
            alert: Alert that was created
            rule: Rule that triggered the alert
        """
        now = datetime.utcnow()

        # Track for deduplication
        if rule.deduplicate:
            dedup_key = f"{rule.rule_id}:{alert.title}"
            self._recent_alerts[dedup_key] = now

        # Track for rate limiting
        if rule.rate_limit_count is not None:
            self._rate_limit_counts[rule.rule_id].append(now)

    def _create_attack_alert(
        self,
        event: AttackFingerprint,
        rule: AlertRule,
    ) -> Alert:
        """Create alert from attack event.

        Args:
            event: Attack event
            rule: Rule that triggered

        Returns:
            Alert instance
        """
        title = f"🚨 Attack Detected: {event.ghost_tool_called}"

        message_parts = [
            f"**Threat Level:** {event.threat_level.upper()}",
            f"**Category:** {event.attack_category}",
            f"**Tool:** {event.ghost_tool_called}",
            f"**Session:** {event.session_id}",
            f"**Time:** {event.timestamp.isoformat()}",
        ]

        if event.client_metadata:
            message_parts.append(f"**Client:** {event.client_metadata}")

        message = "\n".join(message_parts)

        return Alert(
            alert_id=f"alert_{uuid4().hex[:12]}",
            rule_id=rule.rule_id,
            timestamp=datetime.utcnow(),
            severity=rule.severity,
            title=title,
            message=message,
            event_id=event.event_id,
            channels=rule.channels,
            metadata={
                "event_type": "attack",
                "threat_level": event.threat_level,
                "attack_category": event.attack_category,
                "ghost_tool": event.ghost_tool_called,
            },
            delivery_status={channel.value: "pending" for channel in rule.channels},
            delivery_attempts={channel.value: 0 for channel in rule.channels},
        )

    def _create_pattern_alert(
        self,
        pattern: AttackPattern,
        rule: AlertRule,
    ) -> Alert:
        """Create alert from attack pattern.

        Args:
            pattern: Attack pattern
            rule: Rule that triggered

        Returns:
            Alert instance
        """
        # Determine emoji based on pattern type
        emoji_map = {
            "coordinated": "🎯",
            "campaign": "📊",
            "anomaly": "⚠️",
            "reconnaissance": "🔍",
        }
        emoji = emoji_map.get(pattern.pattern_type, "🚨")

        title = f"{emoji} {pattern.pattern_type.title()} Pattern: {pattern.description}"

        message_parts = [
            f"**Pattern Type:** {pattern.pattern_type}",
            f"**Confidence:** {pattern.confidence:.2%}",
            f"**Severity:** {pattern.severity.upper()}",
            f"**Sessions:** {len(pattern.session_ids)}",
            f"**Events:** {len(pattern.event_ids)}",
            f"**First Seen:** {pattern.first_seen.isoformat()}",
            f"**Last Seen:** {pattern.last_seen.isoformat()}",
            "",
            "**Characteristics:**",
        ]

        for key, value in pattern.characteristics.items():
            message_parts.append(f"- {key}: {value}")

        if pattern.recommendations:
            message_parts.append("")
            message_parts.append("**Recommendations:**")
            for rec in pattern.recommendations:
                message_parts.append(f"- {rec}")

        message = "\n".join(message_parts)

        return Alert(
            alert_id=f"alert_{uuid4().hex[:12]}",
            rule_id=rule.rule_id,
            timestamp=datetime.utcnow(),
            severity=rule.severity,
            title=title,
            message=message,
            pattern_id=pattern.pattern_id,
            channels=rule.channels,
            metadata={
                "event_type": "pattern",
                "pattern_type": pattern.pattern_type,
                "confidence": pattern.confidence,
                "severity": pattern.severity,
                "session_count": len(pattern.session_ids),
            },
            delivery_status={channel.value: "pending" for channel in rule.channels},
            delivery_attempts={channel.value: 0 for channel in rule.channels},
        )

    def cleanup_old_tracking_data(self, max_age_hours: int = 24) -> None:
        """Clean up old deduplication and rate limit tracking data.

        Args:
            max_age_hours: Maximum age of data to keep
        """
        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)

        # Clean deduplication tracking
        old_keys = [key for key, timestamp in self._recent_alerts.items() if timestamp < cutoff]
        for key in old_keys:
            del self._recent_alerts[key]

        # Clean rate limit tracking
        for rule_id in list(self._rate_limit_counts.keys()):
            self._rate_limit_counts[rule_id] = [
                ts for ts in self._rate_limit_counts[rule_id] if ts > cutoff
            ]

            # Remove empty entries
            if not self._rate_limit_counts[rule_id]:
                del self._rate_limit_counts[rule_id]

        logger.debug("Cleaned up tracking data older than %d hours", max_age_hours)

    def get_stats(self) -> Dict[str, any]:
        """Get alerting statistics.

        Returns:
            Dictionary with stats
        """
        return {
            "enabled": self.config.enabled,
            "total_rules": len(self.rules),
            "enabled_rules": sum(1 for r in self.rules.values() if r.enabled),
            "tracked_dedup_keys": len(self._recent_alerts),
            "rate_limited_rules": len(self._rate_limit_counts),
        }
