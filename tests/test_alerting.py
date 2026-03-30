"""Tests for alerting and notification system."""

import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from honeymcp.models.alerts import (
    Alert,
    AlertChannel,
    AlertConfig,
    AlertRule,
    AlertSeverity,
)
from honeymcp.models.events import AttackFingerprint
from honeymcp.models.attack_patterns import AttackPattern
from honeymcp.integrations.alerting import AlertRulesEngine
from honeymcp.integrations.notifiers import (
    SlackNotifier,
    PagerDutyNotifier,
    EmailNotifier,
    WebhookNotifier,
    NotificationManager,
)


def create_test_event(
    event_id: str = "evt_001",
    threat_level: str = "high",
    category: str = "exfiltration",
) -> AttackFingerprint:
    """Helper to create test attack events."""
    return AttackFingerprint(
        event_id=event_id,
        timestamp=datetime.utcnow(),
        session_id="sess_test",
        ghost_tool_called="list_cloud_secrets",
        arguments={},
        conversation_history=None,
        tool_call_sequence=["list_cloud_secrets"],
        threat_level=threat_level,
        attack_category=category,
        client_metadata={"user_agent": "test"},
        response_sent="fake response",
    )


def create_test_pattern(
    pattern_type: str = "coordinated",
    confidence: float = 0.85,
) -> AttackPattern:
    """Helper to create test attack patterns."""
    return AttackPattern(
        pattern_id="pattern_001",
        pattern_type=pattern_type,
        confidence=confidence,
        event_ids=["evt_001", "evt_002"],
        session_ids=["sess_a", "sess_b"],
        first_seen=datetime.utcnow() - timedelta(hours=1),
        last_seen=datetime.utcnow(),
        characteristics={"session_count": 2},
        severity="high",
        description="Test pattern",
        recommendations=["Test recommendation"],
    )


class TestAlertRulesEngine:
    """Tests for alert rules engine."""

    def test_initialization(self):
        """Test engine initialization."""
        rule = AlertRule(
            rule_id="rule_001",
            name="Test Rule",
            description="Test",
            channels=[AlertChannel.SLACK],
        )
        
        config = AlertConfig(rules=[rule])
        engine = AlertRulesEngine(config)
        
        assert len(engine.rules) == 1
        assert "rule_001" in engine.rules

    def test_add_remove_rule(self):
        """Test adding and removing rules."""
        config = AlertConfig()
        engine = AlertRulesEngine(config)
        
        rule = AlertRule(
            rule_id="rule_001",
            name="Test Rule",
            description="Test",
            channels=[AlertChannel.SLACK],
        )
        
        engine.add_rule(rule)
        assert "rule_001" in engine.rules
        
        removed = engine.remove_rule("rule_001")
        assert removed is True
        assert "rule_001" not in engine.rules
        
        removed = engine.remove_rule("nonexistent")
        assert removed is False

    def test_evaluate_attack_event_basic(self):
        """Test basic attack event evaluation."""
        rule = AlertRule(
            rule_id="rule_001",
            name="High Threat Rule",
            description="Alert on high threats",
            event_types=["attack"],
            min_threat_level="high",
            channels=[AlertChannel.SLACK],
        )
        
        config = AlertConfig(rules=[rule])
        engine = AlertRulesEngine(config)
        
        # Should match
        event = create_test_event(threat_level="high")
        alerts = engine.evaluate_attack_event(event)
        assert len(alerts) == 1
        assert alerts[0].severity == AlertSeverity.WARNING

    def test_threat_level_filtering(self):
        """Test threat level filtering."""
        rule = AlertRule(
            rule_id="rule_001",
            name="Critical Only",
            description="Alert on critical only",
            event_types=["attack"],
            min_threat_level="critical",
            channels=[AlertChannel.SLACK],
        )
        
        config = AlertConfig(rules=[rule])
        engine = AlertRulesEngine(config)
        
        # Should not match (too low)
        event = create_test_event(threat_level="high")
        alerts = engine.evaluate_attack_event(event)
        assert len(alerts) == 0
        
        # Should match
        event = create_test_event(threat_level="critical")
        alerts = engine.evaluate_attack_event(event)
        assert len(alerts) == 1

    def test_category_filtering(self):
        """Test attack category filtering."""
        rule = AlertRule(
            rule_id="rule_001",
            name="RCE Only",
            description="Alert on RCE",
            event_types=["attack"],
            attack_categories=["rce"],
            channels=[AlertChannel.SLACK],
        )
        
        config = AlertConfig(rules=[rule])
        engine = AlertRulesEngine(config)
        
        # Should not match
        event = create_test_event(category="exfiltration")
        alerts = engine.evaluate_attack_event(event)
        assert len(alerts) == 0
        
        # Should match
        event = create_test_event(category="rce")
        alerts = engine.evaluate_attack_event(event)
        assert len(alerts) == 1

    def test_deduplication(self):
        """Test alert deduplication."""
        rule = AlertRule(
            rule_id="rule_001",
            name="Test Rule",
            description="Test",
            event_types=["attack"],
            channels=[AlertChannel.SLACK],
            deduplicate=True,
            deduplicate_window_seconds=60,
        )
        
        config = AlertConfig(rules=[rule])
        engine = AlertRulesEngine(config)
        
        event = create_test_event()
        
        # First alert should go through
        alerts1 = engine.evaluate_attack_event(event)
        assert len(alerts1) == 1
        
        # Second alert should be deduplicated
        alerts2 = engine.evaluate_attack_event(event)
        assert len(alerts2) == 0

    def test_rate_limiting(self):
        """Test rate limiting."""
        rule = AlertRule(
            rule_id="rule_001",
            name="Test Rule",
            description="Test",
            event_types=["attack"],
            channels=[AlertChannel.SLACK],
            rate_limit_count=2,
            rate_limit_window_seconds=60,
            deduplicate=False,  # Disable dedup to test rate limit
        )
        
        config = AlertConfig(rules=[rule])
        engine = AlertRulesEngine(config)
        
        # First two should go through
        for i in range(2):
            event = create_test_event(event_id=f"evt_{i}")
            alerts = engine.evaluate_attack_event(event)
            assert len(alerts) == 1
        
        # Third should be rate limited
        event = create_test_event(event_id="evt_3")
        alerts = engine.evaluate_attack_event(event)
        assert len(alerts) == 0

    def test_evaluate_pattern(self):
        """Test pattern evaluation."""
        rule = AlertRule(
            rule_id="rule_001",
            name="Pattern Rule",
            description="Alert on patterns",
            event_types=["pattern"],
            pattern_types=["coordinated"],
            min_confidence=0.8,
            channels=[AlertChannel.SLACK],
        )
        
        config = AlertConfig(rules=[rule])
        engine = AlertRulesEngine(config)
        
        # Should match
        pattern = create_test_pattern(pattern_type="coordinated", confidence=0.85)
        alerts = engine.evaluate_pattern(pattern)
        assert len(alerts) == 1
        
        # Should not match (wrong type)
        pattern = create_test_pattern(pattern_type="campaign", confidence=0.85)
        alerts = engine.evaluate_pattern(pattern)
        assert len(alerts) == 0
        
        # Should not match (low confidence)
        pattern = create_test_pattern(pattern_type="coordinated", confidence=0.7)
        alerts = engine.evaluate_pattern(pattern)
        assert len(alerts) == 0

    def test_disabled_rule(self):
        """Test that disabled rules don't trigger."""
        rule = AlertRule(
            rule_id="rule_001",
            name="Disabled Rule",
            description="Test",
            event_types=["attack"],
            channels=[AlertChannel.SLACK],
            enabled=False,
        )
        
        config = AlertConfig(rules=[rule])
        engine = AlertRulesEngine(config)
        
        event = create_test_event()
        alerts = engine.evaluate_attack_event(event)
        assert len(alerts) == 0

    def test_cleanup_old_tracking_data(self):
        """Test cleanup of old tracking data."""
        rule = AlertRule(
            rule_id="rule_001",
            name="Test Rule",
            description="Test",
            event_types=["attack"],
            channels=[AlertChannel.SLACK],
        )
        
        config = AlertConfig(rules=[rule])
        engine = AlertRulesEngine(config)
        
        # Generate some alerts
        for i in range(5):
            event = create_test_event(event_id=f"evt_{i}")
            engine.evaluate_attack_event(event)
        
        # Should have tracking data
        assert len(engine._recent_alerts) > 0
        
        # Cleanup (with 0 hours to remove everything)
        engine.cleanup_old_tracking_data(max_age_hours=0)
        
        # Should be empty
        assert len(engine._recent_alerts) == 0


class TestNotifiers:
    """Tests for notification delivery."""

    @pytest.mark.asyncio
    async def test_slack_notifier_success(self):
        """Test successful Slack notification."""
        config = AlertConfig(
            slack_webhook_url="https://hooks.slack.com/test",
            slack_channel="#security",
        )
        
        notifier = SlackNotifier(config)
        
        alert = Alert(
            alert_id="alert_001",
            rule_id="rule_001",
            timestamp=datetime.utcnow(),
            severity=AlertSeverity.WARNING,
            title="Test Alert",
            message="Test message",
            channels=[AlertChannel.SLACK],
            delivery_status={"slack": "pending"},
            delivery_attempts={"slack": 0},
        )
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.__aenter__.return_value = mock_response
            
            mock_post = AsyncMock()
            mock_post.return_value = mock_response
            
            mock_session.return_value.__aenter__.return_value.post = mock_post
            
            success = await notifier.send(alert)
            assert success is True

    @pytest.mark.asyncio
    async def test_slack_notifier_no_webhook(self):
        """Test Slack notifier without webhook configured."""
        config = AlertConfig()  # No webhook URL
        notifier = SlackNotifier(config)
        
        alert = Alert(
            alert_id="alert_001",
            rule_id="rule_001",
            timestamp=datetime.utcnow(),
            severity=AlertSeverity.WARNING,
            title="Test Alert",
            message="Test message",
            channels=[AlertChannel.SLACK],
            delivery_status={"slack": "pending"},
            delivery_attempts={"slack": 0},
        )
        
        success = await notifier.send(alert)
        assert success is False

    @pytest.mark.asyncio
    async def test_pagerduty_notifier_success(self):
        """Test successful PagerDuty notification."""
        config = AlertConfig(
            pagerduty_routing_key="test_routing_key",
        )
        
        notifier = PagerDutyNotifier(config)
        
        alert = Alert(
            alert_id="alert_001",
            rule_id="rule_001",
            timestamp=datetime.utcnow(),
            severity=AlertSeverity.CRITICAL,
            title="Test Alert",
            message="Test message",
            channels=[AlertChannel.PAGERDUTY],
            delivery_status={"pagerduty": "pending"},
            delivery_attempts={"pagerduty": 0},
        )
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 202
            mock_response.__aenter__.return_value = mock_response
            
            mock_post = AsyncMock()
            mock_post.return_value = mock_response
            
            mock_session.return_value.__aenter__.return_value.post = mock_post
            
            success = await notifier.send(alert)
            assert success is True

    @pytest.mark.asyncio
    async def test_webhook_notifier_success(self):
        """Test successful webhook notification."""
        config = AlertConfig(
            webhook_urls=["https://example.com/webhook"],
        )
        
        notifier = WebhookNotifier(config)
        
        alert = Alert(
            alert_id="alert_001",
            rule_id="rule_001",
            timestamp=datetime.utcnow(),
            severity=AlertSeverity.WARNING,
            title="Test Alert",
            message="Test message",
            channels=[AlertChannel.WEBHOOK],
            delivery_status={"webhook": "pending"},
            delivery_attempts={"webhook": 0},
        )
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.__aenter__.return_value = mock_response
            
            mock_post = AsyncMock()
            mock_post.return_value = mock_response
            
            mock_session.return_value.__aenter__.return_value.post = mock_post
            
            success = await notifier.send(alert)
            assert success is True

    @pytest.mark.asyncio
    async def test_retry_logic(self):
        """Test retry with exponential backoff."""
        config = AlertConfig(
            slack_webhook_url="https://hooks.slack.com/test",
            max_retries=3,
            retry_delay_seconds=1,
            retry_backoff_multiplier=2.0,
        )
        
        notifier = SlackNotifier(config)
        
        alert = Alert(
            alert_id="alert_001",
            rule_id="rule_001",
            timestamp=datetime.utcnow(),
            severity=AlertSeverity.WARNING,
            title="Test Alert",
            message="Test message",
            channels=[AlertChannel.SLACK],
            delivery_status={"slack": "pending"},
            delivery_attempts={"slack": 0},
        )
        
        with patch('aiohttp.ClientSession') as mock_session:
            # Fail twice, succeed on third attempt
            mock_response_fail = AsyncMock()
            mock_response_fail.status = 500
            mock_response_fail.__aenter__.return_value = mock_response_fail
            
            mock_response_success = AsyncMock()
            mock_response_success.status = 200
            mock_response_success.__aenter__.return_value = mock_response_success
            
            mock_post = AsyncMock()
            mock_post.side_effect = [
                mock_response_fail,
                mock_response_fail,
                mock_response_success,
            ]
            
            mock_session.return_value.__aenter__.return_value.post = mock_post
            
            with patch('asyncio.sleep', new_callable=AsyncMock):
                success = await notifier.send_with_retry(alert)
                assert success is True
                assert alert.delivery_attempts["slack"] == 3

    @pytest.mark.asyncio
    async def test_notification_manager(self):
        """Test notification manager multi-channel delivery."""
        config = AlertConfig(
            slack_webhook_url="https://hooks.slack.com/test",
            webhook_urls=["https://example.com/webhook"],
        )
        
        manager = NotificationManager(config)
        
        alert = Alert(
            alert_id="alert_001",
            rule_id="rule_001",
            timestamp=datetime.utcnow(),
            severity=AlertSeverity.WARNING,
            title="Test Alert",
            message="Test message",
            channels=[AlertChannel.SLACK, AlertChannel.WEBHOOK],
            delivery_status={
                "slack": "pending",
                "webhook": "pending",
            },
            delivery_attempts={
                "slack": 0,
                "webhook": 0,
            },
        )
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.__aenter__.return_value = mock_response
            
            mock_post = AsyncMock()
            mock_post.return_value = mock_response
            
            mock_session.return_value.__aenter__.return_value.post = mock_post
            
            success = await manager.send_alert(alert)
            assert success is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
