"""Tests for attack pattern detection and correlation."""

import pytest
from datetime import datetime, timedelta
from honeymcp.models.events import AttackFingerprint
from honeymcp.analysis.pattern_detector import PatternDetector


def create_test_event(
    event_id: str,
    session_id: str,
    tool: str,
    category: str = "exfiltration",
    threat_level: str = "high",
    timestamp: datetime = None,
) -> AttackFingerprint:
    """Helper to create test attack events."""
    if timestamp is None:
        timestamp = datetime.utcnow()
    
    return AttackFingerprint(
        event_id=event_id,
        timestamp=timestamp,
        session_id=session_id,
        ghost_tool_called=tool,
        arguments={},
        conversation_history=None,
        tool_call_sequence=[tool],
        threat_level=threat_level,
        attack_category=category,
        client_metadata={"user_agent": "test"},
        response_sent="fake response",
    )


class TestCoordinatedAttackDetection:
    """Tests for coordinated attack detection."""

    @pytest.mark.asyncio
    async def test_detect_coordinated_attacks_basic(self):
        """Test basic coordinated attack detection."""
        detector = PatternDetector(coordinated_threshold=3)
        
        # Create 3 sessions attacking within same hour
        base_time = datetime.utcnow()
        events = [
            create_test_event("evt1", "sess1", "list_cloud_secrets", timestamp=base_time),
            create_test_event("evt2", "sess2", "list_cloud_secrets", timestamp=base_time + timedelta(minutes=5)),
            create_test_event("evt3", "sess3", "list_cloud_secrets", timestamp=base_time + timedelta(minutes=10)),
        ]
        
        patterns = await detector.detect_coordinated_attacks(events)
        
        assert len(patterns) == 1
        pattern = patterns[0]
        assert pattern.pattern_type == "coordinated"
        assert len(pattern.session_ids) == 3
        assert "list_cloud_secrets" in pattern.characteristics["common_tools"]
        assert pattern.confidence > 0.5

    @pytest.mark.asyncio
    async def test_no_coordination_different_times(self):
        """Test that attacks at different times are not flagged as coordinated."""
        detector = PatternDetector(coordinated_threshold=3)
        
        # Create 3 sessions attacking at different hours
        base_time = datetime.utcnow()
        events = [
            create_test_event("evt1", "sess1", "list_cloud_secrets", timestamp=base_time),
            create_test_event("evt2", "sess2", "list_cloud_secrets", timestamp=base_time + timedelta(hours=2)),
            create_test_event("evt3", "sess3", "list_cloud_secrets", timestamp=base_time + timedelta(hours=4)),
        ]
        
        patterns = await detector.detect_coordinated_attacks(events)
        
        # Should not detect coordination across different time buckets
        assert len(patterns) == 0

    @pytest.mark.asyncio
    async def test_coordination_threshold(self):
        """Test that coordination threshold is respected."""
        detector = PatternDetector(coordinated_threshold=5)
        
        # Create only 3 sessions (below threshold)
        base_time = datetime.utcnow()
        events = [
            create_test_event("evt1", "sess1", "list_cloud_secrets", timestamp=base_time),
            create_test_event("evt2", "sess2", "list_cloud_secrets", timestamp=base_time + timedelta(minutes=5)),
            create_test_event("evt3", "sess3", "list_cloud_secrets", timestamp=base_time + timedelta(minutes=10)),
        ]
        
        patterns = await detector.detect_coordinated_attacks(events)
        
        # Should not detect coordination (below threshold)
        assert len(patterns) == 0

    @pytest.mark.asyncio
    async def test_coordination_with_different_tools(self):
        """Test coordination detection with multiple common tools."""
        detector = PatternDetector(coordinated_threshold=3)
        
        base_time = datetime.utcnow()
        events = [
            create_test_event("evt1", "sess1", "list_cloud_secrets", timestamp=base_time),
            create_test_event("evt2", "sess1", "execute_shell_command", timestamp=base_time + timedelta(minutes=1)),
            create_test_event("evt3", "sess2", "list_cloud_secrets", timestamp=base_time + timedelta(minutes=2)),
            create_test_event("evt4", "sess2", "execute_shell_command", timestamp=base_time + timedelta(minutes=3)),
            create_test_event("evt5", "sess3", "list_cloud_secrets", timestamp=base_time + timedelta(minutes=4)),
            create_test_event("evt6", "sess3", "execute_shell_command", timestamp=base_time + timedelta(minutes=5)),
        ]
        
        patterns = await detector.detect_coordinated_attacks(events)
        
        assert len(patterns) == 1
        pattern = patterns[0]
        assert len(pattern.characteristics["common_tools"]) == 2
        assert pattern.confidence > 0.6  # Higher confidence with more common tools


class TestCampaignDetection:
    """Tests for attack campaign detection."""

    @pytest.mark.asyncio
    async def test_detect_campaign_basic(self):
        """Test basic campaign detection."""
        detector = PatternDetector(
            campaign_min_duration_hours=24,
            campaign_min_events=5
        )
        
        # Create sustained attack over 25 hours
        base_time = datetime.utcnow() - timedelta(hours=25)
        events = []
        for i in range(10):
            events.append(
                create_test_event(
                    f"evt{i}",
                    "sess1",
                    "list_cloud_secrets",
                    timestamp=base_time + timedelta(hours=i * 2.5)
                )
            )
        
        patterns = await detector.detect_attack_campaigns(events)
        
        assert len(patterns) == 1
        pattern = patterns[0]
        assert pattern.pattern_type == "campaign"
        assert pattern.session_ids == ["sess1"]
        assert pattern.characteristics["total_attempts"] == 10
        assert pattern.characteristics["duration_hours"] >= 24

    @pytest.mark.asyncio
    async def test_no_campaign_short_duration(self):
        """Test that short-duration attacks are not flagged as campaigns."""
        detector = PatternDetector(
            campaign_min_duration_hours=24,
            campaign_min_events=5
        )
        
        # Create attacks over only 2 hours
        base_time = datetime.utcnow()
        events = []
        for i in range(10):
            events.append(
                create_test_event(
                    f"evt{i}",
                    "sess1",
                    "list_cloud_secrets",
                    timestamp=base_time + timedelta(minutes=i * 12)
                )
            )
        
        patterns = await detector.detect_attack_campaigns(events)
        
        # Should not detect campaign (too short)
        assert len(patterns) == 0

    @pytest.mark.asyncio
    async def test_no_campaign_few_events(self):
        """Test that campaigns require minimum event count."""
        detector = PatternDetector(
            campaign_min_duration_hours=24,
            campaign_min_events=10
        )
        
        # Create only 5 events over 25 hours
        base_time = datetime.utcnow() - timedelta(hours=25)
        events = []
        for i in range(5):
            events.append(
                create_test_event(
                    f"evt{i}",
                    "sess1",
                    "list_cloud_secrets",
                    timestamp=base_time + timedelta(hours=i * 5)
                )
            )
        
        patterns = await detector.detect_attack_campaigns(events)
        
        # Should not detect campaign (too few events)
        assert len(patterns) == 0

    @pytest.mark.asyncio
    async def test_campaign_tool_diversity(self):
        """Test campaign detection with diverse tool usage."""
        detector = PatternDetector(
            campaign_min_duration_hours=24,
            campaign_min_events=5
        )
        
        base_time = datetime.utcnow() - timedelta(hours=25)
        tools = ["list_cloud_secrets", "execute_shell_command", "dump_database_credentials"]
        events = []
        
        for i in range(15):
            events.append(
                create_test_event(
                    f"evt{i}",
                    "sess1",
                    tools[i % len(tools)],
                    timestamp=base_time + timedelta(hours=i * 1.7)
                )
            )
        
        patterns = await detector.detect_attack_campaigns(events)
        
        assert len(patterns) == 1
        pattern = patterns[0]
        assert len(pattern.characteristics["unique_tools"]) == 3
        assert pattern.confidence > 0.6  # Higher confidence with tool diversity


class TestAnomalyDetection:
    """Tests for anomaly detection."""

    @pytest.mark.asyncio
    async def test_detect_anomaly_basic(self):
        """Test basic anomaly detection."""
        detector = PatternDetector()
        
        # Create events with one tool used much more than others
        events = []
        
        # Tool A used 50 times (anomalous)
        for i in range(50):
            events.append(create_test_event(f"evt_a{i}", f"sess{i}", "tool_a"))
        
        # Tool B used 5 times (normal)
        for i in range(5):
            events.append(create_test_event(f"evt_b{i}", f"sess{i+50}", "tool_b"))
        
        # Tool C used 5 times (normal)
        for i in range(5):
            events.append(create_test_event(f"evt_c{i}", f"sess{i+55}", "tool_c"))
        
        patterns = await detector.detect_anomalies(events)
        
        # Should detect tool_a as anomalous
        assert len(patterns) >= 1
        anomaly = next(p for p in patterns if "tool_a" in p.characteristics["tool"])
        assert anomaly.pattern_type == "anomaly"
        assert anomaly.characteristics["usage_count"] == 50

    @pytest.mark.asyncio
    async def test_no_anomaly_uniform_distribution(self):
        """Test that uniform distribution doesn't trigger anomalies."""
        detector = PatternDetector()
        
        # Create events with uniform tool usage
        tools = ["tool_a", "tool_b", "tool_c", "tool_d"]
        events = []
        
        for i in range(40):
            events.append(
                create_test_event(
                    f"evt{i}",
                    f"sess{i}",
                    tools[i % len(tools)]
                )
            )
        
        patterns = await detector.detect_anomalies(events)
        
        # Should not detect anomalies (uniform distribution)
        assert len(patterns) == 0

    @pytest.mark.asyncio
    async def test_anomaly_insufficient_data(self):
        """Test that anomaly detection requires sufficient data."""
        detector = PatternDetector()
        
        # Create only 5 events (below threshold)
        events = []
        for i in range(5):
            events.append(create_test_event(f"evt{i}", f"sess{i}", "tool_a"))
        
        patterns = await detector.detect_anomalies(events)
        
        # Should not detect anomalies (insufficient data)
        assert len(patterns) == 0


class TestAttackerProfiling:
    """Tests for attacker profiling."""

    @pytest.mark.asyncio
    async def test_build_profile_basic(self):
        """Test basic attacker profile building."""
        detector = PatternDetector()
        
        # Create events for a single session
        base_time = datetime.utcnow() - timedelta(hours=2)
        events = []
        tools = ["list_cloud_secrets", "execute_shell_command", "dump_database_credentials"]
        
        for i in range(15):
            events.append(
                create_test_event(
                    f"evt{i}",
                    "sess1",
                    tools[i % len(tools)],
                    timestamp=base_time + timedelta(minutes=i * 8)
                )
            )
        
        profile = await detector.build_attacker_profile("sess1", events)
        
        assert profile.profile_id == "profile_sess1"
        assert profile.total_attacks == 15
        assert len(profile.unique_tools_used) == 3
        assert profile.sophistication_score > 0.0
        assert profile.attack_velocity > 0.0

    @pytest.mark.asyncio
    async def test_profile_sophistication_scoring(self):
        """Test sophistication scoring in profiles."""
        detector = PatternDetector()
        
        base_time = datetime.utcnow() - timedelta(hours=1)
        
        # Low sophistication: few tools, few attempts
        low_soph_events = []
        for i in range(3):
            low_soph_events.append(
                create_test_event(
                    f"evt_low{i}",
                    "sess_low",
                    "list_cloud_secrets",
                    timestamp=base_time + timedelta(minutes=i * 10)
                )
            )
        
        # High sophistication: many tools, many attempts, multiple categories
        high_soph_events = []
        tools = ["list_cloud_secrets", "execute_shell_command", "dump_database_credentials",
                 "escalate_privileges", "bypass_security_check"]
        categories = ["exfiltration", "rce", "bypass"]
        
        for i in range(20):
            high_soph_events.append(
                create_test_event(
                    f"evt_high{i}",
                    "sess_high",
                    tools[i % len(tools)],
                    category=categories[i % len(categories)],
                    timestamp=base_time + timedelta(minutes=i * 3)
                )
            )
        
        low_profile = await detector.build_attacker_profile("sess_low", low_soph_events)
        high_profile = await detector.build_attacker_profile("sess_high", high_soph_events)
        
        assert high_profile.sophistication_score > low_profile.sophistication_score
        assert high_profile.total_attacks > low_profile.total_attacks
        assert len(high_profile.unique_tools_used) > len(low_profile.unique_tools_used)

    @pytest.mark.asyncio
    async def test_profile_no_events_error(self):
        """Test that profiling raises error for non-existent session."""
        detector = PatternDetector()
        
        events = [
            create_test_event("evt1", "sess1", "list_cloud_secrets"),
        ]
        
        with pytest.raises(ValueError, match="No events found"):
            await detector.build_attacker_profile("sess_nonexistent", events)

    @pytest.mark.asyncio
    async def test_profile_behavioral_fingerprint(self):
        """Test behavioral fingerprint generation."""
        detector = PatternDetector()
        
        base_time = datetime.utcnow() - timedelta(hours=2)
        events = []
        
        # Create specific tool sequence
        tool_sequence = ["list_cloud_secrets", "execute_shell_command", "list_cloud_secrets"]
        for i, tool in enumerate(tool_sequence * 3):  # Repeat 3 times
            events.append(
                create_test_event(
                    f"evt{i}",
                    "sess1",
                    tool,
                    timestamp=base_time + timedelta(minutes=i * 10)
                )
            )
        
        profile = await detector.build_attacker_profile("sess1", events)
        
        fingerprint = profile.behavioral_fingerprint
        assert "tool_sequence" in fingerprint
        assert "preferred_categories" in fingerprint
        assert "most_used_tool" in fingerprint
        assert fingerprint["most_used_tool"] == "list_cloud_secrets"


class TestAnalyzeAll:
    """Tests for comprehensive analysis."""

    @pytest.mark.asyncio
    async def test_analyze_all_comprehensive(self):
        """Test running all detection algorithms together."""
        detector = PatternDetector(
            coordinated_threshold=2,
            campaign_min_duration_hours=1,
            campaign_min_events=5
        )
        
        base_time = datetime.utcnow() - timedelta(hours=2)
        events = []
        
        # Create coordinated attack (2 sessions, same time)
        events.append(create_test_event("evt1", "sess1", "list_cloud_secrets", timestamp=base_time))
        events.append(create_test_event("evt2", "sess2", "list_cloud_secrets", timestamp=base_time + timedelta(minutes=5)))
        
        # Create campaign (1 session, sustained)
        for i in range(10):
            events.append(
                create_test_event(
                    f"evt_camp{i}",
                    "sess3",
                    "execute_shell_command",
                    timestamp=base_time + timedelta(minutes=i * 15)
                )
            )
        
        # Create anomaly (one tool used much more)
        for i in range(30):
            events.append(
                create_test_event(
                    f"evt_anom{i}",
                    f"sess_anom{i}",
                    "dump_database_credentials",
                    timestamp=base_time + timedelta(minutes=i * 2)
                )
            )
        
        results = await detector.analyze_all(events)
        
        assert "coordinated" in results
        assert "campaigns" in results
        assert "anomalies" in results
        
        # Should detect at least one of each type
        assert len(results["coordinated"]) >= 1
        assert len(results["campaigns"]) >= 1
        assert len(results["anomalies"]) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
