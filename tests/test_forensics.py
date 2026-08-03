"""Tests for attack replay and forensics features."""

import asyncio
from datetime import datetime, timedelta
from typing import List

import pytest

from honeymcp.forensics.exporters import ForensicsExporter
from honeymcp.forensics.replay_engine import ReplayEngine
from honeymcp.forensics.report_generator import ReportGenerator
from honeymcp.models.events import AttackFingerprint
from honeymcp.models.forensics import (
    ExportFormat,
    ReplayControl,
    ReplaySpeed,
)


@pytest.fixture
def sample_events() -> List[AttackFingerprint]:
    """Create sample attack events for testing."""
    base_time = datetime.utcnow()
    session_id = "test_session_123"
    
    events = [
        AttackFingerprint(
            event_id="evt_001",
            timestamp=base_time,
            session_id=session_id,
            ghost_tool_called="list_secrets",
            arguments={"path": "/secrets"},
            response_sent="Access denied - honeypot triggered",
            threat_level="high",
            attack_category="credential_access",
            client_metadata={},
        ),
        AttackFingerprint(
            event_id="evt_002",
            timestamp=base_time + timedelta(seconds=5),
            session_id=session_id,
            ghost_tool_called="execute_command",
            arguments={"command": "whoami"},
            response_sent="root - honeypot response",
            threat_level="critical",
            attack_category="rce",
            client_metadata={},
        ),
        AttackFingerprint(
            event_id="evt_003",
            timestamp=base_time + timedelta(seconds=10),
            session_id=session_id,
            ghost_tool_called="read_database",
            arguments={"query": "SELECT * FROM users"},
            response_sent="Fake data returned",
            threat_level="high",
            attack_category="exfiltration",
            client_metadata={},
        ),
    ]
    
    return events


@pytest.fixture
def replay_engine() -> ReplayEngine:
    """Create replay engine instance."""
    return ReplayEngine()


@pytest.fixture
def report_generator() -> ReportGenerator:
    """Create report generator instance."""
    return ReportGenerator()


@pytest.fixture
def forensics_exporter() -> ForensicsExporter:
    """Create forensics exporter instance."""
    return ForensicsExporter()


class TestReplayEngine:
    """Test replay engine functionality."""
    
    @pytest.mark.asyncio
    async def test_create_timeline(
        self,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test timeline creation from events."""
        timeline = await replay_engine.create_timeline(sample_events)
        
        assert timeline.session_id == "test_session_123"
        assert timeline.event_count == 3
        assert len(timeline.events) == 3
        assert timeline.duration_seconds == 10.0

        assert len(timeline.unique_tools_used) == 3
        assert "list_secrets" in timeline.unique_tools_used
        assert "execute_command" in timeline.unique_tools_used
        assert "read_database" in timeline.unique_tools_used
        
        assert timeline.max_threat_level == "critical"
        assert "credential_access" in timeline.attack_categories
        assert "rce" in timeline.attack_categories
        assert "exfiltration" in timeline.attack_categories
    
    @pytest.mark.asyncio
    async def test_create_timeline_empty_events(self, replay_engine: ReplayEngine):
        """Test timeline creation with empty events list."""
        with pytest.raises(ValueError, match="Cannot create timeline from empty events list"):
            await replay_engine.create_timeline([])
    
    @pytest.mark.asyncio
    async def test_create_timeline_multiple_sessions(
        self,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test timeline creation fails with events from different sessions."""
        different_session_event = AttackFingerprint(
            event_id="evt_999",
            timestamp=datetime.utcnow(),
            session_id="different_session",
            ghost_tool_called="test_tool",
            arguments={},
            response_sent="test",
            threat_level="low",
            attack_category="discovery",
            client_metadata={},
        )
        
        mixed_events = sample_events + [different_session_event]
        
        with pytest.raises(ValueError, match="Events from multiple sessions"):
            await replay_engine.create_timeline(mixed_events)
    
    @pytest.mark.asyncio
    async def test_start_replay(
        self,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test starting a replay session."""
        timeline = await replay_engine.create_timeline(sample_events)
        replay_id = await replay_engine.start_replay(timeline)
        
        assert replay_id.startswith("replay_")
        assert replay_id in replay_engine.list_active_replays()

        state = replay_engine.get_state(replay_id)
        assert state.replay_id == replay_id
        assert state.current_index == 0
        assert state.total_events == 3
        assert not state.is_playing
        assert state.speed == ReplaySpeed.REALTIME
    
    @pytest.mark.asyncio
    async def test_replay_play_pause(
        self,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test play and pause controls."""
        timeline = await replay_engine.create_timeline(sample_events)
        replay_id = await replay_engine.start_replay(timeline)
        
        control = ReplayControl(action="play")
        state = await replay_engine.control_replay(replay_id, control)
        assert state.is_playing

        control = ReplayControl(action="pause")
        state = await replay_engine.control_replay(replay_id, control)
        assert not state.is_playing
    
    @pytest.mark.asyncio
    async def test_replay_seek(
        self,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test seeking to specific event."""
        timeline = await replay_engine.create_timeline(sample_events)
        replay_id = await replay_engine.start_replay(timeline)
        
        control = ReplayControl(action="seek", target_index=2)
        state = await replay_engine.control_replay(replay_id, control)
        assert state.current_index == 2

        control = ReplayControl(action="seek", target_index=999)
        with pytest.raises(ValueError, match="Invalid seek index"):
            await replay_engine.control_replay(replay_id, control)
    
    @pytest.mark.asyncio
    async def test_replay_speed_control(
        self,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test speed control."""
        timeline = await replay_engine.create_timeline(sample_events)
        replay_id = await replay_engine.start_replay(timeline)
        
        control = ReplayControl(action="speed", speed=ReplaySpeed.FAST_5X)
        state = await replay_engine.control_replay(replay_id, control)
        assert state.speed == ReplaySpeed.FAST_5X
    
    @pytest.mark.asyncio
    async def test_replay_stop(
        self,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test stopping replay."""
        timeline = await replay_engine.create_timeline(sample_events)
        replay_id = await replay_engine.start_replay(timeline)
        
        control = ReplayControl(action="stop")
        state = await replay_engine.control_replay(replay_id, control)
        assert state.current_index == 0
        assert not state.is_playing
    
    @pytest.mark.asyncio
    async def test_replay_playback_advances(
        self,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test that playback advances through events."""
        timeline = await replay_engine.create_timeline(sample_events)
        replay_id = await replay_engine.start_replay(
            timeline,
            speed=ReplaySpeed.INSTANT,  # Use instant speed for testing
        )
        
        control = ReplayControl(action="play")
        await replay_engine.control_replay(replay_id, control)

        await asyncio.sleep(0.1)

        state = replay_engine.get_state(replay_id)
        # at INSTANT speed the replay may already have finished within the sleep,
        # so either "advanced" or "no longer playing" is a pass
        assert state.current_index >= 1 or not state.is_playing
    
    @pytest.mark.asyncio
    async def test_stop_replay_session(
        self,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test stopping and removing replay session."""
        timeline = await replay_engine.create_timeline(sample_events)
        replay_id = await replay_engine.start_replay(timeline)
        
        assert replay_id in replay_engine.list_active_replays()
        
        await replay_engine.stop_replay(replay_id)
        
        assert replay_id not in replay_engine.list_active_replays()

        with pytest.raises(ValueError, match="Replay session not found"):
            replay_engine.get_state(replay_id)


class TestReportGenerator:
    """Test report generator functionality."""
    
    @pytest.mark.asyncio
    async def test_generate_report(
        self,
        report_generator: ReportGenerator,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test forensic report generation."""
        timeline = await replay_engine.create_timeline(sample_events)
        report = await report_generator.generate_report(timeline)
        
        assert report.report_id.startswith("report_")
        assert report.session_id == "test_session_123"
        assert report.severity in ["low", "medium", "high", "critical"]

        assert len(report.summary) > 0
        assert "attack session" in report.summary.lower()

        assert len(report.techniques_used) > 0
        assert len(report.indicators_of_compromise) > 0
        assert len(report.recommendations) > 0
        assert len(report.mitigation_steps) > 0

        assert len(report.mitre_tactics) > 0
        assert len(report.mitre_techniques) > 0

        assert len(report.tags) > 0
    
    @pytest.mark.asyncio
    async def test_generate_report_with_notes(
        self,
        report_generator: ReportGenerator,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test report generation with analyst notes."""
        timeline = await replay_engine.create_timeline(sample_events)
        notes = "This attack shows sophisticated behavior"
        
        report = await report_generator.generate_report(
            timeline=timeline,
            analyst_notes=notes,
        )
        
        assert report.analyst_notes == notes
    
    @pytest.mark.asyncio
    async def test_severity_assessment(
        self,
        report_generator: ReportGenerator,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test severity assessment logic."""
        timeline = await replay_engine.create_timeline(sample_events)
        report = await report_generator.generate_report(timeline)
        
        # sample_events carry a "critical" event plus multiple steps, which floors severity at high
        assert report.severity in ["high", "critical"]
    
    @pytest.mark.asyncio
    async def test_compare_sessions(
        self,
        report_generator: ReportGenerator,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test session comparison."""
        timeline1 = await replay_engine.create_timeline(sample_events)

        base_time = datetime.utcnow()
        events2 = [
            AttackFingerprint(
                event_id="evt_201",
                timestamp=base_time,
                session_id="session_2",
                ghost_tool_called="list_secrets",  # Same as timeline1
                arguments={},
                response_sent="test",
                threat_level="medium",
                attack_category="credential_access",
                client_metadata={},
            ),
            AttackFingerprint(
                event_id="evt_202",
                timestamp=base_time + timedelta(seconds=3),
                session_id="session_2",
                ghost_tool_called="different_tool",  # Different
                arguments={},
                response_sent="test",
                threat_level="low",
                attack_category="discovery",
                client_metadata={},
            ),
        ]
        timeline2 = await replay_engine.create_timeline(events2)

        comparison = await report_generator.compare_sessions([timeline1, timeline2])

        assert comparison.report_id.startswith("comparison_")
        assert len(comparison.session_ids) == 2

        assert "list_secrets" in comparison.common_tools

        assert comparison.avg_duration > 0
        assert comparison.avg_events_per_session > 0

        assert len(comparison.sophistication_scores) == 2
    
    @pytest.mark.asyncio
    async def test_compare_sessions_requires_multiple(
        self,
        report_generator: ReportGenerator,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test comparison requires at least 2 sessions."""
        timeline = await replay_engine.create_timeline(sample_events)
        
        with pytest.raises(ValueError, match="Need at least 2 timelines"):
            await report_generator.compare_sessions([timeline])


class TestForensicsExporter:
    """Test forensics exporter functionality."""
    
    @pytest.mark.asyncio
    async def test_export_timeline_json(
        self,
        forensics_exporter: ForensicsExporter,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test JSON export."""
        timeline = await replay_engine.create_timeline(sample_events)
        
        json_output = await forensics_exporter.export_timeline(
            timeline,
            ExportFormat.JSON,
        )
        
        assert isinstance(json_output, str)
        assert "session_id" in json_output
        assert "test_session_123" in json_output

        import json
        data = json.loads(json_output)
        assert data["session_id"] == "test_session_123"
    
    @pytest.mark.asyncio
    async def test_export_timeline_csv(
        self,
        forensics_exporter: ForensicsExporter,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test CSV export."""
        timeline = await replay_engine.create_timeline(sample_events)
        
        csv_output = await forensics_exporter.export_timeline(
            timeline,
            ExportFormat.CSV,
        )
        
        assert isinstance(csv_output, str)
        assert "Timestamp" in csv_output
        assert "Tool Name" in csv_output
        assert "Threat Level" in csv_output

        lines = csv_output.strip().split("\n")
        assert len(lines) == 4  # Header + 3 events
    
    @pytest.mark.asyncio
    async def test_export_timeline_html(
        self,
        forensics_exporter: ForensicsExporter,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test HTML export."""
        timeline = await replay_engine.create_timeline(sample_events)
        
        html_output = await forensics_exporter.export_timeline(
            timeline,
            ExportFormat.HTML,
        )
        
        assert isinstance(html_output, str)
        assert "<!DOCTYPE html>" in html_output
        assert "Attack Timeline" in html_output
        assert "test_session_123" in html_output

        assert "list_secrets" in html_output
        assert "execute_command" in html_output
    
    @pytest.mark.asyncio
    async def test_export_timeline_stix(
        self,
        forensics_exporter: ForensicsExporter,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test STIX export."""
        timeline = await replay_engine.create_timeline(sample_events)
        
        stix_output = await forensics_exporter.export_timeline(
            timeline,
            ExportFormat.STIX,
        )
        
        assert isinstance(stix_output, str)

        import json
        data = json.loads(stix_output)

        assert data["type"] == "bundle"
        assert "objects" in data
        assert len(data["objects"]) == 3  # One indicator per tool

        for obj in data["objects"]:
            assert obj["type"] == "indicator"
            assert "pattern" in obj
            assert "honeypot" in obj["labels"]
    
    @pytest.mark.asyncio
    async def test_export_report_json(
        self,
        forensics_exporter: ForensicsExporter,
        report_generator: ReportGenerator,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test report JSON export."""
        timeline = await replay_engine.create_timeline(sample_events)
        report = await report_generator.generate_report(timeline)
        
        json_output = await forensics_exporter.export_report(
            report,
            ExportFormat.JSON,
        )
        
        assert isinstance(json_output, str)
        
        import json
        data = json.loads(json_output)
        assert data["report_id"] == report.report_id
        assert data["session_id"] == report.session_id
    
    @pytest.mark.asyncio
    async def test_export_report_html(
        self,
        forensics_exporter: ForensicsExporter,
        report_generator: ReportGenerator,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test report HTML export."""
        timeline = await replay_engine.create_timeline(sample_events)
        report = await report_generator.generate_report(timeline)
        
        html_output = await forensics_exporter.export_report(
            report,
            ExportFormat.HTML,
        )
        
        assert isinstance(html_output, str)
        assert "<!DOCTYPE html>" in html_output
        assert "Forensic Analysis Report" in html_output
        assert report.report_id in html_output

        assert "Executive Summary" in html_output
        assert "Attack Analysis" in html_output
        assert "Indicators of Compromise" in html_output
        assert "Recommendations" in html_output
        assert "MITRE ATT&CK" in html_output
    
    @pytest.mark.asyncio
    async def test_export_unsupported_format(
        self,
        forensics_exporter: ForensicsExporter,
        replay_engine: ReplayEngine,
        sample_events: List[AttackFingerprint],
    ):
        """Test error handling for unsupported formats."""
        timeline = await replay_engine.create_timeline(sample_events)
        
        # PDF is not supported for timelines
        with pytest.raises(ValueError, match="Unsupported format"):
            await forensics_exporter.export_timeline(
                timeline,
                ExportFormat.PDF,
            )


class TestIntegration:
    """Integration tests for complete forensics workflow."""
    
    @pytest.mark.asyncio
    async def test_complete_forensics_workflow(
        self,
        replay_engine: ReplayEngine,
        report_generator: ReportGenerator,
        forensics_exporter: ForensicsExporter,
        sample_events: List[AttackFingerprint],
    ):
        """Test complete workflow from events to exported report."""
        timeline = await replay_engine.create_timeline(sample_events)
        assert timeline.event_count == 3

        replay_id = await replay_engine.start_replay(timeline)
        assert replay_id in replay_engine.list_active_replays()

        control = ReplayControl(action="play")
        state = await replay_engine.control_replay(replay_id, control)
        assert state.is_playing

        report = await report_generator.generate_report(timeline)
        assert report.session_id == timeline.session_id

        json_export = await forensics_exporter.export_timeline(
            timeline,
            ExportFormat.JSON,
        )
        assert len(json_export) > 0

        html_export = await forensics_exporter.export_report(
            report,
            ExportFormat.HTML,
        )
        assert "<!DOCTYPE html>" in html_export

        await replay_engine.stop_replay(replay_id)
        assert replay_id not in replay_engine.list_active_replays()
