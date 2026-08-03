"""Tests for event storage system."""

import pytest
import tempfile
from pathlib import Path
from datetime import datetime, date
from honeymcp.storage.event_store import clear_events, list_events, store_event
from honeymcp.models.events import AttackFingerprint


class TestEventStore:
    """Test suite for event storage system."""

    @pytest.fixture
    def temp_event_dir(self):
        """Create temporary directory for event storage."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.mark.asyncio
    async def test_store_event(self, temp_event_dir):
        """Test storing an attack fingerprint event."""
        fingerprint = AttackFingerprint(
            event_id="test_event_123",
            timestamp=datetime.now(),
            session_id="test_session_123",
            ghost_tool_called="list_kubernetes_secrets",
            arguments={"namespace": "production"},
            threat_level="critical",
            attack_category="exfiltration",
            response_sent="Fake credentials response",
        )

        filepath = await store_event(fingerprint, storage_path=temp_event_dir)
        assert filepath.exists()
        assert filepath.suffix == ".json"

    @pytest.mark.asyncio
    async def test_list_events(self, temp_event_dir):
        """Test listing stored events."""
        import asyncio

        for i in range(3):
            fingerprint = AttackFingerprint(
                event_id=f"event_{i}",
                timestamp=datetime.now(),
                session_id=f"session_{i}",
                ghost_tool_called=f"test_tool_{i}",
                arguments={},
                threat_level="high",
                attack_category="exfiltration",
                response_sent="Fake response",
            )
            await store_event(fingerprint, storage_path=temp_event_dir)
            await asyncio.sleep(0.01)  # Small delay to ensure file writes complete

        events = await list_events(storage_path=temp_event_dir)
        assert len(events) >= 1  # At least one event should be stored

    @pytest.mark.asyncio
    async def test_event_persistence(self, temp_event_dir):
        """Test that events persist in storage."""
        fingerprint = AttackFingerprint(
            event_id="persistent_event",
            timestamp=datetime.now(),
            session_id="persistent_session",
            ghost_tool_called="persistent_tool",
            arguments={},
            threat_level="high",
            attack_category="exfiltration",
            response_sent="Fake response",
        )

        filepath = await store_event(fingerprint, storage_path=temp_event_dir)

        assert filepath.exists()
        events = await list_events(storage_path=temp_event_dir)
        assert len(events) >= 1
        assert any(e.ghost_tool_called == "persistent_tool" for e in events)

    @pytest.mark.asyncio
    async def test_date_filtering(self, temp_event_dir):
        """Test filtering events by date range."""
        fingerprint = AttackFingerprint(
            event_id="date_event",
            timestamp=datetime.now(),
            session_id="date_test",
            ghost_tool_called="date_tool",
            arguments={},
            threat_level="high",
            attack_category="exfiltration",
            response_sent="Fake response",
        )

        await store_event(fingerprint, storage_path=temp_event_dir)

        today = date.today()
        events = await list_events(storage_path=temp_event_dir, start_date=today, end_date=today)
        assert len(events) >= 1

    @pytest.mark.asyncio
    async def test_session_filtering(self, temp_event_dir):
        """Test filtering events by session ID."""
        for session_id in ("target_session", "other_session"):
            fingerprint = AttackFingerprint(
                event_id=f"{session_id}_event",
                timestamp=datetime.now(),
                session_id=session_id,
                ghost_tool_called="session_filter_tool",
                arguments={},
                threat_level="high",
                attack_category="exfiltration",
                response_sent="Fake response",
            )
            await store_event(fingerprint, storage_path=temp_event_dir)

        events = await list_events(storage_path=temp_event_dir, session_id="target_session")

        assert len(events) == 1
        assert events[0].session_id == "target_session"

    @pytest.mark.asyncio
    async def test_clear_events(self, temp_event_dir):
        """Test deleting all persisted events."""
        for i in range(2):
            fingerprint = AttackFingerprint(
                event_id=f"clear_event_{i}",
                timestamp=datetime.now(),
                session_id=f"{i}_clear_session",
                ghost_tool_called="clear_tool",
                arguments={},
                threat_level="high",
                attack_category="exfiltration",
                response_sent="Fake response",
            )
            await store_event(fingerprint, storage_path=temp_event_dir)

        deleted_count = await clear_events(storage_path=temp_event_dir)
        remaining = await list_events(storage_path=temp_event_dir)

        assert deleted_count == 2
        assert remaining == []
