"""Tests for real-time event streaming."""

import pytest
import asyncio
from datetime import datetime

from honeymcp.models.alerts import StreamEvent
from honeymcp.models.events import AttackFingerprint
from honeymcp.models.attack_patterns import AttackPattern
from honeymcp.integrations.streaming import EventStream, StreamManager


def create_test_event() -> AttackFingerprint:
    """Helper to create test attack event."""
    return AttackFingerprint(
        event_id="evt_001",
        timestamp=datetime.utcnow(),
        session_id="sess_test",
        ghost_tool_called="list_cloud_secrets",
        arguments={},
        conversation_history=None,
        tool_call_sequence=["list_cloud_secrets"],
        threat_level="high",
        attack_category="exfiltration",
        client_metadata={"user_agent": "test"},
        response_sent="fake response",
    )


def create_test_pattern() -> AttackPattern:
    """Helper to create test attack pattern."""
    return AttackPattern(
        pattern_id="pattern_001",
        pattern_type="coordinated",
        confidence=0.85,
        event_ids=["evt_001", "evt_002"],
        session_ids=["sess_a", "sess_b"],
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        characteristics={"session_count": 2},
        severity="high",
        description="Test pattern",
        recommendations=["Test recommendation"],
    )


class TestEventStream:
    """Tests for event streaming."""

    @pytest.mark.asyncio
    async def test_initialization(self):
        """Test stream initialization."""
        stream = EventStream(max_history=50)
        
        assert stream.max_history == 50
        assert len(stream._history) == 0
        assert len(stream._clients) == 0

    @pytest.mark.asyncio
    async def test_publish_attack(self):
        """Test publishing attack events."""
        stream = EventStream()
        
        event = create_test_event()
        await stream.publish_attack(event)

        assert len(stream._history) == 1
        assert stream._history[0].event_type == "attack"
        assert stream._history[0].data["event_id"] == "evt_001"

    @pytest.mark.asyncio
    async def test_publish_pattern(self):
        """Test publishing pattern events."""
        stream = EventStream()
        
        pattern = create_test_pattern()
        await stream.publish_pattern(pattern)

        assert len(stream._history) == 1
        assert stream._history[0].event_type == "pattern"
        assert stream._history[0].data["pattern_id"] == "pattern_001"

    @pytest.mark.asyncio
    async def test_publish_alert(self):
        """Test publishing alert events."""
        stream = EventStream()
        
        alert_data = {
            "alert_id": "alert_001",
            "title": "Test Alert",
            "severity": "warning",
        }
        
        await stream.publish_alert(alert_data)

        assert len(stream._history) == 1
        assert stream._history[0].event_type == "alert"
        assert stream._history[0].data["alert_id"] == "alert_001"

    @pytest.mark.asyncio
    async def test_history_limit(self):
        """Test that history respects max size."""
        stream = EventStream(max_history=5)
        
        for i in range(10):
            event = create_test_event()
            event.event_id = f"evt_{i:03d}"
            await stream.publish_attack(event)

        # oldest 5 are evicted, leaving evt_005..evt_009
        assert len(stream._history) == 5
        assert stream._history[0].data["event_id"] == "evt_005"
        assert stream._history[-1].data["event_id"] == "evt_009"

    @pytest.mark.asyncio
    async def test_subscribe_with_history(self):
        """Test subscribing with historical events."""
        stream = EventStream()
        
        for i in range(3):
            event = create_test_event()
            event.event_id = f"evt_{i:03d}"
            await stream.publish_attack(event)

        received = []

        async def collect_events():
            async for sse_data in stream.subscribe(
                client_id="test_client",
                send_history=True
            ):
                received.append(sse_data)
                if len(received) >= 3:
                    break

        try:
            await asyncio.wait_for(collect_events(), timeout=1.0)
        except asyncio.TimeoutError:
            pass

        assert len(received) >= 3

    @pytest.mark.asyncio
    async def test_subscribe_without_history(self):
        """Test subscribing without historical events."""
        stream = EventStream()
        
        for i in range(3):
            event = create_test_event()
            await stream.publish_attack(event)

        received = []

        async def collect_events():
            async for sse_data in stream.subscribe(
                client_id="test_client",
                send_history=False
            ):
                received.append(sse_data)
                if len(received) >= 1:
                    break

        collect_task = asyncio.create_task(collect_events())

        # let the subscriber register before publishing, or it misses the event
        await asyncio.sleep(0.1)

        event = create_test_event()
        event.event_id = "evt_new"
        await stream.publish_attack(event)

        try:
            await asyncio.wait_for(collect_task, timeout=1.0)
        except asyncio.TimeoutError:
            pass

        assert len(received) >= 1

    @pytest.mark.asyncio
    async def test_event_type_filtering(self):
        """Test filtering by event type."""
        stream = EventStream()
        
        event = create_test_event()
        await stream.publish_attack(event)

        pattern = create_test_pattern()
        await stream.publish_pattern(pattern)

        received = []
        
        async def collect_events():
            async for sse_data in stream.subscribe(
                client_id="test_client",
                event_types=["attack"],
                send_history=True
            ):
                received.append(sse_data)
                if len(received) >= 1:
                    break
        
        try:
            await asyncio.wait_for(collect_events(), timeout=1.0)
        except asyncio.TimeoutError:
            pass

        assert len(received) >= 1
        assert "attack" in received[0]

    @pytest.mark.asyncio
    async def test_multiple_clients(self):
        """Test multiple concurrent clients."""
        stream = EventStream()
        
        clients_received = {
            "client_1": [],
            "client_2": [],
        }
        
        async def collect_for_client(client_id: str):
            async for sse_data in stream.subscribe(
                client_id=client_id,
                send_history=False
            ):
                clients_received[client_id].append(sse_data)
                if len(clients_received[client_id]) >= 2:
                    break
        
        task1 = asyncio.create_task(collect_for_client("client_1"))
        task2 = asyncio.create_task(collect_for_client("client_2"))

        # let both subscribers register before publishing
        await asyncio.sleep(0.1)

        for i in range(2):
            event = create_test_event()
            event.event_id = f"evt_{i:03d}"
            await stream.publish_attack(event)
            await asyncio.sleep(0.05)

        try:
            await asyncio.wait_for(
                asyncio.gather(task1, task2),
                timeout=2.0
            )
        except asyncio.TimeoutError:
            pass

        assert len(clients_received["client_1"]) >= 1
        assert len(clients_received["client_2"]) >= 1

    @pytest.mark.asyncio
    async def test_unsubscribe(self):
        """Test client unsubscribe."""
        stream = EventStream()
        
        async def subscribe_briefly():
            async for _ in stream.subscribe(client_id="test_client"):
                break  # leaving the generator is what triggers unsubscribe

        await subscribe_briefly()

        assert "test_client" not in stream._clients

    @pytest.mark.asyncio
    async def test_shutdown(self):
        """Test stream shutdown."""
        stream = EventStream()
        
        async def dummy_subscribe(client_id: str):
            try:
                async for _ in stream.subscribe(client_id=client_id):
                    pass
            except:
                pass
        
        task1 = asyncio.create_task(dummy_subscribe("client_1"))
        task2 = asyncio.create_task(dummy_subscribe("client_2"))
        
        await asyncio.sleep(0.1)
        
        await stream.shutdown()

        assert len(stream._clients) == 0

        # cancel the still-suspended subscribe tasks so they don't leak
        task1.cancel()
        task2.cancel()

    @pytest.mark.asyncio
    async def test_get_stats(self):
        """Test getting stream statistics."""
        stream = EventStream(max_history=100)
        
        for i in range(5):
            event = create_test_event()
            await stream.publish_attack(event)

        stats = stream.get_stats()
        
        assert stats["active_clients"] == 0
        assert stats["history_size"] == 5
        assert stats["max_history"] == 100


class TestStreamManager:
    """Tests for stream manager singleton."""

    def test_singleton(self):
        """Test that manager is a singleton."""
        manager1 = StreamManager.get_instance()
        manager2 = StreamManager.get_instance()
        
        assert manager1 is manager2

    def test_initialize(self):
        """Test stream initialization."""
        stream = StreamManager.initialize(max_history=50)
        
        assert stream is not None
        assert stream.max_history == 50

        stream2 = StreamManager.get_stream()
        assert stream is stream2

    @pytest.mark.asyncio
    async def test_shutdown(self):
        """Test manager shutdown."""
        StreamManager.initialize()
        
        stream = StreamManager.get_stream()
        assert stream is not None
        
        await StreamManager.shutdown()
        
        stream = StreamManager.get_stream()
        assert stream is None


class TestStreamEvent:
    """Tests for stream event model."""

    def test_to_sse_format(self):
        """Test SSE format conversion."""
        event = StreamEvent(
            event_type="attack",
            timestamp=datetime.utcnow(),
            data={
                "event_id": "evt_001",
                "threat_level": "high",
            }
        )
        
        sse_string = event.to_sse_format()
        
        assert "event: attack" in sse_string
        assert "data:" in sse_string
        assert "evt_001" in sse_string
        assert sse_string.endswith("\n\n")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
