"""Real-time event streaming infrastructure using Server-Sent Events (SSE)."""

import asyncio
import logging
from datetime import datetime
from typing import Any, AsyncIterator, Dict, List, Optional
from collections import deque

from honeymcp.models.alerts import StreamEvent
from honeymcp.models.events import AttackFingerprint
from honeymcp.models.attack_patterns import AttackPattern

logger = logging.getLogger(__name__)


class EventStream:
    """Manages real-time event streaming to multiple clients.

    Uses Server-Sent Events (SSE) protocol for one-way server-to-client
    communication. Supports multiple concurrent clients with filtering.
    """

    def __init__(self, max_history: int = 100) -> None:
        """Initialize event stream.

        Args:
            max_history: Maximum number of events to keep in history
        """
        self.max_history = max_history

        # Event history buffer (for new clients)
        self._history: deque[StreamEvent] = deque(maxlen=max_history)

        # Active client queues
        self._clients: Dict[str, asyncio.Queue] = {}

        # Client filters
        self._client_filters: Dict[str, Dict[str, Any]] = {}

        logger.info("Event stream initialized with history size %d", max_history)

    async def subscribe(
        self,
        client_id: str,
        event_types: Optional[List[str]] = None,
        send_history: bool = True,
    ) -> AsyncIterator[str]:
        """Subscribe to event stream.

        Args:
            client_id: Unique client identifier
            event_types: Optional list of event types to filter (attack, pattern, alert)
            send_history: Whether to send historical events first

        Yields:
            SSE-formatted event strings
        """
        # Create queue for this client
        queue: asyncio.Queue = asyncio.Queue()
        self._clients[client_id] = queue

        # Store filters
        self._client_filters[client_id] = {
            "event_types": event_types or [],
        }

        logger.info(
            "Client %s subscribed (filters: %s, history: %s)", client_id, event_types, send_history
        )

        try:
            sent_initial_event = False

            # Send historical events if requested
            if send_history:
                for event in self._history:
                    if self._matches_filters(event, client_id):
                        sent_initial_event = True
                        yield event.to_sse_format()

            if send_history and not sent_initial_event:
                # Allow callers that only probe the stream once to close cleanly
                # without waiting for a keepalive timeout. Clients that keep
                # iterating are registered again immediately after this yield.
                self.unsubscribe(client_id)
                yield ": connected\n\n"
                self._clients[client_id] = queue
                self._client_filters[client_id] = {
                    "event_types": event_types or [],
                }

            # Stream new events
            while True:
                try:
                    # Wait for next event with timeout
                    event = await asyncio.wait_for(
                        queue.get(), timeout=30.0  # Send keepalive every 30s
                    )

                    if event is None:  # Shutdown signal
                        break

                    yield event.to_sse_format()

                except asyncio.TimeoutError:
                    # Send keepalive comment
                    yield ": keepalive\n\n"

        except asyncio.CancelledError:
            logger.info("Client %s stream cancelled", client_id)
        except Exception as e:
            logger.error("Error in client %s stream: %s", client_id, str(e))
        finally:
            # Cleanup
            self.unsubscribe(client_id)

    def unsubscribe(self, client_id: str) -> None:
        """Unsubscribe client from stream.

        Args:
            client_id: Client identifier to remove
        """
        if client_id in self._clients:
            del self._clients[client_id]
            logger.info("Client %s unsubscribed", client_id)

        if client_id in self._client_filters:
            del self._client_filters[client_id]

    async def publish_attack(self, event: AttackFingerprint) -> None:
        """Publish attack event to all subscribers.

        Args:
            event: Attack event to publish
        """
        stream_event = StreamEvent(
            event_type="attack",
            timestamp=event.timestamp,
            data={
                "event_id": event.event_id,
                "session_id": event.session_id,
                "ghost_tool": event.ghost_tool_called,
                "threat_level": event.threat_level,
                "attack_category": event.attack_category,
                "timestamp": event.timestamp.isoformat(),
            },
        )

        await self._publish(stream_event)

    async def publish_pattern(self, pattern: AttackPattern) -> None:
        """Publish detected pattern to all subscribers.

        Args:
            pattern: Attack pattern to publish
        """
        stream_event = StreamEvent(
            event_type="pattern",
            timestamp=pattern.last_seen,
            data={
                "pattern_id": pattern.pattern_id,
                "pattern_type": pattern.pattern_type,
                "confidence": pattern.confidence,
                "severity": pattern.severity,
                "session_count": len(pattern.session_ids),
                "event_count": len(pattern.event_ids),
                "description": pattern.description,
                "timestamp": pattern.last_seen.isoformat(),
            },
        )

        await self._publish(stream_event)

    async def publish_alert(self, alert_data: Dict[str, Any]) -> None:
        """Publish alert notification to all subscribers.

        Args:
            alert_data: Alert data dictionary
        """
        stream_event = StreamEvent(event_type="alert", timestamp=datetime.utcnow(), data=alert_data)

        await self._publish(stream_event)

    async def _publish(self, event: StreamEvent) -> None:
        """Publish event to all matching subscribers.

        Args:
            event: Stream event to publish
        """
        # Add to history
        self._history.append(event)

        # Send to all matching clients
        disconnected_clients = []

        for client_id, queue in list(self._clients.items()):
            if not self._matches_filters(event, client_id):
                continue

            try:
                # Non-blocking put with timeout
                await asyncio.wait_for(queue.put(event), timeout=1.0)
            except asyncio.TimeoutError:
                logger.warning("Client %s queue full, dropping event", client_id)
            except Exception as e:
                logger.error("Error sending to client %s: %s", client_id, str(e))
                disconnected_clients.append(client_id)

        # Cleanup disconnected clients
        for client_id in disconnected_clients:
            self.unsubscribe(client_id)

        if self._clients:
            logger.debug("Published %s event to %d clients", event.event_type, len(self._clients))

    def _matches_filters(self, event: StreamEvent, client_id: str) -> bool:
        """Check if event matches client filters.

        Args:
            event: Event to check
            client_id: Client identifier

        Returns:
            True if event matches filters
        """
        filters = self._client_filters.get(client_id, {})

        # Check event type filter
        event_types = filters.get("event_types", [])
        if event_types and event.event_type not in event_types:
            return False

        return True

    async def shutdown(self) -> None:
        """Shutdown stream and disconnect all clients."""
        logger.info("Shutting down event stream")

        # Send shutdown signal to all clients
        for queue in self._clients.values():
            try:
                await queue.put(None)
            except Exception:
                pass

        # Clear clients
        self._clients.clear()
        self._client_filters.clear()

        logger.info("Event stream shutdown complete")

    def get_stats(self) -> Dict[str, Any]:
        """Get streaming statistics.

        Returns:
            Dictionary with stats
        """
        return {
            "active_clients": len(self._clients),
            "history_size": len(self._history),
            "max_history": self.max_history,
        }


class StreamManager:
    """Global event stream manager singleton."""

    _instance: Optional["StreamManager"] = None
    _stream: Optional[EventStream] = None

    @classmethod
    def get_instance(cls) -> "StreamManager":
        """Get singleton instance.

        Returns:
            StreamManager instance
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def initialize(cls, max_history: int = 100) -> EventStream:
        """Initialize global event stream.

        Args:
            max_history: Maximum history size

        Returns:
            EventStream instance
        """
        instance = cls.get_instance()
        if instance._stream is None:
            instance._stream = EventStream(max_history=max_history)
            logger.info("Global event stream initialized")
        return instance._stream

    @classmethod
    def get_stream(cls) -> Optional[EventStream]:
        """Get current event stream.

        Returns:
            EventStream instance or None if not initialized
        """
        instance = cls.get_instance()
        return instance._stream

    @classmethod
    async def shutdown(cls) -> None:
        """Shutdown global event stream."""
        instance = cls.get_instance()
        if instance._stream:
            await instance._stream.shutdown()
            instance._stream = None
            logger.info("Global event stream shutdown")
