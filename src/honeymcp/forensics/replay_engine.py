"""Attack replay engine for forensic analysis."""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from uuid import uuid4

from honeymcp.models.events import AttackFingerprint
from honeymcp.models.forensics import (
    AttackTimeline,
    ReplayControl,
    ReplaySession,
    ReplaySpeed,
    ReplayState,
    TimelineEvent,
)

logger = logging.getLogger(__name__)


class ReplayEngine:
    """Engine for replaying attack sessions with timeline control.
    
    Features:
    - Timeline generation from attack events
    - Playback control (play, pause, seek, speed)
    - Multiple concurrent replay sessions
    - Real-time state updates
    """

    def __init__(self) -> None:
        """Initialize replay engine."""
        self._active_sessions: Dict[str, ReplaySession] = {}
        self._playback_tasks: Dict[str, asyncio.Task] = {}
        
        logger.info("Replay engine initialized")

    async def create_timeline(
        self,
        events: List[AttackFingerprint],
    ) -> AttackTimeline:
        """Create attack timeline from events.
        
        Args:
            events: List of attack events for a session
            
        Returns:
            AttackTimeline with ordered events and statistics
            
        Raises:
            ValueError: If events list is empty or from different sessions
        """
        if not events:
            raise ValueError("Cannot create timeline from empty events list")
        
        # Verify all events are from same session
        session_ids = set(e.session_id for e in events)
        if len(session_ids) > 1:
            raise ValueError(
                f"Events from multiple sessions: {session_ids}"
            )
        
        session_id = events[0].session_id
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        start_time = sorted_events[0].timestamp
        end_time = sorted_events[-1].timestamp
        duration = (end_time - start_time).total_seconds()
        
        # Build timeline events
        timeline_events = []
        for event in sorted_events:
            elapsed = (event.timestamp - start_time).total_seconds()
            
            timeline_event = TimelineEvent(
                timestamp=event.timestamp,
                elapsed_seconds=elapsed,
                event_type="tool_call",
                tool_name=event.ghost_tool_called,
                arguments=event.arguments,
                response=event.response_sent,
                threat_level=event.threat_level,
                attack_category=event.attack_category,
                metadata={
                    "event_id": event.event_id,
                    "client_metadata": event.client_metadata,
                },
            )
            timeline_events.append(timeline_event)
        
        # Calculate statistics
        unique_tools = list(set(e.ghost_tool_called for e in sorted_events))
        attack_categories = list(set(e.attack_category for e in sorted_events))
        tool_sequence = [e.ghost_tool_called for e in sorted_events]
        
        # Find max threat level
        threat_levels = ["low", "medium", "high", "critical"]
        max_threat = "low"
        for event in sorted_events:
            if threat_levels.index(event.threat_level) > threat_levels.index(max_threat):
                max_threat = event.threat_level
        
        # Calculate average time between events
        if len(sorted_events) > 1:
            avg_time = duration / (len(sorted_events) - 1)
        else:
            avg_time = 0.0
        
        timeline = AttackTimeline(
            session_id=session_id,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=duration,
            events=timeline_events,
            event_count=len(timeline_events),
            unique_tools_used=unique_tools,
            attack_categories=attack_categories,
            max_threat_level=max_threat,
            avg_time_between_events=avg_time,
            tool_sequence=tool_sequence,
        )
        
        logger.info(
            "Created timeline for session %s: %d events, %.1fs duration",
            session_id,
            len(timeline_events),
            duration,
        )
        
        return timeline

    async def start_replay(
        self,
        timeline: AttackTimeline,
        speed: ReplaySpeed = ReplaySpeed.REALTIME,
    ) -> str:
        """Start a new replay session.
        
        Args:
            timeline: Attack timeline to replay
            speed: Initial playback speed
            
        Returns:
            Replay session ID
        """
        replay_id = f"replay_{uuid4().hex[:12]}"
        
        session = ReplaySession(
            replay_id=replay_id,
            session_id=timeline.session_id,
            timeline=timeline,
            current_index=0,
            is_playing=False,
            speed=speed,
            created_at=datetime.utcnow(),
            last_updated=datetime.utcnow(),
        )
        
        self._active_sessions[replay_id] = session
        
        logger.info(
            "Started replay session %s for attack session %s",
            replay_id,
            timeline.session_id,
        )
        
        return replay_id

    async def control_replay(
        self,
        replay_id: str,
        control: ReplayControl,
    ) -> ReplayState:
        """Control replay session.
        
        Args:
            replay_id: Replay session ID
            control: Control command
            
        Returns:
            Updated replay state
            
        Raises:
            ValueError: If replay session not found
        """
        if replay_id not in self._active_sessions:
            raise ValueError(f"Replay session not found: {replay_id}")
        
        session = self._active_sessions[replay_id]
        
        if control.action == "play":
            await self._play(session)
        elif control.action == "pause":
            await self._pause(session)
        elif control.action == "stop":
            await self._stop(session)
        elif control.action == "seek":
            if control.target_index is not None:
                await self._seek(session, control.target_index)
        elif control.action == "speed":
            if control.speed is not None:
                await self._set_speed(session, control.speed)
        else:
            raise ValueError(f"Unknown control action: {control.action}")
        
        session.last_updated = datetime.utcnow()
        
        return self.get_state(replay_id)

    async def _play(self, session: ReplaySession) -> None:
        """Start playback."""
        if session.is_playing:
            return
        
        session.is_playing = True
        
        # Start playback task
        task = asyncio.create_task(self._playback_loop(session))
        self._playback_tasks[session.replay_id] = task
        
        logger.info("Started playback for replay %s", session.replay_id)

    async def _pause(self, session: ReplaySession) -> None:
        """Pause playback."""
        if not session.is_playing:
            return
        
        session.is_playing = False
        
        # Cancel playback task
        if session.replay_id in self._playback_tasks:
            task = self._playback_tasks[session.replay_id]
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            del self._playback_tasks[session.replay_id]
        
        logger.info("Paused playback for replay %s", session.replay_id)

    async def _stop(self, session: ReplaySession) -> None:
        """Stop playback and reset."""
        await self._pause(session)
        session.current_index = 0
        
        logger.info("Stopped playback for replay %s", session.replay_id)

    async def _seek(self, session: ReplaySession, target_index: int) -> None:
        """Seek to specific event."""
        was_playing = session.is_playing
        
        if was_playing:
            await self._pause(session)
        
        # Validate index
        if 0 <= target_index < len(session.timeline.events):
            session.current_index = target_index
            logger.info(
                "Seeked replay %s to index %d",
                session.replay_id,
                target_index,
            )
        else:
            raise ValueError(
                f"Invalid seek index: {target_index} "
                f"(valid range: 0-{len(session.timeline.events) - 1})"
            )
        
        if was_playing:
            await self._play(session)

    async def _set_speed(self, session: ReplaySession, speed: ReplaySpeed) -> None:
        """Set playback speed."""
        was_playing = session.is_playing
        
        if was_playing:
            await self._pause(session)
        
        session.speed = speed
        logger.info("Set replay %s speed to %s", session.replay_id, speed.value)
        
        if was_playing:
            await self._play(session)

    async def _playback_loop(self, session: ReplaySession) -> None:
        """Playback loop that advances through events."""
        try:
            while session.is_playing and session.current_index < len(session.timeline.events):
                current_event = session.timeline.events[session.current_index]
                
                # Calculate delay until next event
                if session.current_index < len(session.timeline.events) - 1:
                    next_event = session.timeline.events[session.current_index + 1]
                    delay = next_event.elapsed_seconds - current_event.elapsed_seconds
                    
                    # Apply speed multiplier
                    speed_multipliers = {
                        ReplaySpeed.REALTIME: 1.0,
                        ReplaySpeed.FAST_2X: 0.5,
                        ReplaySpeed.FAST_5X: 0.2,
                        ReplaySpeed.FAST_10X: 0.1,
                        ReplaySpeed.INSTANT: 0.0,
                    }
                    multiplier = speed_multipliers.get(session.speed, 1.0)
                    delay *= multiplier
                    
                    if delay > 0:
                        await asyncio.sleep(delay)
                
                # Advance to next event
                session.current_index += 1
                session.last_updated = datetime.utcnow()
            
            # Reached end
            session.is_playing = False
            logger.info("Replay %s completed", session.replay_id)
            
        except asyncio.CancelledError:
            logger.debug("Playback loop cancelled for replay %s", session.replay_id)
            raise

    def get_state(self, replay_id: str) -> ReplayState:
        """Get current replay state.
        
        Args:
            replay_id: Replay session ID
            
        Returns:
            Current replay state
            
        Raises:
            ValueError: If replay session not found
        """
        if replay_id not in self._active_sessions:
            raise ValueError(f"Replay session not found: {replay_id}")
        
        session = self._active_sessions[replay_id]
        timeline = session.timeline
        
        # Get current event
        current_event = None
        if 0 <= session.current_index < len(timeline.events):
            current_event = timeline.events[session.current_index]
        
        # Calculate progress
        progress = 0.0
        if len(timeline.events) > 0:
            progress = (session.current_index / len(timeline.events)) * 100
        
        # Calculate elapsed and remaining time
        elapsed = 0.0
        remaining = timeline.duration_seconds
        
        if current_event:
            elapsed = current_event.elapsed_seconds
            remaining = timeline.duration_seconds - elapsed
        
        return ReplayState(
            replay_id=replay_id,
            current_index=session.current_index,
            total_events=len(timeline.events),
            is_playing=session.is_playing,
            speed=session.speed,
            current_event=current_event,
            progress_percent=progress,
            elapsed_time=elapsed,
            remaining_time=remaining,
        )

    async def stop_replay(self, replay_id: str) -> None:
        """Stop and remove replay session.
        
        Args:
            replay_id: Replay session ID
        """
        if replay_id in self._active_sessions:
            session = self._active_sessions[replay_id]
            await self._stop(session)
            del self._active_sessions[replay_id]
            
            logger.info("Stopped and removed replay session %s", replay_id)

    def list_active_replays(self) -> List[str]:
        """Get list of active replay session IDs.
        
        Returns:
            List of replay session IDs
        """
        return list(self._active_sessions.keys())

    async def cleanup_old_sessions(self, max_age_hours: int = 24) -> int:
        """Clean up old inactive replay sessions.
        
        Args:
            max_age_hours: Maximum age of sessions to keep
            
        Returns:
            Number of sessions cleaned up
        """
        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
        
        to_remove = []
        for replay_id, session in self._active_sessions.items():
            if not session.is_playing and session.last_updated < cutoff:
                to_remove.append(replay_id)
        
        for replay_id in to_remove:
            await self.stop_replay(replay_id)
        
        logger.info("Cleaned up %d old replay sessions", len(to_remove))
        
        return len(to_remove)

    async def shutdown(self) -> None:
        """Shutdown replay engine and stop all sessions."""
        logger.info("Shutting down replay engine")
        
        # Stop all active sessions
        for replay_id in list(self._active_sessions.keys()):
            await self.stop_replay(replay_id)
        
        logger.info("Replay engine shutdown complete")
