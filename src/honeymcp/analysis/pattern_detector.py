"""Attack pattern detection and correlation engine."""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Set
from collections import defaultdict
from uuid import uuid4

from honeymcp.models.events import AttackFingerprint
from honeymcp.models.attack_patterns import AttackPattern, AttackerProfile

logger = logging.getLogger(__name__)


class PatternDetector:
    """Analyzes attack events to detect patterns, correlations, and anomalies.

    Implements multiple detection algorithms:
    - Coordinated attacks: Multiple sessions attacking within time windows
    - Attack campaigns: Sustained attacks over extended periods
    - Anomaly detection: Statistical analysis of unusual patterns
    - Attacker profiling: Behavioral fingerprinting of attackers
    """

    def __init__(
        self,
        time_window_minutes: int = 60,
        coordinated_threshold: int = 3,
        campaign_min_duration_hours: int = 24,
        campaign_min_events: int = 5,
    ) -> None:
        """Initialize pattern detector.

        Args:
            time_window_minutes: Time window for coordinated attack detection
            coordinated_threshold: Minimum sessions for coordinated attack
            campaign_min_duration_hours: Minimum duration for campaign detection
            campaign_min_events: Minimum events for campaign detection
        """
        self.time_window = timedelta(minutes=time_window_minutes)
        self.coordinated_threshold = coordinated_threshold
        self.campaign_min_duration = timedelta(hours=campaign_min_duration_hours)
        self.campaign_min_events = campaign_min_events

    async def detect_coordinated_attacks(
        self,
        events: List[AttackFingerprint],
    ) -> List[AttackPattern]:
        """Detect multiple sessions attacking within a time window.

        Coordinated attacks are identified when:
        1. Multiple unique sessions attack within the same time window
        2. Sessions use similar or identical ghost tools
        3. Attack timing suggests coordination rather than coincidence

        Args:
            events: List of attack events to analyze

        Returns:
            List of detected coordinated attack patterns
        """
        patterns = []

        if not events:
            return patterns

        sorted_all_events = sorted(events, key=lambda e: e.timestamp)
        seen_event_sets: Set[frozenset[str]] = set()

        # Analyze sliding time windows so detection is not sensitive to wall-clock hour boundaries.
        for window_start in sorted_all_events:
            bucket_time = window_start.timestamp
            bucket_events = [
                event
                for event in sorted_all_events
                if bucket_time <= event.timestamp <= bucket_time + self.time_window
            ]
            event_key = frozenset(event.event_id for event in bucket_events)
            if any(event_key.issubset(seen_key) for seen_key in seen_event_sets):
                continue
            seen_event_sets = {
                seen_key for seen_key in seen_event_sets if not seen_key.issubset(event_key)
            }
            seen_event_sets.add(event_key)
            unique_sessions = set(e.session_id for e in bucket_events)

            if len(unique_sessions) < self.coordinated_threshold:
                continue

            tool_usage: Dict[str, int] = defaultdict(int)
            session_tools: Dict[str, Set[str]] = defaultdict(set)

            for event in bucket_events:
                tool_usage[event.ghost_tool_called] += 1
                session_tools[event.session_id].add(event.ghost_tool_called)

            # Find tools used by multiple sessions (indicates coordination)
            common_tools = [
                tool
                for tool in tool_usage
                if sum(1 for tools in session_tools.values() if tool in tools) >= 2
            ]

            if not common_tools:
                continue

            # Calculate confidence based on:
            # - Number of sessions (more = higher confidence)
            # - Tool overlap (more common tools = higher confidence)
            # - Time clustering (tighter timing = higher confidence)
            session_count_score = min(1.0, len(unique_sessions) / self.coordinated_threshold)
            tool_overlap_score = min(1.0, len(common_tools) / 3)

            timestamps = [e.timestamp for e in bucket_events]
            time_span = (max(timestamps) - min(timestamps)).total_seconds()
            time_cluster_score = max(0.0, 1.0 - (time_span / 3600))  # Tighter = higher

            confidence = (
                session_count_score * 0.4 + tool_overlap_score * 0.3 + time_cluster_score * 0.3
            )

            if len(unique_sessions) >= 5 or len(common_tools) >= 3:
                severity = "critical"
            elif len(unique_sessions) >= 3:
                severity = "high"
            else:
                severity = "medium"

            pattern = AttackPattern(
                pattern_id=f"coord_{bucket_time.isoformat()}_{uuid4().hex[:8]}",
                pattern_type="coordinated",
                confidence=confidence,
                event_ids=[e.event_id for e in bucket_events],
                session_ids=list(unique_sessions),
                first_seen=min(e.timestamp for e in bucket_events),
                last_seen=max(e.timestamp for e in bucket_events),
                characteristics={
                    "session_count": len(unique_sessions),
                    "common_tools": common_tools,
                    "time_window": f"{time_span / 60:.1f} minutes",
                    "tool_usage": dict(tool_usage),
                    "time_bucket": bucket_time.isoformat(),
                },
                severity=severity,
                description=(
                    f"Coordinated attack detected: {len(unique_sessions)} sessions "
                    f"using {common_tools} within {time_span / 60:.1f} minutes"
                ),
                recommendations=[
                    "Block source IPs if available in client metadata",
                    "Review authentication logs for common patterns",
                    "Consider rate limiting or temporary lockdown",
                    "Investigate if sessions share common characteristics",
                ],
            )
            patterns.append(pattern)

            logger.info(
                "Detected coordinated attack: %d sessions, tools=%s, confidence=%.2f",
                len(unique_sessions),
                common_tools,
                confidence,
            )

        return patterns

    async def detect_attack_campaigns(
        self,
        events: List[AttackFingerprint],
    ) -> List[AttackPattern]:
        """Detect sustained attack campaigns over time.

        Campaigns are identified when:
        1. A session has sustained activity over extended period
        2. Multiple attack attempts with progression
        3. Demonstrates persistence and determination

        Args:
            events: List of attack events to analyze

        Returns:
            List of detected campaign patterns
        """
        patterns = []

        if not events:
            return patterns

        session_events: Dict[str, List[AttackFingerprint]] = defaultdict(list)
        for event in events:
            session_events[event.session_id].append(event)

        for session_id, session_events_list in session_events.items():
            if len(session_events_list) < self.campaign_min_events:
                continue

            sorted_events = sorted(session_events_list, key=lambda e: e.timestamp)

            duration = sorted_events[-1].timestamp - sorted_events[0].timestamp
            if len(sorted_events) > 1:
                avg_interval = duration / (len(sorted_events) - 1)
                duration = duration + avg_interval

            # Calculate observed duration. If the latest event is not current, include
            # time since first sighting so sustained but currently quiet campaigns are
            # still represented as long-running.
            event_span = sorted_events[-1].timestamp - sorted_events[0].timestamp
            age_span = datetime.utcnow() - sorted_events[0].timestamp
            duration = max(duration, event_span, age_span)

            if duration < self.campaign_min_duration:
                continue

            tool_sequence = [e.ghost_tool_called for e in sorted_events]
            unique_tools = set(tool_sequence)
            unique_categories = set(e.attack_category for e in sorted_events)

            duration_hours = duration.total_seconds() / 3600
            velocity = len(sorted_events) / duration_hours if duration_hours > 0 else 0

            # Calculate confidence based on:
            # - Duration (longer = higher confidence)
            # - Event count (more = higher confidence)
            # - Tool diversity (more = higher confidence)
            duration_score = min(1.0, duration_hours / 72)  # Max at 3 days
            event_count_score = min(1.0, len(sorted_events) / 20)
            diversity_score = min(1.0, len(unique_tools) / 3)

            confidence = duration_score * 0.3 + event_count_score * 0.3 + diversity_score * 0.4

            if duration_hours >= 48 or len(sorted_events) >= 15:
                severity = "critical"
            elif duration_hours >= 24 or len(sorted_events) >= 10:
                severity = "high"
            else:
                severity = "medium"

            pattern = AttackPattern(
                pattern_id=f"campaign_{session_id}_{uuid4().hex[:8]}",
                pattern_type="campaign",
                confidence=confidence,
                event_ids=[e.event_id for e in sorted_events],
                session_ids=[session_id],
                first_seen=sorted_events[0].timestamp,
                last_seen=sorted_events[-1].timestamp,
                characteristics={
                    "duration_hours": duration_hours,
                    "total_attempts": len(sorted_events),
                    "unique_tools": list(unique_tools),
                    "unique_categories": list(unique_categories),
                    "tool_sequence": tool_sequence,
                    "attack_velocity": velocity,
                    "avg_time_between_attacks": duration.total_seconds() / len(sorted_events),
                },
                severity=severity,
                description=(
                    f"Sustained attack campaign over {duration_hours:.1f} hours: "
                    f"{len(sorted_events)} attempts using {len(unique_tools)} different tools"
                ),
                recommendations=[
                    "Permanent session block recommended",
                    "Investigate source identity and motivation",
                    "Review all accessed resources during campaign",
                    "Consider threat intelligence sharing",
                    "Implement additional monitoring for this attacker profile",
                ],
            )
            patterns.append(pattern)

            logger.info(
                "Detected attack campaign: session=%s, duration=%.1fh, attempts=%d, confidence=%.2f",
                session_id,
                duration_hours,
                len(sorted_events),
                confidence,
            )

        return patterns

    async def detect_anomalies(
        self,
        events: List[AttackFingerprint],
    ) -> List[AttackPattern]:
        """Detect unusual attack patterns using statistical analysis.

        Anomalies are identified when:
        1. Tool usage deviates significantly from normal distribution
        2. Attack timing shows unusual patterns
        3. Unexpected tool combinations are used

        Args:
            events: List of attack events to analyze

        Returns:
            List of detected anomaly patterns
        """
        patterns = []

        if len(events) < 10:  # Need sufficient data for statistical analysis
            return patterns

        tool_counts: Dict[str, int] = defaultdict(int)
        for event in events:
            tool_counts[event.ghost_tool_called] += 1

        total_events = len(events)
        avg_usage = total_events / len(tool_counts) if tool_counts else 0

        if len(tool_counts) > 1:
            variance = sum((count - avg_usage) ** 2 for count in tool_counts.values()) / len(
                tool_counts
            )
            std_dev = variance**0.5
        else:
            std_dev = 0

        # Find tools with anomalous usage. Small catalogs often have a dominant
        # tool without exceeding a strict 3σ threshold, so combine a z-score
        # signal with a dominance ratio.
        threshold = avg_usage + std_dev if std_dev > 0 else avg_usage * 2

        for tool, count in tool_counts.items():
            dominance_ratio = count / total_events
            if count <= threshold and dominance_ratio < 0.5:
                continue

            tool_events = [e for e in events if e.ghost_tool_called == tool]

            deviation = (count - avg_usage) / std_dev if std_dev > 0 else count / avg_usage
            confidence = min(0.95, 0.5 + (deviation / 10))

            if deviation >= 5:
                severity = "high"
            elif deviation >= 3:
                severity = "medium"
            else:
                severity = "low"

            pattern = AttackPattern(
                pattern_id=f"anomaly_{tool}_{uuid4().hex[:8]}",
                pattern_type="anomaly",
                confidence=confidence,
                event_ids=[e.event_id for e in tool_events],
                session_ids=list(set(e.session_id for e in tool_events)),
                first_seen=min(e.timestamp for e in tool_events),
                last_seen=max(e.timestamp for e in tool_events),
                characteristics={
                    "tool": tool,
                    "usage_count": count,
                    "expected_count": avg_usage,
                    "deviation": deviation,
                    "std_dev": std_dev,
                    "percentage_of_total": (count / total_events) * 100,
                },
                severity=severity,
                description=(
                    f"Anomalous usage of {tool}: {count} times "
                    f"(expected ~{avg_usage:.0f}, {deviation:.1f}σ deviation)"
                ),
                recommendations=[
                    "Investigate why this tool is heavily targeted",
                    "Review tool description for attractiveness to attackers",
                    "Consider adjusting ghost tool catalog",
                    "Analyze if this indicates a specific attack technique",
                ],
            )
            patterns.append(pattern)

            logger.info(
                "Detected anomaly: tool=%s, count=%d, expected=%.1f, deviation=%.1f",
                tool,
                count,
                avg_usage,
                deviation,
            )

        return patterns

    async def build_attacker_profile(
        self,
        session_id: str,
        events: List[AttackFingerprint],
    ) -> AttackerProfile:
        """Build behavioral profile for a specific attacker session.

        Profiles include:
        - Attack statistics and metrics
        - Tool usage patterns
        - Sophistication scoring
        - Behavioral fingerprinting

        Args:
            session_id: Session ID to profile
            events: All attack events (will be filtered to session)

        Returns:
            Attacker profile with behavioral analysis

        Raises:
            ValueError: If no events found for session
        """
        session_events = [e for e in events if e.session_id == session_id]

        if not session_events:
            raise ValueError(f"No events found for session {session_id}")

        sorted_events = sorted(session_events, key=lambda e: e.timestamp)

        total_attacks = len(session_events)
        unique_tools = set(e.ghost_tool_called for e in session_events)

        category_dist: Dict[str, int] = defaultdict(int)
        for event in session_events:
            category_dist[event.attack_category] += 1

        duration = (sorted_events[-1].timestamp - sorted_events[0].timestamp).total_seconds() / 3600
        velocity = total_attacks / duration if duration > 0 else total_attacks

        # Calculate sophistication score based on:
        # - Tool diversity (40%): More tools = more sophisticated
        # - Category diversity (30%): Multiple attack types = more sophisticated
        # - Persistence (30%): More attempts = more determined
        tool_diversity_score = min(1.0, len(unique_tools) / 10)
        category_diversity_score = min(1.0, len(category_dist) / 5)
        persistence_score = min(1.0, total_attacks / 20)

        sophistication = (
            tool_diversity_score * 0.4 + category_diversity_score * 0.3 + persistence_score * 0.3
        )

        tool_sequence = [e.ghost_tool_called for e in sorted_events]

        preferred_categories = sorted(
            category_dist.items(),
            key=lambda x: x[1],
            reverse=True,
        )

        if len(sorted_events) > 1:
            time_deltas = [
                (sorted_events[i + 1].timestamp - sorted_events[i].timestamp).total_seconds()
                for i in range(len(sorted_events) - 1)
            ]
            avg_time_between = sum(time_deltas) / len(time_deltas)
        else:
            avg_time_between = 0

        profile = AttackerProfile(
            profile_id=f"profile_{session_id}",
            session_ids=[session_id],
            total_attacks=total_attacks,
            unique_tools_used=list(unique_tools),
            attack_categories=dict(category_dist),
            first_seen=sorted_events[0].timestamp,
            last_seen=sorted_events[-1].timestamp,
            attack_velocity=velocity,
            sophistication_score=sophistication,
            behavioral_fingerprint={
                "tool_sequence": tool_sequence,
                "preferred_categories": preferred_categories,
                "attack_duration_hours": duration,
                "avg_time_between_attacks": avg_time_between,
                "tool_diversity": len(unique_tools),
                "category_diversity": len(category_dist),
                "most_used_tool": (
                    max(
                        ((tool, tool_sequence.count(tool)) for tool in unique_tools),
                        key=lambda x: x[1],
                    )[0]
                    if unique_tools
                    else None
                ),
                "attack_pattern": "persistent" if total_attacks >= 10 else "exploratory",
            },
        )

        logger.info(
            "Built attacker profile: session=%s, attacks=%d, sophistication=%.2f",
            session_id,
            total_attacks,
            sophistication,
        )

        return profile

    async def analyze_all(
        self,
        events: List[AttackFingerprint],
    ) -> Dict[str, List]:
        """Run all detection algorithms and return comprehensive analysis.

        Args:
            events: List of attack events to analyze

        Returns:
            Dictionary with keys: coordinated, campaigns, anomalies
        """
        results = {
            "coordinated": await self.detect_coordinated_attacks(events),
            "campaigns": await self.detect_attack_campaigns(events),
            "anomalies": await self.detect_anomalies(events),
        }

        logger.info(
            "Pattern analysis complete: %d coordinated, %d campaigns, %d anomalies",
            len(results["coordinated"]),
            len(results["campaigns"]),
            len(results["anomalies"]),
        )

        return results
