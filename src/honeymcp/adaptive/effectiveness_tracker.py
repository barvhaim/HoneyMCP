"""Track effectiveness of ghost tools for adaptive optimization."""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict

from honeymcp.models.adaptive_tools import ToolEffectivenessMetric
from honeymcp.models.events import AttackFingerprint

logger = logging.getLogger(__name__)


class EffectivenessTracker:
    """Track and calculate effectiveness metrics for ghost tools.

    Features:
    - Real-time metric updates as attacks occur
    - Sliding window analysis for recent performance
    - Multi-dimensional scoring (attractiveness, detection, engagement)
    - Session-based tracking for unique attacker counting
    """

    def __init__(self) -> None:
        """Initialize effectiveness tracker."""
        self._metrics: Dict[str, ToolEffectivenessMetric] = {}
        self._session_tools: Dict[str, set] = defaultdict(set)  # session_id -> tools used
        self._session_start_times: Dict[str, datetime] = {}  # session_id -> start time

        logger.info("Effectiveness tracker initialized")

    async def record_trigger(
        self,
        event: AttackFingerprint,
    ) -> None:
        """Record a tool trigger event.

        Args:
            event: Attack event to record
        """
        tool_name = event.ghost_tool_called
        session_id = event.session_id

        # Initialize metric if needed
        if tool_name not in self._metrics:
            self._metrics[tool_name] = ToolEffectivenessMetric(
                tool_name=tool_name,
                first_seen=event.timestamp,
                last_updated=event.timestamp,
            )

        metric = self._metrics[tool_name]

        # Update trigger count
        metric.trigger_count += 1
        metric.last_triggered = event.timestamp

        # Track unique sessions
        if tool_name not in self._session_tools[session_id]:
            self._session_tools[session_id].add(tool_name)
            metric.unique_sessions = len(
                [sid for sid, tools in self._session_tools.items() if tool_name in tools]
            )

        # Track session start time
        if session_id not in self._session_start_times:
            self._session_start_times[session_id] = event.timestamp

        # Update time to trigger
        time_to_trigger = (event.timestamp - self._session_start_times[session_id]).total_seconds()
        if metric.trigger_count == 1:
            metric.avg_time_to_trigger = time_to_trigger
        else:
            # Running average
            metric.avg_time_to_trigger = (
                metric.avg_time_to_trigger * (metric.trigger_count - 1) + time_to_trigger
            ) / metric.trigger_count

        # Track high threat triggers
        if event.threat_level in ["high", "critical"]:
            metric.high_threat_triggers += 1

        # Update timestamp
        metric.last_updated = datetime.utcnow()

        # Recalculate scores
        await self._calculate_scores(metric)

        logger.debug(
            "Recorded trigger for %s: count=%d, score=%.2f",
            tool_name,
            metric.trigger_count,
            metric.overall_score,
        )

    async def _calculate_scores(self, metric: ToolEffectivenessMetric) -> None:
        """Calculate effectiveness scores for a tool.

        Args:
            metric: Metric to calculate scores for
        """
        # Attractiveness: How often it's triggered relative to exposure time
        # Higher trigger count and unique sessions = more attractive
        if metric.trigger_count > 0:
            # Normalize by time since first seen (days)
            days_active = max(1, (datetime.utcnow() - metric.first_seen).days)
            triggers_per_day = metric.trigger_count / days_active

            # Score based on triggers per day (cap at 10 for normalization)
            metric.attractiveness_score = min(1.0, triggers_per_day / 10.0)

            # Boost for unique sessions
            if metric.unique_sessions > 1:
                session_boost = min(0.2, metric.unique_sessions * 0.05)
                metric.attractiveness_score = min(1.0, metric.attractiveness_score + session_boost)

        # Detection: How well it identifies threats
        # Higher ratio of high-threat triggers = better detection
        if metric.trigger_count > 0:
            threat_ratio = metric.high_threat_triggers / metric.trigger_count
            metric.detection_score = threat_ratio

        # Engagement: How much time attackers spend with it
        # Lower time to trigger = more engaging (attackers find it quickly)
        if metric.avg_time_to_trigger > 0:
            # Normalize: 0-60s = high score, >300s = low score
            if metric.avg_time_to_trigger <= 60:
                metric.engagement_score = 1.0
            elif metric.avg_time_to_trigger >= 300:
                metric.engagement_score = 0.2
            else:
                # Linear interpolation
                metric.engagement_score = 1.0 - ((metric.avg_time_to_trigger - 60) / 240) * 0.8

        # Overall score: weighted average
        # Attractiveness: 40%, Detection: 40%, Engagement: 20%
        metric.overall_score = (
            metric.attractiveness_score * 0.4
            + metric.detection_score * 0.4
            + metric.engagement_score * 0.2
        )

    def get_metric(self, tool_name: str) -> Optional[ToolEffectivenessMetric]:
        """Get effectiveness metric for a tool.

        Args:
            tool_name: Name of the tool

        Returns:
            Metric if available, None otherwise
        """
        return self._metrics.get(tool_name)

    def get_all_metrics(self) -> Dict[str, ToolEffectivenessMetric]:
        """Get all effectiveness metrics.

        Returns:
            Dictionary of tool name to metric
        """
        return self._metrics.copy()

    def get_top_tools(self, n: int = 10) -> List[ToolEffectivenessMetric]:
        """Get top N most effective tools.

        Args:
            n: Number of tools to return

        Returns:
            List of top tools sorted by overall score
        """
        sorted_metrics = sorted(
            self._metrics.values(),
            key=lambda m: m.overall_score,
            reverse=True,
        )
        return sorted_metrics[:n]

    def get_bottom_tools(self, n: int = 10) -> List[ToolEffectivenessMetric]:
        """Get bottom N least effective tools.

        Args:
            n: Number of tools to return

        Returns:
            List of bottom tools sorted by overall score
        """
        sorted_metrics = sorted(
            self._metrics.values(),
            key=lambda m: m.overall_score,
        )
        return sorted_metrics[:n]

    async def get_tools_by_score_range(
        self,
        min_score: float = 0.0,
        max_score: float = 1.0,
    ) -> List[ToolEffectivenessMetric]:
        """Get tools within a score range.

        Args:
            min_score: Minimum overall score
            max_score: Maximum overall score

        Returns:
            List of tools in score range
        """
        return [
            metric
            for metric in self._metrics.values()
            if min_score <= metric.overall_score <= max_score
        ]

    async def get_recent_metrics(
        self,
        hours: int = 24,
    ) -> Dict[str, ToolEffectivenessMetric]:
        """Get metrics for tools active in recent time window.

        Args:
            hours: Hours to look back

        Returns:
            Dictionary of recently active tools
        """
        cutoff = datetime.utcnow() - timedelta(hours=hours)

        return {
            name: metric
            for name, metric in self._metrics.items()
            if metric.last_triggered and metric.last_triggered >= cutoff
        }

    async def analyze_trends(
        self,
        tool_name: str,
        window_hours: int = 24,
    ) -> Dict[str, float]:
        """Analyze trends for a specific tool.

        Args:
            tool_name: Tool to analyze
            window_hours: Time window for analysis

        Returns:
            Dictionary with trend metrics
        """
        metric = self._metrics.get(tool_name)
        if not metric:
            return {}

        # Calculate trends (simplified - in production would track historical data)
        trends = {
            "current_score": metric.overall_score,
            "trigger_rate": metric.trigger_count
            / max(1, (datetime.utcnow() - metric.first_seen).days),
            "unique_session_rate": metric.unique_sessions / max(1, metric.trigger_count),
            "threat_detection_rate": metric.high_threat_triggers / max(1, metric.trigger_count),
        }

        return trends

    async def compare_tools(
        self,
        tool1: str,
        tool2: str,
    ) -> Dict[str, any]:
        """Compare effectiveness of two tools.

        Args:
            tool1: First tool name
            tool2: Second tool name

        Returns:
            Comparison results
        """
        metric1 = self._metrics.get(tool1)
        metric2 = self._metrics.get(tool2)

        if not metric1 or not metric2:
            return {"error": "One or both tools not found"}

        return {
            "tool1": tool1,
            "tool2": tool2,
            "score_difference": metric1.overall_score - metric2.overall_score,
            "better_tool": tool1 if metric1.overall_score > metric2.overall_score else tool2,
            "metrics": {
                tool1: {
                    "overall_score": metric1.overall_score,
                    "attractiveness": metric1.attractiveness_score,
                    "detection": metric1.detection_score,
                    "engagement": metric1.engagement_score,
                    "triggers": metric1.trigger_count,
                },
                tool2: {
                    "overall_score": metric2.overall_score,
                    "attractiveness": metric2.attractiveness_score,
                    "detection": metric2.detection_score,
                    "engagement": metric2.engagement_score,
                    "triggers": metric2.trigger_count,
                },
            },
        }

    async def get_statistics(self) -> Dict[str, any]:
        """Get overall statistics across all tools.

        Returns:
            Statistics dictionary
        """
        if not self._metrics:
            return {
                "total_tools": 0,
                "total_triggers": 0,
                "avg_score": 0.0,
            }

        total_triggers = sum(m.trigger_count for m in self._metrics.values())
        avg_score = sum(m.overall_score for m in self._metrics.values()) / len(self._metrics)

        # Find best and worst
        best_tool = max(self._metrics.values(), key=lambda m: m.overall_score)
        worst_tool = min(self._metrics.values(), key=lambda m: m.overall_score)

        return {
            "total_tools": len(self._metrics),
            "total_triggers": total_triggers,
            "total_unique_sessions": len(self._session_tools),
            "avg_score": avg_score,
            "best_tool": {
                "name": best_tool.tool_name,
                "score": best_tool.overall_score,
            },
            "worst_tool": {
                "name": worst_tool.tool_name,
                "score": worst_tool.overall_score,
            },
            "score_distribution": {
                "high": len([m for m in self._metrics.values() if m.overall_score >= 0.7]),
                "medium": len([m for m in self._metrics.values() if 0.3 <= m.overall_score < 0.7]),
                "low": len([m for m in self._metrics.values() if m.overall_score < 0.3]),
            },
        }

    async def reset_metrics(self, tool_name: Optional[str] = None) -> None:
        """Reset metrics for a tool or all tools.

        Args:
            tool_name: Tool to reset, or None for all tools
        """
        if tool_name:
            if tool_name in self._metrics:
                del self._metrics[tool_name]
                logger.info("Reset metrics for tool: %s", tool_name)
        else:
            self._metrics.clear()
            self._session_tools.clear()
            self._session_start_times.clear()
            logger.info("Reset all metrics")

    async def export_metrics(self) -> List[Dict[str, any]]:
        """Export all metrics for analysis.

        Returns:
            List of metric dictionaries
        """
        return [metric.model_dump(mode="json") for metric in self._metrics.values()]

    async def import_metrics(self, metrics_data: List[Dict[str, any]]) -> None:
        """Import metrics from external source.

        Args:
            metrics_data: List of metric dictionaries
        """
        for data in metrics_data:
            metric = ToolEffectivenessMetric(**data)
            self._metrics[metric.tool_name] = metric

        logger.info("Imported %d metrics", len(metrics_data))
