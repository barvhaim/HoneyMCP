"""Adaptive catalog optimization for ghost tools."""

import logging
from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4

from honeymcp.models.adaptive_tools import (
    AdaptiveToolRecommendation,
    CatalogOptimizationConfig,
    CatalogSnapshot,
    OptimizationStrategy,
    ToolEffectivenessMetric,
)
from honeymcp.models.ghost_tool_spec import GhostToolSpec
from honeymcp.adaptive.effectiveness_tracker import EffectivenessTracker

logger = logging.getLogger(__name__)


class CatalogOptimizer:
    """Optimize ghost tool catalog based on effectiveness metrics.

    Features:
    - Automatic tool promotion/retirement based on performance
    - Multiple optimization strategies
    - Catalog size management
    - Recommendation generation with rationale
    - Historical snapshot tracking
    """

    def __init__(
        self,
        tracker: EffectivenessTracker,
        config: Optional[CatalogOptimizationConfig] = None,
    ) -> None:
        """Initialize catalog optimizer.

        Args:
            tracker: Effectiveness tracker instance
            config: Optimization configuration
        """
        self.tracker = tracker
        self.config = config or CatalogOptimizationConfig()
        self._snapshots: List[CatalogSnapshot] = []

        logger.info(
            "Catalog optimizer initialized with strategy: %s",
            self.config.strategy.value,
        )

    async def analyze_catalog(
        self,
        current_tools: List[GhostToolSpec],
    ) -> AdaptiveToolRecommendation:
        """Analyze current catalog and generate recommendations.

        Args:
            current_tools: Current ghost tools in catalog

        Returns:
            Recommendations for catalog changes
        """
        recommendation_id = f"rec_{uuid4().hex[:12]}"

        metrics = await self.tracker.get_recent_metrics(hours=self.config.evaluation_window_hours)

        if self.config.strategy == OptimizationStrategy.BALANCED:
            recommendation = await self._balanced_optimization(
                current_tools, metrics, recommendation_id
            )
        elif self.config.strategy == OptimizationStrategy.DETECTION_FOCUSED:
            recommendation = await self._detection_focused_optimization(
                current_tools, metrics, recommendation_id
            )
        elif self.config.strategy == OptimizationStrategy.ENGAGEMENT_FOCUSED:
            recommendation = await self._engagement_focused_optimization(
                current_tools, metrics, recommendation_id
            )
        else:  # ADAPTIVE
            recommendation = await self._adaptive_optimization(
                current_tools, metrics, recommendation_id
            )

        logger.info(
            "Generated recommendation %s: +%d tools, -%d tools",
            recommendation_id,
            len(recommendation.tools_to_add),
            len(recommendation.tools_to_remove),
        )

        return recommendation

    async def _balanced_optimization(
        self,
        current_tools: List[GhostToolSpec],
        metrics: Dict[str, ToolEffectivenessMetric],
        recommendation_id: str,
    ) -> AdaptiveToolRecommendation:
        """Balanced optimization strategy.

        Balances all metrics equally for well-rounded catalog.
        """
        tools_to_remove = []
        tools_to_add = []
        rationale_parts = []

        if self.config.auto_retire_enabled:
            for tool in current_tools:
                metric = metrics.get(tool.name)
                if metric and metric.overall_score < self.config.min_score_threshold:
                    tools_to_remove.append(tool.name)
                    rationale_parts.append(
                        f"Remove '{tool.name}' (score: {metric.overall_score:.2f})"
                    )

        current_count = len(current_tools) - len(tools_to_remove)
        if current_count < self.config.min_tools:
            needed = self.config.min_tools - current_count
            tools_to_add.extend([f"new_tool_{i}" for i in range(needed)])
            rationale_parts.append(f"Add {needed} tools to meet minimum")

        if current_count > self.config.max_tools:
            excess = current_count - self.config.max_tools
            sorted_tools = sorted(
                [(t.name, metrics.get(t.name)) for t in current_tools],
                key=lambda x: x[1].overall_score if x[1] else 0.0,
            )
            for tool_name, _ in sorted_tools[:excess]:
                if tool_name not in tools_to_remove:
                    tools_to_remove.append(tool_name)
            rationale_parts.append(f"Remove {excess} tools to meet maximum")

        rationale = "; ".join(rationale_parts) if rationale_parts else "No changes needed"

        return AdaptiveToolRecommendation(
            recommendation_id=recommendation_id,
            generated_at=datetime.utcnow(),
            tools_to_add=tools_to_add,
            tools_to_remove=tools_to_remove,
            tools_to_modify={},
            rationale=rationale,
            expected_improvement=0.1 if tools_to_remove or tools_to_add else 0.0,
            based_on_sessions=list(metrics.keys()),
            strategy_used=OptimizationStrategy.BALANCED,
        )

    async def _detection_focused_optimization(
        self,
        current_tools: List[GhostToolSpec],
        metrics: Dict[str, ToolEffectivenessMetric],
        recommendation_id: str,
    ) -> AdaptiveToolRecommendation:
        """Detection-focused optimization strategy.

        Prioritizes tools with high threat detection rates.
        """
        tools_to_remove = []
        rationale_parts = []

        # 0.5 detection floor is strategy-local, not config.min_score_threshold
        if self.config.auto_retire_enabled:
            for tool in current_tools:
                metric = metrics.get(tool.name)
                if metric and metric.detection_score < 0.5:
                    tools_to_remove.append(tool.name)
                    rationale_parts.append(
                        f"Remove '{tool.name}' (detection: {metric.detection_score:.2f})"
                    )

        rationale = (
            "Detection-focused: " + "; ".join(rationale_parts)
            if rationale_parts
            else "All tools have adequate detection scores"
        )

        return AdaptiveToolRecommendation(
            recommendation_id=recommendation_id,
            generated_at=datetime.utcnow(),
            tools_to_add=[],
            tools_to_remove=tools_to_remove,
            tools_to_modify={},
            rationale=rationale,
            expected_improvement=0.15 if tools_to_remove else 0.0,
            based_on_sessions=list(metrics.keys()),
            strategy_used=OptimizationStrategy.DETECTION_FOCUSED,
        )

    async def _engagement_focused_optimization(
        self,
        current_tools: List[GhostToolSpec],
        metrics: Dict[str, ToolEffectivenessMetric],
        recommendation_id: str,
    ) -> AdaptiveToolRecommendation:
        """Engagement-focused optimization strategy.

        Prioritizes tools that keep attackers engaged longer.
        """
        tools_to_remove = []
        rationale_parts = []

        # 0.4 engagement floor is strategy-local, not config.min_score_threshold
        if self.config.auto_retire_enabled:
            for tool in current_tools:
                metric = metrics.get(tool.name)
                if metric and metric.engagement_score < 0.4:
                    tools_to_remove.append(tool.name)
                    rationale_parts.append(
                        f"Remove '{tool.name}' (engagement: {metric.engagement_score:.2f})"
                    )

        rationale = (
            "Engagement-focused: " + "; ".join(rationale_parts)
            if rationale_parts
            else "All tools have adequate engagement"
        )

        return AdaptiveToolRecommendation(
            recommendation_id=recommendation_id,
            generated_at=datetime.utcnow(),
            tools_to_add=[],
            tools_to_remove=tools_to_remove,
            tools_to_modify={},
            rationale=rationale,
            expected_improvement=0.12 if tools_to_remove else 0.0,
            based_on_sessions=list(metrics.keys()),
            strategy_used=OptimizationStrategy.ENGAGEMENT_FOCUSED,
        )

    async def _adaptive_optimization(
        self,
        current_tools: List[GhostToolSpec],
        metrics: Dict[str, ToolEffectivenessMetric],
        recommendation_id: str,
    ) -> AdaptiveToolRecommendation:
        """Adaptive optimization strategy.

        Adapts based on current attack patterns and catalog performance.
        """
        stats = await self.tracker.get_statistics()

        if stats["avg_score"] < 0.5:
            # Low overall performance - focus on detection
            return await self._detection_focused_optimization(
                current_tools, metrics, recommendation_id
            )
        elif stats["score_distribution"]["high"] < len(current_tools) * 0.3:
            # Not enough high-performing tools - use balanced
            return await self._balanced_optimization(current_tools, metrics, recommendation_id)
        else:
            # Good performance - focus on engagement
            return await self._engagement_focused_optimization(
                current_tools, metrics, recommendation_id
            )

    async def create_snapshot(
        self,
        current_tools: List[GhostToolSpec],
    ) -> CatalogSnapshot:
        """Create snapshot of current catalog state.

        Args:
            current_tools: Current tools in catalog

        Returns:
            Catalog snapshot
        """
        snapshot_id = f"snap_{uuid4().hex[:12]}"

        all_metrics = self.tracker.get_all_metrics()

        if all_metrics:
            overall_effectiveness = sum(m.overall_score for m in all_metrics.values()) / len(
                all_metrics
            )
            avg_tool_score = overall_effectiveness
        else:
            overall_effectiveness = 0.0
            avg_tool_score = 0.0

        stats = await self.tracker.get_statistics()

        snapshot = CatalogSnapshot(
            snapshot_id=snapshot_id,
            timestamp=datetime.utcnow(),
            active_tools=[t.name for t in current_tools],
            tool_metrics=all_metrics,
            overall_effectiveness=overall_effectiveness,
            avg_tool_score=avg_tool_score,
            optimization_strategy=self.config.strategy,
            total_sessions=stats.get("total_unique_sessions", 0),
            total_triggers=stats.get("total_triggers", 0),
        )

        self._snapshots.append(snapshot)

        logger.info(
            "Created catalog snapshot %s: %d tools, %.2f effectiveness",
            snapshot_id,
            len(current_tools),
            overall_effectiveness,
        )

        return snapshot

    def get_snapshots(
        self,
        limit: Optional[int] = None,
    ) -> List[CatalogSnapshot]:
        """Get historical snapshots.

        Args:
            limit: Maximum number of snapshots to return (most recent first)

        Returns:
            List of snapshots
        """
        sorted_snapshots = sorted(
            self._snapshots,
            key=lambda s: s.timestamp,
            reverse=True,
        )

        if limit:
            return sorted_snapshots[:limit]
        return sorted_snapshots

    async def compare_snapshots(
        self,
        snapshot1_id: str,
        snapshot2_id: str,
    ) -> Dict[str, any]:
        """Compare two catalog snapshots.

        Args:
            snapshot1_id: First snapshot ID
            snapshot2_id: Second snapshot ID

        Returns:
            Comparison results
        """
        snap1 = next((s for s in self._snapshots if s.snapshot_id == snapshot1_id), None)
        snap2 = next((s for s in self._snapshots if s.snapshot_id == snapshot2_id), None)

        if not snap1 or not snap2:
            return {"error": "One or both snapshots not found"}

        tools_added = set(snap2.active_tools) - set(snap1.active_tools)
        tools_removed = set(snap1.active_tools) - set(snap2.active_tools)
        tools_kept = set(snap1.active_tools) & set(snap2.active_tools)

        effectiveness_change = snap2.overall_effectiveness - snap1.overall_effectiveness

        return {
            "snapshot1": {
                "id": snapshot1_id,
                "timestamp": snap1.timestamp,
                "tools": len(snap1.active_tools),
                "effectiveness": snap1.overall_effectiveness,
            },
            "snapshot2": {
                "id": snapshot2_id,
                "timestamp": snap2.timestamp,
                "tools": len(snap2.active_tools),
                "effectiveness": snap2.overall_effectiveness,
            },
            "changes": {
                "tools_added": list(tools_added),
                "tools_removed": list(tools_removed),
                "tools_kept": len(tools_kept),
                "effectiveness_change": effectiveness_change,
                "improvement": effectiveness_change > 0,
            },
        }

    async def get_optimization_history(self) -> List[Dict[str, any]]:
        """Get history of optimization changes.

        Returns:
            List of optimization events
        """
        history = []

        for i in range(1, len(self._snapshots)):
            prev = self._snapshots[i - 1]
            curr = self._snapshots[i]

            tools_added = set(curr.active_tools) - set(prev.active_tools)
            tools_removed = set(prev.active_tools) - set(curr.active_tools)

            if tools_added or tools_removed:
                history.append(
                    {
                        "timestamp": curr.timestamp,
                        "tools_added": list(tools_added),
                        "tools_removed": list(tools_removed),
                        "effectiveness_before": prev.overall_effectiveness,
                        "effectiveness_after": curr.overall_effectiveness,
                        "improvement": curr.overall_effectiveness - prev.overall_effectiveness,
                    }
                )

        return history

    async def predict_impact(
        self,
        recommendation: AdaptiveToolRecommendation,
        current_tools: List[GhostToolSpec],
    ) -> Dict[str, any]:
        """Predict impact of applying a recommendation.

        Args:
            recommendation: Recommendation to evaluate
            current_tools: Current catalog tools

        Returns:
            Impact prediction
        """
        current_metrics = self.tracker.get_all_metrics()

        if current_metrics:
            current_avg = sum(m.overall_score for m in current_metrics.values()) / len(
                current_metrics
            )
        else:
            current_avg = 0.0

        # Simulate removal of low-performing tools
        remaining_tools = [t for t in current_tools if t.name not in recommendation.tools_to_remove]

        if remaining_tools:
            remaining_scores = [
                current_metrics[t.name].overall_score
                for t in remaining_tools
                if t.name in current_metrics
            ]
            if remaining_scores:
                new_avg = sum(remaining_scores) / len(remaining_scores)
            else:
                new_avg = current_avg
        else:
            new_avg = 0.0

        predicted_improvement = new_avg - current_avg

        return {
            "current_avg_score": current_avg,
            "predicted_avg_score": new_avg,
            "predicted_improvement": predicted_improvement,
            "tools_affected": len(recommendation.tools_to_remove)
            + len(recommendation.tools_to_add),
            "confidence": 0.7,  # Simplified confidence score
            "recommendation": recommendation.rationale,
        }

    async def apply_recommendation(
        self,
        recommendation: AdaptiveToolRecommendation,
        current_tools: List[GhostToolSpec],
    ) -> List[GhostToolSpec]:
        """Apply recommendation to catalog (simulation).

        Args:
            recommendation: Recommendation to apply
            current_tools: Current catalog

        Returns:
            Updated catalog
        """
        updated_tools = [t for t in current_tools if t.name not in recommendation.tools_to_remove]

        # Note: Adding new tools would require tool generation
        # This is a placeholder - actual implementation would integrate
        # with tool generation system

        logger.info(
            "Applied recommendation: removed %d tools, catalog now has %d tools",
            len(recommendation.tools_to_remove),
            len(updated_tools),
        )

        return updated_tools

    def get_config(self) -> CatalogOptimizationConfig:
        """Get current optimization configuration.

        Returns:
            Current configuration
        """
        return self.config

    def update_config(self, config: CatalogOptimizationConfig) -> None:
        """Update optimization configuration.

        Args:
            config: New configuration
        """
        self.config = config
        logger.info("Updated optimization config: strategy=%s", config.strategy.value)
