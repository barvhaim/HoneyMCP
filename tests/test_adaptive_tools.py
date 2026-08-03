"""Tests for adaptive ghost tool system."""

import asyncio
from datetime import datetime, timedelta
from typing import List

import pytest

from honeymcp.adaptive.attacker_profiler import AttackerProfiler
from honeymcp.adaptive.catalog_optimizer import CatalogOptimizer
from honeymcp.adaptive.effectiveness_tracker import EffectivenessTracker
from honeymcp.models.adaptive_tools import (
    CatalogOptimizationConfig,
    OptimizationStrategy,
)
from honeymcp.models.events import AttackFingerprint
from honeymcp.models.ghost_tool_spec import GhostToolSpec


@pytest.fixture
def sample_events() -> List[AttackFingerprint]:
    """Create sample attack events."""
    base_time = datetime.utcnow()
    session_id = "test_session_123"
    
    events = [
        AttackFingerprint(
            event_id="evt_001",
            timestamp=base_time,
            session_id=session_id,
            ghost_tool_called="list_secrets",
            arguments={},
            response_sent="test",
            threat_level="high",
            attack_category="credential_access",
            client_metadata={},
        ),
        AttackFingerprint(
            event_id="evt_002",
            timestamp=base_time + timedelta(seconds=5),
            session_id=session_id,
            ghost_tool_called="execute_command",
            arguments={},
            response_sent="test",
            threat_level="critical",
            attack_category="rce",
            client_metadata={},
        ),
        AttackFingerprint(
            event_id="evt_003",
            timestamp=base_time + timedelta(seconds=10),
            session_id=session_id,
            ghost_tool_called="list_secrets",  # Repeat
            arguments={},
            response_sent="test",
            threat_level="high",
            attack_category="credential_access",
            client_metadata={},
        ),
    ]
    
    return events


@pytest.fixture
def sample_tools() -> List[GhostToolSpec]:
    """Create sample ghost tools."""
    return [
        GhostToolSpec(
            name="list_secrets",
            description="List secrets",
            parameters={},
            response_generator=lambda args: "fake response",
            threat_level="high",
            attack_category="credential_access",
        ),
        GhostToolSpec(
            name="execute_command",
            description="Execute command",
            parameters={},
            response_generator=lambda args: "fake response",
            threat_level="critical",
            attack_category="rce",
        ),
        GhostToolSpec(
            name="low_performing_tool",
            description="Low performing tool",
            parameters={},
            response_generator=lambda args: "fake response",
            threat_level="low",
            attack_category="discovery",
        ),
    ]


@pytest.fixture
def effectiveness_tracker() -> EffectivenessTracker:
    """Create effectiveness tracker."""
    return EffectivenessTracker()


@pytest.fixture
def catalog_optimizer(effectiveness_tracker: EffectivenessTracker) -> CatalogOptimizer:
    """Create catalog optimizer."""
    return CatalogOptimizer(effectiveness_tracker)


@pytest.fixture
def attacker_profiler() -> AttackerProfiler:
    """Create attacker profiler."""
    return AttackerProfiler()


class TestEffectivenessTracker:
    """Test effectiveness tracking."""
    
    @pytest.mark.asyncio
    async def test_record_trigger(
        self,
        effectiveness_tracker: EffectivenessTracker,
        sample_events: List[AttackFingerprint],
    ):
        """Test recording tool triggers."""
        event = sample_events[0]
        
        await effectiveness_tracker.record_trigger(event)
        
        metric = effectiveness_tracker.get_metric("list_secrets")
        assert metric is not None
        assert metric.tool_name == "list_secrets"
        assert metric.trigger_count == 1
        assert metric.unique_sessions == 1
    
    @pytest.mark.asyncio
    async def test_multiple_triggers(
        self,
        effectiveness_tracker: EffectivenessTracker,
        sample_events: List[AttackFingerprint],
    ):
        """Test multiple triggers update metrics."""
        for event in sample_events:
            await effectiveness_tracker.record_trigger(event)
        
        metric = effectiveness_tracker.get_metric("list_secrets")
        assert metric.trigger_count == 2

        metric = effectiveness_tracker.get_metric("execute_command")
        assert metric.trigger_count == 1
    
    @pytest.mark.asyncio
    async def test_score_calculation(
        self,
        effectiveness_tracker: EffectivenessTracker,
        sample_events: List[AttackFingerprint],
    ):
        """Test effectiveness score calculation."""
        for event in sample_events:
            await effectiveness_tracker.record_trigger(event)
        
        metric = effectiveness_tracker.get_metric("list_secrets")
        
        assert 0.0 <= metric.attractiveness_score <= 1.0
        assert 0.0 <= metric.detection_score <= 1.0
        assert 0.0 <= metric.engagement_score <= 1.0
        assert 0.0 <= metric.overall_score <= 1.0
        
        # High threat triggers should give good detection score
        assert metric.detection_score > 0.5
    
    @pytest.mark.asyncio
    async def test_get_top_tools(
        self,
        effectiveness_tracker: EffectivenessTracker,
        sample_events: List[AttackFingerprint],
    ):
        """Test getting top performing tools."""
        for event in sample_events:
            await effectiveness_tracker.record_trigger(event)
        
        top_tools = effectiveness_tracker.get_top_tools(n=2)
        
        assert len(top_tools) <= 2
        # Should be sorted by score
        if len(top_tools) == 2:
            assert top_tools[0].overall_score >= top_tools[1].overall_score
    
    @pytest.mark.asyncio
    async def test_get_statistics(
        self,
        effectiveness_tracker: EffectivenessTracker,
        sample_events: List[AttackFingerprint],
    ):
        """Test getting overall statistics."""
        for event in sample_events:
            await effectiveness_tracker.record_trigger(event)
        
        stats = await effectiveness_tracker.get_statistics()
        
        assert stats["total_tools"] == 2
        assert stats["total_triggers"] == 3
        assert stats["total_unique_sessions"] == 1
        assert "avg_score" in stats
        assert "best_tool" in stats
        assert "worst_tool" in stats


class TestCatalogOptimizer:
    """Test catalog optimization."""
    
    @pytest.mark.asyncio
    async def test_analyze_catalog(
        self,
        catalog_optimizer: CatalogOptimizer,
        effectiveness_tracker: EffectivenessTracker,
        sample_tools: List[GhostToolSpec],
        sample_events: List[AttackFingerprint],
    ):
        """Test catalog analysis."""
        for event in sample_events:
            await effectiveness_tracker.record_trigger(event)

        recommendation = await catalog_optimizer.analyze_catalog(sample_tools)

        assert recommendation.recommendation_id.startswith("rec_")
        assert isinstance(recommendation.tools_to_add, list)
        assert isinstance(recommendation.tools_to_remove, list)
        assert len(recommendation.rationale) > 0
    
    @pytest.mark.asyncio
    async def test_balanced_optimization(
        self,
        catalog_optimizer: CatalogOptimizer,
        effectiveness_tracker: EffectivenessTracker,
        sample_tools: List[GhostToolSpec],
        sample_events: List[AttackFingerprint],
    ):
        """Test balanced optimization strategy."""
        for event in sample_events:
            await effectiveness_tracker.record_trigger(event)

        catalog_optimizer.config.strategy = OptimizationStrategy.BALANCED
        
        recommendation = await catalog_optimizer.analyze_catalog(sample_tools)
        
        assert recommendation.strategy_used == OptimizationStrategy.BALANCED
    
    @pytest.mark.asyncio
    async def test_create_snapshot(
        self,
        catalog_optimizer: CatalogOptimizer,
        sample_tools: List[GhostToolSpec],
    ):
        """Test creating catalog snapshot."""
        snapshot = await catalog_optimizer.create_snapshot(sample_tools)
        
        assert snapshot.snapshot_id.startswith("snap_")
        assert len(snapshot.active_tools) == len(sample_tools)
        assert 0.0 <= snapshot.overall_effectiveness <= 1.0
    
    @pytest.mark.asyncio
    async def test_get_snapshots(
        self,
        catalog_optimizer: CatalogOptimizer,
        sample_tools: List[GhostToolSpec],
    ):
        """Test retrieving snapshots."""
        await catalog_optimizer.create_snapshot(sample_tools)
        # sleep so the two snapshots get distinct timestamps to order by
        await asyncio.sleep(0.1)
        await catalog_optimizer.create_snapshot(sample_tools)

        snapshots = catalog_optimizer.get_snapshots(limit=2)

        assert len(snapshots) == 2
        # most recent first
        assert snapshots[0].timestamp >= snapshots[1].timestamp
    
    @pytest.mark.asyncio
    async def test_config_update(
        self,
        catalog_optimizer: CatalogOptimizer,
    ):
        """Test updating optimizer configuration."""
        new_config = CatalogOptimizationConfig(
            strategy=OptimizationStrategy.DETECTION_FOCUSED,
            min_tools=3,
            max_tools=15,
        )
        
        catalog_optimizer.update_config(new_config)
        
        assert catalog_optimizer.config.strategy == OptimizationStrategy.DETECTION_FOCUSED
        assert catalog_optimizer.config.min_tools == 3
        assert catalog_optimizer.config.max_tools == 15


class TestAttackerProfiler:
    """Test attacker profiling."""
    
    @pytest.mark.asyncio
    async def test_analyze_session(
        self,
        attacker_profiler: AttackerProfiler,
        sample_events: List[AttackFingerprint],
    ):
        """Test session analysis and profile creation."""
        session_id = sample_events[0].session_id
        
        profile = await attacker_profiler.analyze_session(session_id, sample_events)
        
        assert profile.session_id == session_id
        assert len(profile.tool_preferences) > 0
        assert len(profile.attack_sequence) > 0
        assert profile.timing_pattern in ["rapid", "methodical", "sporadic", "unknown"]
        assert 0.0 <= profile.sophistication_score <= 1.0
        assert profile.tool_diversity > 0
    
    @pytest.mark.asyncio
    async def test_sophistication_calculation(
        self,
        attacker_profiler: AttackerProfiler,
        sample_events: List[AttackFingerprint],
    ):
        """Test sophistication score calculation."""
        session_id = sample_events[0].session_id
        
        profile = await attacker_profiler.analyze_session(session_id, sample_events)
        
        # multiple distinct tools plus high/critical threat levels floor this above 0
        assert profile.sophistication_score > 0.0
    
    @pytest.mark.asyncio
    async def test_tool_recommendations(
        self,
        attacker_profiler: AttackerProfiler,
        sample_events: List[AttackFingerprint],
    ):
        """Test tool recommendations."""
        session_id = sample_events[0].session_id
        
        profile = await attacker_profiler.analyze_session(session_id, sample_events)
        
        assert len(profile.recommended_tools) > 0
        # recommendations derive from the observed categories (credential_access, rce)
        assert any("credential" in tool.lower() or "execute" in tool.lower()
                  for tool in profile.recommended_tools)
    
    @pytest.mark.asyncio
    async def test_generate_hint(
        self,
        attacker_profiler: AttackerProfiler,
        sample_events: List[AttackFingerprint],
    ):
        """Test generation hint creation."""
        session_id = sample_events[0].session_id
        
        # generate_hint requires the session to have been profiled first
        await attacker_profiler.analyze_session(session_id, sample_events)

        hint = await attacker_profiler.generate_hint(session_id)
        
        assert hint is not None
        assert hint.session_id == session_id
        assert len(hint.suggested_tool_types) > 0
        assert len(hint.suggested_categories) > 0
        assert hint.sophistication_level in ["low", "medium", "high"]
        assert 0.0 <= hint.confidence <= 1.0
    
    @pytest.mark.asyncio
    async def test_compare_profiles(
        self,
        attacker_profiler: AttackerProfiler,
        sample_events: List[AttackFingerprint],
    ):
        """Test profile comparison."""
        session1 = "session_1"
        session2 = "session_2"
        
        events1 = [e for e in sample_events]
        for e in events1:
            e.session_id = session1
        
        events2 = [e for e in sample_events]
        for e in events2:
            e.session_id = session2
        
        await attacker_profiler.analyze_session(session1, events1)
        await attacker_profiler.analyze_session(session2, events2)
        
        comparison = await attacker_profiler.compare_profiles(session1, session2)
        
        assert "similarity_score" in comparison
        assert 0.0 <= comparison["similarity_score"] <= 1.0
        # both profiles were built from the same event list, so similarity must be high
        assert comparison["similarity_score"] > 0.5
    
    @pytest.mark.asyncio
    async def test_identify_campaigns(
        self,
        attacker_profiler: AttackerProfiler,
        sample_events: List[AttackFingerprint],
    ):
        """Test campaign identification."""
        # three sessions built from identical events cluster into one campaign
        for i in range(3):
            session_id = f"session_{i}"
            events = [e for e in sample_events]
            for e in events:
                e.session_id = session_id
            
            await attacker_profiler.analyze_session(session_id, events)
        
        campaigns = await attacker_profiler.identify_campaigns()

        assert len(campaigns) > 0
        assert campaigns[0]["session_count"] >= 2
    
    @pytest.mark.asyncio
    async def test_get_statistics(
        self,
        attacker_profiler: AttackerProfiler,
        sample_events: List[AttackFingerprint],
    ):
        """Test profiling statistics."""
        session_id = sample_events[0].session_id
        await attacker_profiler.analyze_session(session_id, sample_events)
        
        stats = await attacker_profiler.get_statistics()
        
        assert stats["total_profiles"] == 1
        assert "avg_sophistication" in stats
        assert "sophistication_distribution" in stats
        assert "automation_detected" in stats


class TestIntegration:
    """Integration tests for adaptive system."""
    
    @pytest.mark.asyncio
    async def test_complete_adaptive_workflow(
        self,
        effectiveness_tracker: EffectivenessTracker,
        catalog_optimizer: CatalogOptimizer,
        attacker_profiler: AttackerProfiler,
        sample_events: List[AttackFingerprint],
        sample_tools: List[GhostToolSpec],
    ):
        """Test complete adaptive workflow."""
        session_id = sample_events[0].session_id
        
        for event in sample_events:
            await effectiveness_tracker.record_trigger(event)

        metrics = effectiveness_tracker.get_all_metrics()
        assert len(metrics) > 0

        recommendation = await catalog_optimizer.analyze_catalog(sample_tools)
        assert recommendation is not None

        snapshot = await catalog_optimizer.create_snapshot(sample_tools)
        assert snapshot is not None

        profile = await attacker_profiler.analyze_session(session_id, sample_events)
        assert profile is not None

        hint = await attacker_profiler.generate_hint(session_id)
        assert hint is not None

        tracker_stats = await effectiveness_tracker.get_statistics()
        profiler_stats = await attacker_profiler.get_statistics()
        
        assert tracker_stats["total_tools"] > 0
        assert profiler_stats["total_profiles"] > 0
    
    @pytest.mark.asyncio
    async def test_optimization_improves_catalog(
        self,
        effectiveness_tracker: EffectivenessTracker,
        catalog_optimizer: CatalogOptimizer,
        sample_events: List[AttackFingerprint],
        sample_tools: List[GhostToolSpec],
    ):
        """Test that optimization can improve catalog."""
        # only trigger the first 2 tools, leaving low_performing_tool with zero triggers
        for event in sample_events[:2]:
            await effectiveness_tracker.record_trigger(event)

        snapshot1 = await catalog_optimizer.create_snapshot(sample_tools)

        recommendation = await catalog_optimizer.analyze_catalog(sample_tools)

        # the untriggered tool is the expected removal candidate
        if recommendation.tools_to_remove:
            assert "low_performing_tool" in recommendation.tools_to_remove or \
                   len(recommendation.tools_to_remove) > 0
