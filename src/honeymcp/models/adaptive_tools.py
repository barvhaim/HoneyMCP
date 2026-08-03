"""Data models for adaptive ghost tool system."""

from datetime import datetime
from typing import Dict, List, Optional
from enum import Enum
from pydantic import BaseModel, Field


class ToolEffectivenessMetric(BaseModel):
    """Metrics tracking effectiveness of a ghost tool.

    Tracks how well a tool attracts and fingerprints attackers.
    """

    tool_name: str = Field(description="Name of the ghost tool")

    trigger_count: int = Field(default=0, description="Number of times triggered")
    unique_sessions: int = Field(default=0, description="Unique sessions that used this tool")

    avg_time_to_trigger: float = Field(
        default=0.0, description="Average time from session start to first trigger (seconds)"
    )
    total_engagement_time: float = Field(
        default=0.0, description="Total time attackers spent with this tool (seconds)"
    )

    high_threat_triggers: int = Field(
        default=0, description="Triggers that resulted in high/critical threat level"
    )

    attractiveness_score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="How attractive the tool is to attackers"
    )
    detection_score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="How well it detects threats"
    )
    engagement_score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="How much attackers engage with it"
    )
    overall_score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Overall effectiveness score"
    )

    first_seen: datetime = Field(description="When tool was first deployed")
    last_triggered: Optional[datetime] = Field(
        default=None, description="Last time tool was triggered"
    )
    last_updated: datetime = Field(description="Last metrics update")


class OptimizationStrategy(str, Enum):
    """Strategy for catalog optimization."""

    BALANCED = "balanced"  # Balance between all metrics
    DETECTION_FOCUSED = "detection_focused"  # Prioritize threat detection
    ENGAGEMENT_FOCUSED = "engagement_focused"  # Prioritize attacker engagement
    ADAPTIVE = "adaptive"  # Adapt based on attack patterns


class CatalogOptimizationConfig(BaseModel):
    """Configuration for catalog optimization."""

    strategy: OptimizationStrategy = Field(
        default=OptimizationStrategy.BALANCED, description="Optimization strategy"
    )

    min_tools: int = Field(default=5, ge=1, description="Minimum number of tools to maintain")
    max_tools: int = Field(default=20, ge=1, description="Maximum number of tools to maintain")

    min_score_threshold: float = Field(
        default=0.3, ge=0.0, le=1.0, description="Minimum score to keep a tool"
    )

    promotion_threshold: float = Field(
        default=0.7, ge=0.0, le=1.0, description="Score threshold to promote a tool"
    )

    evaluation_window_hours: int = Field(
        default=24, ge=1, description="Hours of data to consider for evaluation"
    )

    auto_retire_enabled: bool = Field(
        default=True, description="Automatically retire low-performing tools"
    )

    auto_generate_enabled: bool = Field(
        default=True, description="Automatically generate new tools"
    )


class ToolGenerationHint(BaseModel):
    """Hints for generating new tools based on attacker behavior."""

    session_id: str = Field(description="Session that generated this hint")

    attempted_tools: List[str] = Field(description="Tools the attacker tried to use")
    attack_categories: List[str] = Field(description="Attack categories observed")
    sophistication_level: str = Field(
        description="Estimated attacker sophistication: low, medium, high"
    )

    suggested_tool_types: List[str] = Field(
        description="Types of tools that might attract this attacker"
    )
    suggested_categories: List[str] = Field(description="Categories to focus on")

    timestamp: datetime = Field(description="When hint was generated")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in this hint")


class AdaptiveToolRecommendation(BaseModel):
    """Recommendation for catalog changes."""

    recommendation_id: str = Field(description="Unique recommendation ID")
    generated_at: datetime = Field(description="When recommendation was generated")

    tools_to_add: List[str] = Field(default_factory=list, description="Tools to add to catalog")
    tools_to_remove: List[str] = Field(
        default_factory=list, description="Tools to remove from catalog"
    )
    tools_to_modify: Dict[str, Dict[str, str]] = Field(
        default_factory=dict, description="Tools to modify (tool_name -> {field: new_value})"
    )

    rationale: str = Field(description="Explanation for recommendations")
    expected_improvement: float = Field(
        ge=0.0, le=1.0, description="Expected improvement in effectiveness"
    )

    based_on_sessions: List[str] = Field(description="Sessions used for analysis")
    strategy_used: OptimizationStrategy = Field(description="Strategy used for optimization")


class AttackerProfile(BaseModel):
    """Profile of attacker behavior for personalized tools."""

    session_id: str = Field(description="Session identifier")

    tool_preferences: List[str] = Field(description="Tools this attacker prefers")
    attack_sequence: List[str] = Field(description="Typical attack sequence")
    timing_pattern: str = Field(description="Attack timing: rapid, methodical, sporadic")

    sophistication_score: float = Field(
        ge=0.0, le=1.0, description="Estimated sophistication level"
    )
    tool_diversity: int = Field(description="Number of different tools used")
    uses_automation: bool = Field(
        default=False, description="Whether attacker appears to use automation"
    )

    recommended_tools: List[str] = Field(description="Tools likely to attract this attacker")
    bait_chain: List[str] = Field(
        default_factory=list, description="Sequence of tools to lead attacker deeper"
    )

    created_at: datetime = Field(description="Profile creation time")
    last_updated: datetime = Field(description="Last profile update")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in profile accuracy")


class ABTestVariant(BaseModel):
    """A/B test variant for tool descriptions."""

    variant_id: str = Field(description="Variant identifier")
    tool_name: str = Field(description="Tool being tested")

    description: str = Field(description="Tool description for this variant")
    parameters: Dict[str, str] = Field(default_factory=dict, description="Parameter descriptions")

    impressions: int = Field(default=0, description="Number of times shown to attackers")
    triggers: int = Field(default=0, description="Number of times triggered")
    conversion_rate: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Trigger rate (triggers / impressions)"
    )

    created_at: datetime = Field(description="Variant creation time")
    is_control: bool = Field(default=False, description="Whether this is the control variant")


class ABTest(BaseModel):
    """A/B test for tool effectiveness."""

    test_id: str = Field(description="Test identifier")
    tool_name: str = Field(description="Tool being tested")

    variants: List[ABTestVariant] = Field(description="Test variants")
    start_time: datetime = Field(description="Test start time")
    end_time: Optional[datetime] = Field(
        default=None, description="Test end time (None if ongoing)"
    )

    winner: Optional[str] = Field(
        default=None, description="Winning variant ID (if test completed)"
    )
    confidence_level: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Statistical confidence in results"
    )

    status: str = Field(default="running", description="Test status: running, completed, cancelled")
    min_sample_size: int = Field(default=100, description="Minimum samples needed per variant")


class CatalogSnapshot(BaseModel):
    """Snapshot of catalog state at a point in time."""

    snapshot_id: str = Field(description="Snapshot identifier")
    timestamp: datetime = Field(description="Snapshot timestamp")

    active_tools: List[str] = Field(description="Active tool names")
    tool_metrics: Dict[str, ToolEffectivenessMetric] = Field(description="Metrics for each tool")

    overall_effectiveness: float = Field(
        ge=0.0, le=1.0, description="Overall catalog effectiveness"
    )
    avg_tool_score: float = Field(ge=0.0, le=1.0, description="Average tool effectiveness score")

    optimization_strategy: OptimizationStrategy = Field(
        description="Strategy in use at snapshot time"
    )
    total_sessions: int = Field(description="Total sessions analyzed")
    total_triggers: int = Field(description="Total tool triggers")
