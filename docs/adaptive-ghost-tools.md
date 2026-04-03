# Adaptive Ghost Tool System

The Adaptive Ghost Tool System enables HoneyMCP to automatically optimize its honeypot catalog based on real-world attacker behavior. This self-improving system learns which tools are most effective at attracting and fingerprinting attackers, then adapts the catalog accordingly.

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Optimization Strategies](#optimization-strategies)
- [Use Cases](#use-cases)
- [Best Practices](#best-practices)

## Overview

The adaptive system consists of three main components:

1. **Effectiveness Tracker**: Monitors tool performance in real-time
2. **Catalog Optimizer**: Analyzes metrics and recommends catalog changes
3. **Attacker Profiler**: Profiles attacker behavior for personalized honeypots

Together, these components create a self-optimizing defense system that improves over time.

## Key Features

### 1. Real-Time Effectiveness Tracking

Track multi-dimensional effectiveness metrics for each ghost tool:

```python
from honeymcp.adaptive.effectiveness_tracker import EffectivenessTracker

tracker = EffectivenessTracker()

# Record tool triggers
await tracker.record_trigger(attack_event)

# Get metrics
metric = tracker.get_metric("list_secrets")
print(f"Overall score: {metric.overall_score}")
print(f"Attractiveness: {metric.attractiveness_score}")
print(f"Detection: {metric.detection_score}")
print(f"Engagement: {metric.engagement_score}")
```

**Metrics tracked:**
- **Trigger count**: How often the tool is used
- **Unique sessions**: Number of different attackers
- **Time to trigger**: How quickly attackers find it
- **Threat detection**: Ratio of high-threat triggers
- **Effectiveness scores**: Multi-dimensional scoring (0.0-1.0)

### 2. Intelligent Catalog Optimization

Automatically optimize your honeypot catalog:

```python
from honeymcp.adaptive.catalog_optimizer import CatalogOptimizer
from honeymcp.models.adaptive_tools import (
    CatalogOptimizationConfig,
    OptimizationStrategy,
)

# Configure optimizer
config = CatalogOptimizationConfig(
    strategy=OptimizationStrategy.BALANCED,
    min_tools=5,
    max_tools=20,
    min_score_threshold=0.3,
    auto_retire_enabled=True,
)

optimizer = CatalogOptimizer(tracker, config)

# Analyze catalog
recommendation = await optimizer.analyze_catalog(current_tools)

print(f"Tools to add: {recommendation.tools_to_add}")
print(f"Tools to remove: {recommendation.tools_to_remove}")
print(f"Rationale: {recommendation.rationale}")
```

**Optimization features:**
- Automatic tool promotion/retirement
- Multiple optimization strategies
- Catalog size management
- Historical snapshot tracking
- Impact prediction

### 3. Attacker Profiling

Profile attacker behavior for personalized honeypots:

```python
from honeymcp.adaptive.attacker_profiler import AttackerProfiler

profiler = AttackerProfiler()

# Analyze session
profile = await profiler.analyze_session(session_id, events)

print(f"Sophistication: {profile.sophistication_score}")
print(f"Tool preferences: {profile.tool_preferences}")
print(f"Timing pattern: {profile.timing_pattern}")
print(f"Uses automation: {profile.uses_automation}")

# Get personalized recommendations
print(f"Recommended tools: {profile.recommended_tools}")
print(f"Bait chain: {profile.bait_chain}")
```

**Profiling features:**
- Sophistication scoring
- Tool preference learning
- Attack sequence detection
- Automation detection
- Campaign identification

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Adaptive Ghost Tool System                  │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────┐│
│  │  Effectiveness   │  │    Catalog       │  │  Attacker  ││
│  │    Tracker       │──│   Optimizer      │──│  Profiler  ││
│  └──────────────────┘  └──────────────────┘  └────────────┘│
│           │                     │                    │       │
│           └─────────────────────┴────────────────────┘       │
│                            │                                 │
│                    ┌───────▼────────┐                        │
│                    │  Attack Events │                        │
│                    └────────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Attack occurs** → Event recorded
2. **Tracker updates** → Metrics calculated
3. **Profiler analyzes** → Attacker behavior learned
4. **Optimizer evaluates** → Recommendations generated
5. **Catalog adapts** → Tools added/removed

## Quick Start

### 1. Enable Adaptive System

```python
from honeymcp.adaptive import (
    EffectivenessTracker,
    CatalogOptimizer,
    AttackerProfiler,
)

# Initialize components
tracker = EffectivenessTracker()
optimizer = CatalogOptimizer(tracker)
profiler = AttackerProfiler()

# Store in app state for API access
app.state.effectiveness_tracker = tracker
app.state.catalog_optimizer = optimizer
app.state.attacker_profiler = profiler
```

### 2. Record Attack Events

```python
# When attack is detected
await tracker.record_trigger(attack_event)

# Optionally profile the attacker
events = await get_session_events(session_id)
profile = await profiler.analyze_session(session_id, events)
```

### 3. Get Optimization Recommendations

```python
# Analyze current catalog
from honeymcp.core.ghost_tools import list_ghost_tools

current_tools = list_ghost_tools()
recommendation = await optimizer.analyze_catalog(current_tools)

# Review recommendations
print(f"Recommendation: {recommendation.rationale}")
print(f"Expected improvement: {recommendation.expected_improvement:.1%}")

# Apply if desired
updated_tools = await optimizer.apply_recommendation(
    recommendation,
    current_tools
)
```

### 4. Monitor Performance

```python
# Get statistics
stats = await tracker.get_statistics()
print(f"Total tools: {stats['total_tools']}")
print(f"Average score: {stats['avg_score']:.2f}")
print(f"Best tool: {stats['best_tool']['name']}")

# Get top performers
top_tools = tracker.get_top_tools(n=5)
for tool in top_tools:
    print(f"{tool.tool_name}: {tool.overall_score:.2f}")
```

## API Reference

### REST API Endpoints

#### Get Effectiveness Metrics

```http
GET /adaptive/metrics
GET /adaptive/metrics?tool_name=list_secrets
```

**Response:**
```json
{
  "metrics": {
    "list_secrets": {
      "tool_name": "list_secrets",
      "trigger_count": 15,
      "unique_sessions": 5,
      "attractiveness_score": 0.75,
      "detection_score": 0.85,
      "engagement_score": 0.70,
      "overall_score": 0.77
    }
  },
  "statistics": {
    "total_tools": 10,
    "avg_score": 0.65,
    "best_tool": {"name": "list_secrets", "score": 0.77}
  }
}
```

#### Get Top Tools

```http
GET /adaptive/top-tools?n=5
```

**Response:**
```json
[
  {
    "tool_name": "list_secrets",
    "overall_score": 0.77,
    "trigger_count": 15
  },
  {
    "tool_name": "execute_command",
    "overall_score": 0.72,
    "trigger_count": 12
  }
]
```

#### Get Catalog Recommendations

```http
GET /adaptive/recommendations
```

**Response:**
```json
{
  "recommendation_id": "rec_abc123",
  "tools_to_add": ["new_admin_tool"],
  "tools_to_remove": ["low_performing_tool"],
  "rationale": "Remove 'low_performing_tool' (score: 0.15); Add tools to meet minimum",
  "expected_improvement": 0.12,
  "strategy_used": "balanced"
}
```

#### Create Catalog Snapshot

```http
POST /adaptive/snapshot
```

**Response:**
```json
{
  "snapshot_id": "snap_xyz789",
  "timestamp": "2024-01-15T10:00:00Z",
  "active_tools": ["list_secrets", "execute_command"],
  "overall_effectiveness": 0.68,
  "total_triggers": 150
}
```

#### Get Attacker Profile

```http
GET /adaptive/profiles/{session_id}
POST /adaptive/profiles/{session_id}/analyze
```

**Response:**
```json
{
  "session_id": "session_123",
  "sophistication_score": 0.75,
  "tool_preferences": ["list_secrets", "execute_command"],
  "timing_pattern": "methodical",
  "uses_automation": false,
  "recommended_tools": ["get_api_keys", "dump_credentials"],
  "bait_chain": ["access_database", "execute_query", "admin_panel"]
}
```

#### Identify Campaigns

```http
GET /adaptive/campaigns
```

**Response:**
```json
[
  {
    "campaign_id": "campaign_1",
    "sessions": ["session_1", "session_2", "session_3"],
    "session_count": 3,
    "sophistication": 0.82,
    "common_tools": ["list_secrets", "execute_command"]
  }
]
```

## Optimization Strategies

### 1. Balanced Strategy

Balances all metrics equally for well-rounded catalog:

```python
config = CatalogOptimizationConfig(
    strategy=OptimizationStrategy.BALANCED,
    min_score_threshold=0.3,
)
```

**Best for:**
- General-purpose deployments
- Diverse threat landscape
- Initial setup

**Scoring weights:**
- Attractiveness: 40%
- Detection: 40%
- Engagement: 20%

### 2. Detection-Focused Strategy

Prioritizes tools with high threat detection rates:

```python
config = CatalogOptimizationConfig(
    strategy=OptimizationStrategy.DETECTION_FOCUSED,
)
```

**Best for:**
- High-security environments
- Compliance requirements
- Threat intelligence gathering

**Behavior:**
- Removes tools with detection score < 0.5
- Keeps high-threat-detecting tools
- Optimizes for threat identification

### 3. Engagement-Focused Strategy

Prioritizes tools that keep attackers engaged:

```python
config = CatalogOptimizationConfig(
    strategy=OptimizationStrategy.ENGAGEMENT_FOCUSED,
)
```

**Best for:**
- Research environments
- Attacker behavior analysis
- Long-term monitoring

**Behavior:**
- Removes tools with engagement score < 0.4
- Keeps tools attackers interact with
- Optimizes for attacker retention

### 4. Adaptive Strategy

Automatically adapts based on current performance:

```python
config = CatalogOptimizationConfig(
    strategy=OptimizationStrategy.ADAPTIVE,
)
```

**Best for:**
- Dynamic environments
- Evolving threats
- Hands-off operation

**Behavior:**
- Switches strategies based on metrics
- Low performance → Detection-focused
- Good performance → Engagement-focused
- Balanced otherwise

## Use Cases

### 1. Automatic Catalog Optimization

**Scenario:** Maintain optimal honeypot catalog automatically.

```python
# Run periodically (e.g., daily)
async def optimize_catalog():
    # Get current tools
    current_tools = list_ghost_tools()
    
    # Create snapshot before changes
    snapshot_before = await optimizer.create_snapshot(current_tools)
    
    # Get recommendation
    recommendation = await optimizer.analyze_catalog(current_tools)
    
    # Predict impact
    impact = await optimizer.predict_impact(recommendation, current_tools)
    
    if impact["predicted_improvement"] > 0.05:  # 5% improvement
        # Apply recommendation
        updated_tools = await optimizer.apply_recommendation(
            recommendation,
            current_tools
        )
        
        # Create snapshot after changes
        snapshot_after = await optimizer.create_snapshot(updated_tools)
        
        # Log changes
        logger.info(
            "Catalog optimized: %d tools removed, %d added, %.1f%% improvement",
            len(recommendation.tools_to_remove),
            len(recommendation.tools_to_add),
            impact["predicted_improvement"] * 100
        )
```

### 2. Personalized Honeypots

**Scenario:** Generate custom honeypots for specific attackers.

```python
async def generate_personalized_tools(session_id: str):
    # Get session events
    events = await get_session_events(session_id)
    
    # Profile attacker
    profile = await profiler.analyze_session(session_id, events)
    
    # Generate hint for tool creation
    hint = await profiler.generate_hint(session_id)
    
    if profile.sophistication_score > 0.7:
        # High sophistication - use advanced tools
        tools_to_add = [
            "advanced_privilege_escalation",
            "kernel_exploit",
            "zero_day_simulator"
        ]
    elif profile.uses_automation:
        # Automated attack - use API-focused tools
        tools_to_add = [
            "api_key_generator",
            "bulk_data_export",
            "automated_scanner_trap"
        ]
    else:
        # Use recommended tools from profile
        tools_to_add = profile.recommended_tools
    
    # Add personalized tools to catalog
    for tool_name in tools_to_add:
        add_ghost_tool(tool_name)
    
    logger.info(
        "Added %d personalized tools for session %s (sophistication: %.2f)",
        len(tools_to_add),
        session_id,
        profile.sophistication_score
    )
```

### 3. Campaign Detection

**Scenario:** Identify coordinated attack campaigns.

```python
async def detect_campaigns():
    # Identify campaigns
    campaigns = await profiler.identify_campaigns()
    
    for campaign in campaigns:
        if campaign["session_count"] >= 3:
            # Significant campaign detected
            logger.warning(
                "Campaign detected: %d sessions, sophistication %.2f",
                campaign["session_count"],
                campaign["sophistication"]
            )
            
            # Alert security team
            await send_alert(
                title=f"Attack Campaign Detected: {campaign['campaign_id']}",
                details=f"Coordinated attack across {campaign['session_count']} sessions",
                severity="high"
            )
            
            # Generate specialized honeypots
            for tool in campaign["common_tools"]:
                # Create variations of commonly used tools
                create_tool_variation(tool)
```

### 4. A/B Testing Tools

**Scenario:** Test different tool descriptions for effectiveness.

```python
from honeymcp.models.adaptive_tools import ABTest, ABTestVariant

async def run_ab_test(tool_name: str):
    # Create test variants
    variants = [
        ABTestVariant(
            variant_id="control",
            tool_name=tool_name,
            description="Standard description",
            is_control=True
        ),
        ABTestVariant(
            variant_id="variant_a",
            tool_name=tool_name,
            description="More tempting description with 'admin' keyword"
        ),
        ABTestVariant(
            variant_id="variant_b",
            tool_name=tool_name,
            description="Technical description for sophisticated attackers"
        )
    ]
    
    # Create test
    test = ABTest(
        test_id=f"test_{tool_name}",
        tool_name=tool_name,
        variants=variants,
        start_time=datetime.utcnow(),
        min_sample_size=100
    )
    
    # Run test (implementation would rotate variants)
    # ...
    
    # Analyze results
    winner = max(variants, key=lambda v: v.conversion_rate)
    
    logger.info(
        "A/B test complete: Winner is %s with %.1f%% conversion",
        winner.variant_id,
        winner.conversion_rate * 100
    )
```

### 5. Performance Monitoring

**Scenario:** Monitor and report on catalog effectiveness.

```python
async def generate_performance_report():
    # Get statistics
    stats = await tracker.get_statistics()
    
    # Get top and bottom performers
    top_tools = tracker.get_top_tools(n=5)
    bottom_tools = tracker.get_bottom_tools(n=5)
    
    # Get recent snapshots
    snapshots = optimizer.get_snapshots(limit=7)  # Last week
    
    # Calculate trends
    if len(snapshots) >= 2:
        effectiveness_trend = (
            snapshots[0].overall_effectiveness -
            snapshots[-1].overall_effectiveness
        )
    else:
        effectiveness_trend = 0.0
    
    # Generate report
    report = {
        "summary": {
            "total_tools": stats["total_tools"],
            "avg_score": stats["avg_score"],
            "total_triggers": stats["total_triggers"],
            "effectiveness_trend": effectiveness_trend
        },
        "top_performers": [
            {"name": t.tool_name, "score": t.overall_score}
            for t in top_tools
        ],
        "needs_improvement": [
            {"name": t.tool_name, "score": t.overall_score}
            for t in bottom_tools
        ],
        "recommendations": "Consider retiring low-performing tools"
        if stats["score_distribution"]["low"] > 3
        else "Catalog performing well"
    }
    
    return report
```

## Best Practices

### 1. Regular Optimization

Run optimization periodically but not too frequently:

```python
# Good: Daily optimization
schedule.every().day.at("02:00").do(optimize_catalog)

# Bad: Continuous optimization (too frequent)
# while True:
#     optimize_catalog()
```

**Recommended frequency:**
- High-traffic: Daily
- Medium-traffic: Weekly
- Low-traffic: Monthly

### 2. Gradual Changes

Don't remove too many tools at once:

```python
config = CatalogOptimizationConfig(
    min_tools=5,  # Always keep minimum
    max_tools=20,  # Don't grow too large
    min_score_threshold=0.3,  # Not too aggressive
)
```

### 3. Monitor Impact

Always track the impact of changes:

```python
# Before optimization
snapshot_before = await optimizer.create_snapshot(current_tools)

# Apply changes
# ...

# After optimization
snapshot_after = await optimizer.create_snapshot(updated_tools)

# Compare
comparison = await optimizer.compare_snapshots(
    snapshot_before.snapshot_id,
    snapshot_after.snapshot_id
)

if comparison["changes"]["improvement"]:
    logger.info("Optimization successful!")
else:
    logger.warning("Optimization did not improve effectiveness")
```

### 4. Combine with Manual Review

Use adaptive system as guidance, not automation:

```python
# Get recommendation
recommendation = await optimizer.analyze_catalog(current_tools)

# Review before applying
if recommendation.expected_improvement > 0.1:
    # Significant improvement - review carefully
    await send_notification(
        "Catalog optimization recommended",
        recommendation.rationale
    )
    # Wait for manual approval
else:
    # Minor improvement - auto-apply
    await optimizer.apply_recommendation(recommendation, current_tools)
```

### 5. Profile High-Value Targets

Focus profiling on sophisticated attackers:

```python
async def profile_if_sophisticated(session_id: str, events: List):
    # Quick sophistication check
    unique_tools = len(set(e.ghost_tool_called for e in events))
    high_threat = sum(1 for e in events if e.threat_level in ["high", "critical"])
    
    if unique_tools >= 5 or high_threat >= 3:
        # Sophisticated attacker - full profile
        profile = await profiler.analyze_session(session_id, events)
        
        # Generate personalized tools
        hint = await profiler.generate_hint(session_id)
        # ...
```

## Configuration Reference

### CatalogOptimizationConfig

```python
from honeymcp.models.adaptive_tools import CatalogOptimizationConfig

config = CatalogOptimizationConfig(
    strategy=OptimizationStrategy.BALANCED,  # Optimization strategy
    min_tools=5,  # Minimum tools to maintain
    max_tools=20,  # Maximum tools to maintain
    min_score_threshold=0.3,  # Minimum score to keep tool
    promotion_threshold=0.7,  # Score to promote tool
    evaluation_window_hours=24,  # Hours of data to consider
    auto_retire_enabled=True,  # Auto-retire low performers
    auto_generate_enabled=True,  # Auto-generate new tools
)
```

### Effectiveness Scoring

**Attractiveness Score (0.0-1.0):**
- Based on trigger frequency and unique sessions
- Higher = more attractive to attackers

**Detection Score (0.0-1.0):**
- Based on ratio of high-threat triggers
- Higher = better at detecting threats

**Engagement Score (0.0-1.0):**
- Based on time to trigger
- Higher = attackers find it quickly

**Overall Score (0.0-1.0):**
- Weighted average: 40% attractiveness, 40% detection, 20% engagement

## Troubleshooting

### Low Effectiveness Scores

**Issue:** All tools have low scores.

**Solutions:**
1. Check if enough data collected (need multiple attacks)
2. Review tool descriptions - make them more tempting
3. Adjust scoring thresholds
4. Switch to detection-focused strategy

### Tools Not Being Retired

**Issue:** Low-performing tools remain in catalog.

**Solutions:**
```python
# Check configuration
config = optimizer.get_config()
print(f"Auto-retire enabled: {config.auto_retire_enabled}")
print(f"Min threshold: {config.min_score_threshold}")

# Lower threshold if needed
config.min_score_threshold = 0.2
optimizer.update_config(config)
```

### Profiles Not Generated

**Issue:** Attacker profiles not being created.

**Solutions:**
```python
# Check if events exist
events = await get_session_events(session_id)
print(f"Events found: {len(events)}")

# Manually trigger profiling
if events:
    profile = await profiler.analyze_session(session_id, events)
```

## Future Enhancements

Planned features:

1. **ML-Based Optimization**: Use machine learning for smarter recommendations
2. **Real-Time Adaptation**: Adjust tools during active attacks
3. **Cross-Deployment Learning**: Share effectiveness data across deployments
4. **Automated Tool Generation**: Generate new tools based on patterns
5. **Integration with Threat Intel**: Incorporate external threat data

## Related Documentation

- [Pattern Analysis](./pattern-analysis.md) - Detect attack patterns
- [Forensics & Replay](./forensics-and-replay.md) - Analyze attacks
- [Streaming & Alerting](./streaming-and-alerting.md) - Real-time notifications
- [API Reference](./api-reference.md) - Complete API docs

## Support

For questions or issues:
- GitHub Issues: https://github.com/yourusername/honeymcp/issues
- Documentation: https://honeymcp.readthedocs.io
- Community: https://discord.gg/honeymcp
