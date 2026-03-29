# Attack Pattern Analysis & Correlation

HoneyMCP includes a sophisticated pattern analysis engine that correlates attack events to detect coordinated attacks, campaigns, anomalies, and build attacker profiles.

## Overview

The pattern analysis system transforms individual attack events into actionable threat intelligence by:
- **Detecting coordinated attacks** across multiple sessions
- **Identifying attack campaigns** with sustained activity
- **Finding anomalies** using statistical analysis
- **Building attacker profiles** with behavioral fingerprinting

## Pattern Types

### 1. Coordinated Attacks

**Definition**: Multiple unique sessions attacking within the same time window using similar tools.

**Detection Criteria**:
- Minimum 3 sessions (configurable) attacking within 1-hour window
- Sessions use common ghost tools
- Attack timing suggests coordination

**Example**:
```json
{
  "pattern_type": "coordinated",
  "confidence": 0.85,
  "session_ids": ["sess_a", "sess_b", "sess_c"],
  "characteristics": {
    "session_count": 3,
    "common_tools": ["list_cloud_secrets"],
    "time_window": "15 minutes"
  },
  "severity": "high"
}
```

**Indicators**:
- Multiple sessions from different sources
- Synchronized timing (within minutes)
- Identical or similar tool usage
- Suggests organized attack or botnet

### 2. Attack Campaigns

**Definition**: Sustained attack activity from a single session over an extended period.

**Detection Criteria**:
- Minimum 24 hours duration (configurable)
- Minimum 5 attack attempts (configurable)
- Demonstrates persistence and determination

**Example**:
```json
{
  "pattern_type": "campaign",
  "confidence": 0.92,
  "session_ids": ["sess_persistent"],
  "characteristics": {
    "duration_hours": 48.5,
    "total_attempts": 25,
    "unique_tools": ["list_cloud_secrets", "execute_shell_command", "dump_database_credentials"],
    "attack_velocity": 0.52
  },
  "severity": "critical"
}
```

**Indicators**:
- Long duration (days or weeks)
- Multiple attack attempts
- Tool progression and learning
- Suggests targeted attack or APT

### 3. Anomalies

**Definition**: Unusual patterns detected through statistical analysis of tool usage.

**Detection Criteria**:
- Tool usage >3 standard deviations from mean
- Requires minimum 10 events for statistical significance
- Indicates unexpected attacker behavior

**Example**:
```json
{
  "pattern_type": "anomaly",
  "confidence": 0.78,
  "characteristics": {
    "tool": "dump_ml_model_weights",
    "usage_count": 45,
    "expected_count": 8,
    "deviation": 4.2,
    "percentage_of_total": 35.7
  },
  "severity": "medium"
}
```

**Indicators**:
- Specific tool heavily targeted
- Unusual tool combinations
- Unexpected attack patterns
- May indicate new attack technique

### 4. Attacker Profiles

**Definition**: Behavioral fingerprint of an attacker based on their techniques and patterns.

**Profile Components**:
- **Attack Statistics**: Total attempts, velocity, duration
- **Tool Usage**: Unique tools, preferred categories
- **Sophistication Score**: 0.0-1.0 based on techniques
- **Behavioral Fingerprint**: Unique characteristics

**Example**:
```json
{
  "profile_id": "profile_sess_abc123",
  "total_attacks": 15,
  "sophistication_score": 0.72,
  "attack_velocity": 7.5,
  "behavioral_fingerprint": {
    "tool_sequence": ["list_cloud_secrets", "execute_shell_command"],
    "most_used_tool": "list_cloud_secrets",
    "attack_pattern": "persistent"
  }
}
```

**Sophistication Scoring**:
- **Tool Diversity** (40%): More unique tools = higher score
- **Category Diversity** (30%): Multiple attack types = higher score
- **Persistence** (30%): More attempts = higher score

## API Endpoints

### Get All Patterns

```http
GET /patterns?pattern_type=coordinated&min_confidence=0.7
```

**Query Parameters**:
- `pattern_type` (optional): Filter by type (coordinated, campaign, anomaly)
- `min_confidence` (optional): Minimum confidence score (0.0-1.0)
- `start_date` (optional): Filter events from this date
- `end_date` (optional): Filter events until this date

**Response**:
```json
[
  {
    "pattern_id": "coord_2026-03-28T12:00:00_abc123",
    "pattern_type": "coordinated",
    "confidence": 0.85,
    "event_ids": ["evt_001", "evt_002", "evt_003"],
    "session_ids": ["sess_a", "sess_b", "sess_c"],
    "first_seen": "2026-03-28T12:00:00Z",
    "last_seen": "2026-03-28T12:15:00Z",
    "characteristics": {...},
    "severity": "high",
    "description": "Coordinated attack detected...",
    "recommendations": [...]
  }
]
```

### Get Pattern Summary

```http
GET /patterns/summary
```

**Response**:
```json
{
  "total_patterns": 15,
  "by_type": {
    "coordinated": 5,
    "campaign": 3,
    "anomaly": 7
  },
  "by_severity": {
    "critical": 2,
    "high": 6,
    "medium": 7
  },
  "high_confidence_count": 8,
  "recent_patterns": [...]
}
```

### Get Attacker Profile

```http
GET /profiles/{session_id}
```

**Response**:
```json
{
  "profile_id": "profile_sess_abc123",
  "session_ids": ["sess_abc123"],
  "total_attacks": 15,
  "unique_tools_used": ["list_cloud_secrets", "execute_shell_command"],
  "attack_categories": {
    "exfiltration": 10,
    "rce": 5
  },
  "first_seen": "2026-03-28T10:00:00Z",
  "last_seen": "2026-03-28T12:00:00Z",
  "attack_velocity": 7.5,
  "sophistication_score": 0.72,
  "behavioral_fingerprint": {...}
}
```

### Get All Profiles

```http
GET /profiles?min_sophistication=0.5&limit=50
```

**Query Parameters**:
- `min_sophistication` (optional): Minimum sophistication score
- `start_date` (optional): Filter events from this date
- `end_date` (optional): Filter events until this date
- `limit` (optional): Maximum profiles to return (default: 50)

## Configuration

### Pattern Detector Settings

```python
from honeymcp.analysis.pattern_detector import PatternDetector

detector = PatternDetector(
    time_window_minutes=60,           # Time window for coordinated attacks
    coordinated_threshold=3,          # Min sessions for coordination
    campaign_min_duration_hours=24,   # Min duration for campaigns
    campaign_min_events=5,            # Min events for campaigns
)
```

### Via YAML Configuration

```yaml
# honeymcp.yaml
pattern_analysis:
  enabled: true
  time_window_minutes: 60
  coordinated_threshold: 3
  campaign_min_duration_hours: 24
  campaign_min_events: 5
```

## Usage Examples

### Python API

```python
from honeymcp.analysis.pattern_detector import PatternDetector
from honeymcp.storage.event_store import list_events

# Load events
events = await list_events()

# Initialize detector
detector = PatternDetector()

# Detect coordinated attacks
coordinated = await detector.detect_coordinated_attacks(events)
for pattern in coordinated:
    print(f"Coordinated attack: {len(pattern.session_ids)} sessions")
    print(f"Confidence: {pattern.confidence:.2f}")
    print(f"Tools: {pattern.characteristics['common_tools']}")

# Detect campaigns
campaigns = await detector.detect_attack_campaigns(events)
for pattern in campaigns:
    print(f"Campaign: {pattern.characteristics['duration_hours']:.1f} hours")
    print(f"Attempts: {pattern.characteristics['total_attempts']}")

# Detect anomalies
anomalies = await detector.detect_anomalies(events)
for pattern in anomalies:
    print(f"Anomaly: {pattern.characteristics['tool']}")
    print(f"Usage: {pattern.characteristics['usage_count']} times")

# Build attacker profile
profile = await detector.build_attacker_profile("sess_123", events)
print(f"Sophistication: {profile.sophistication_score:.2f}")
print(f"Velocity: {profile.attack_velocity:.1f} attacks/hour")

# Run all analyses
results = await detector.analyze_all(events)
print(f"Coordinated: {len(results['coordinated'])}")
print(f"Campaigns: {len(results['campaigns'])}")
print(f"Anomalies: {len(results['anomalies'])}")
```

### Dashboard Integration

The pattern analysis results are automatically available in the dashboard:

1. **Patterns Tab**: View all detected patterns with filtering
2. **Campaigns Tab**: Track ongoing attack campaigns
3. **Profiles Tab**: Browse attacker behavioral profiles
4. **Anomalies Tab**: Review unusual patterns

## Interpretation Guide

### Coordinated Attacks

**High Confidence (>0.8)**:
- Multiple sessions (5+) within tight time window (<30 min)
- Identical tool usage across sessions
- **Action**: Immediate investigation, consider IP blocking

**Medium Confidence (0.5-0.8)**:
- 3-4 sessions within 1-hour window
- Similar but not identical tools
- **Action**: Monitor closely, review logs

**Low Confidence (<0.5)**:
- May be coincidental
- **Action**: Note for future correlation

### Attack Campaigns

**Critical Severity**:
- Duration >48 hours OR >15 attempts
- Shows tool progression and learning
- **Action**: Permanent block, threat intelligence sharing

**High Severity**:
- Duration 24-48 hours OR 10-15 attempts
- Demonstrates persistence
- **Action**: Enhanced monitoring, consider blocking

**Medium Severity**:
- Duration <24 hours OR 5-10 attempts
- May be exploratory
- **Action**: Continue monitoring

### Sophistication Scores

**High (>0.7)**:
- Uses 5+ different tools
- Multiple attack categories
- Persistent and methodical
- **Profile**: Advanced attacker, possible APT

**Medium (0.4-0.7)**:
- Uses 3-5 tools
- 2-3 attack categories
- Some persistence
- **Profile**: Skilled attacker, targeted attack

**Low (<0.4)**:
- Uses 1-2 tools
- Single category
- Few attempts
- **Profile**: Script kiddie, automated scanner

## Best Practices

### 1. Regular Analysis

Run pattern analysis regularly to detect emerging threats:

```python
# Daily analysis job
async def daily_analysis():
    yesterday = date.today() - timedelta(days=1)
    events = await list_events(start_date=yesterday)
    
    detector = PatternDetector()
    results = await detector.analyze_all(events)
    
    # Alert on high-confidence patterns
    for pattern in results['coordinated']:
        if pattern.confidence > 0.8:
            send_alert(pattern)
```

### 2. Combine with Other Signals

Pattern analysis is most effective when combined with:
- Network traffic analysis
- Authentication logs
- System logs
- Threat intelligence feeds

### 3. Tune Thresholds

Adjust detection thresholds based on your environment:

```python
# High-security environment (more sensitive)
detector = PatternDetector(
    coordinated_threshold=2,  # Lower threshold
    campaign_min_events=3,    # Fewer events needed
)

# High-traffic environment (less sensitive)
detector = PatternDetector(
    coordinated_threshold=5,  # Higher threshold
    campaign_min_events=10,   # More events needed
)
```

### 4. Investigate High-Confidence Patterns

Always investigate patterns with confidence >0.8:
1. Review all events in the pattern
2. Check client metadata for common indicators
3. Correlate with other security logs
4. Consider blocking or enhanced monitoring

### 5. Build Threat Intelligence

Use attacker profiles to build threat intelligence:
- Track sophisticated attackers over time
- Identify common techniques and tools
- Share profiles with security community
- Update defenses based on observed patterns

## Performance Considerations

### Large Event Sets

For large event sets (>10,000 events), consider:

```python
# Analyze recent events only
recent_events = await list_events(
    start_date=date.today() - timedelta(days=7)
)

# Or batch processing
async def batch_analyze(events, batch_size=1000):
    for i in range(0, len(events), batch_size):
        batch = events[i:i+batch_size]
        results = await detector.analyze_all(batch)
        process_results(results)
```

### Caching

Cache pattern analysis results to avoid recomputation:

```python
from functools import lru_cache
from datetime import date

@lru_cache(maxsize=128)
async def get_daily_patterns(analysis_date: date):
    events = await list_events(start_date=analysis_date, end_date=analysis_date)
    detector = PatternDetector()
    return await detector.analyze_all(events)
```

## Troubleshooting

### No Patterns Detected

**Possible Causes**:
- Insufficient events (need >10 for anomalies)
- Thresholds too high
- Events too dispersed in time

**Solutions**:
- Lower detection thresholds
- Increase time window
- Accumulate more events

### Too Many False Positives

**Possible Causes**:
- Thresholds too low
- Legitimate traffic patterns
- Testing/development activity

**Solutions**:
- Raise detection thresholds
- Use allowlist for known sessions
- Filter out development environments

### Low Confidence Scores

**Possible Causes**:
- Weak correlation signals
- Noisy data
- Insufficient context

**Solutions**:
- Collect more events
- Improve event quality
- Adjust confidence calculation weights

## API Reference

### PatternDetector Class

```python
class PatternDetector:
    def __init__(
        self,
        time_window_minutes: int = 60,
        coordinated_threshold: int = 3,
        campaign_min_duration_hours: int = 24,
        campaign_min_events: int = 5,
    ):
        """Initialize pattern detector with configuration."""
    
    async def detect_coordinated_attacks(
        self, events: List[AttackFingerprint]
    ) -> List[AttackPattern]:
        """Detect coordinated attacks across sessions."""
    
    async def detect_attack_campaigns(
        self, events: List[AttackFingerprint]
    ) -> List[AttackPattern]:
        """Detect sustained attack campaigns."""
    
    async def detect_anomalies(
        self, events: List[AttackFingerprint]
    ) -> List[AttackPattern]:
        """Detect anomalous patterns using statistics."""
    
    async def build_attacker_profile(
        self, session_id: str, events: List[AttackFingerprint]
    ) -> AttackerProfile:
        """Build behavioral profile for attacker."""
    
    async def analyze_all(
        self, events: List[AttackFingerprint]
    ) -> Dict[str, List]:
        """Run all detection algorithms."""
```

## Testing

Run pattern detection tests:

```bash
# Test all pattern detection
pytest tests/test_pattern_detection.py -v

# Test specific pattern type
pytest tests/test_pattern_detection.py::TestCoordinatedAttackDetection -v
pytest tests/test_pattern_detection.py::TestCampaignDetection -v
pytest tests/test_pattern_detection.py::TestAnomalyDetection -v
pytest tests/test_pattern_detection.py::TestAttackerProfiling -v
```

## FAQ

**Q: How often should I run pattern analysis?**
A: Run hourly for real-time detection, daily for comprehensive analysis.

**Q: Can I customize confidence scoring?**
A: Yes, modify the weights in the detector implementation.

**Q: How do I export patterns for SIEM integration?**
A: Use the API endpoints to fetch patterns in JSON format.

**Q: What's the difference between campaigns and coordinated attacks?**
A: Campaigns are sustained attacks from one session; coordinated attacks involve multiple sessions.

**Q: How accurate is sophistication scoring?**
A: Scores are relative indicators based on observed behavior, not absolute measures.

**Q: Can patterns overlap?**
A: Yes, a session can be part of both a campaign and coordinated attack.

**Q: How do I reduce false positives?**
A: Increase thresholds, use allowlists, and tune for your environment.

**Q: Are patterns stored persistently?**
A: No, patterns are computed on-demand from stored events.
