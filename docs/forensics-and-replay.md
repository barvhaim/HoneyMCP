# Attack Replay & Forensics System

The Attack Replay & Forensics System provides comprehensive tools for analyzing, replaying, and reporting on detected attacks. This feature enables security teams to conduct post-incident analysis, generate compliance reports, and share threat intelligence.

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [Export Formats](#export-formats)
- [Use Cases](#use-cases)
- [Best Practices](#best-practices)

## Overview

The forensics system captures complete attack sequences and provides tools to:

1. **Replay attacks** with timeline control (play, pause, seek, speed)
2. **Generate forensic reports** with executive summaries and recommendations
3. **Export data** in multiple formats (JSON, CSV, HTML, STIX)
4. **Compare sessions** to identify attack patterns and campaigns
5. **Share threat intelligence** using industry-standard formats

## Key Features

### 1. Attack Timeline Generation

Automatically creates detailed timelines from attack events:

```python
from honeymcp.forensics.replay_engine import ReplayEngine

engine = ReplayEngine()

# Create timeline from events
timeline = await engine.create_timeline(events)

print(f"Session: {timeline.session_id}")
print(f"Duration: {timeline.duration_seconds}s")
print(f"Events: {timeline.event_count}")
print(f"Tools used: {timeline.unique_tools_used}")
print(f"Max threat: {timeline.max_threat_level}")
```

**Timeline includes:**
- Chronological event sequence with precise timing
- Tool usage patterns and sequences
- Attack categories and threat levels
- Statistical analysis (avg time between events, tool diversity)

### 2. Interactive Replay

Step through attacks with full playback control:

```python
# Start replay session
replay_id = await engine.start_replay(timeline)

# Play at different speeds
from honeymcp.models.forensics import ReplayControl, ReplaySpeed

# Play at 5x speed
control = ReplayControl(action="play")
await engine.control_replay(replay_id, control)

control = ReplayControl(action="speed", speed=ReplaySpeed.FAST_5X)
await engine.control_replay(replay_id, control)

# Pause
control = ReplayControl(action="pause")
await engine.control_replay(replay_id, control)

# Seek to specific event
control = ReplayControl(action="seek", target_index=5)
await engine.control_replay(replay_id, control)

# Get current state
state = engine.get_state(replay_id)
print(f"Progress: {state.progress_percent:.1f}%")
print(f"Current event: {state.current_event.tool_name}")
```

**Replay features:**
- **Play/Pause/Stop**: Full playback control
- **Speed control**: Realtime, 2x, 5x, 10x, or instant
- **Seek**: Jump to any event in the timeline
- **State tracking**: Monitor progress and current position

### 3. Forensic Report Generation

Generate comprehensive analysis reports:

```python
from honeymcp.forensics.report_generator import ReportGenerator

generator = ReportGenerator()

# Generate report
report = await generator.generate_report(
    timeline=timeline,
    analyst_notes="Sophisticated attack showing knowledge of system internals"
)

print(f"Severity: {report.severity}")
print(f"Attack vector: {report.attack_vector}")
print(f"Techniques: {report.techniques_used}")
print(f"IOCs: {report.indicators_of_compromise}")
print(f"MITRE tactics: {report.mitre_tactics}")
```

**Report includes:**
- **Executive summary**: High-level overview for management
- **Severity assessment**: Automated risk scoring
- **Attack analysis**: Vector identification and technique extraction
- **IOC extraction**: Indicators of compromise for detection
- **MITRE ATT&CK mapping**: Tactics and techniques
- **Recommendations**: Security improvements and mitigation steps

### 4. Session Comparison

Compare multiple attack sessions to identify patterns:

```python
# Compare multiple sessions
comparison = await generator.compare_sessions([timeline1, timeline2, timeline3])

print(f"Common tools: {comparison.common_tools}")
print(f"Common categories: {comparison.common_categories}")
print(f"Sophistication scores: {comparison.sophistication_scores}")
print(f"Analysis: {comparison.analysis}")
```

**Comparison features:**
- Identify common attack patterns
- Find unique tools per session
- Calculate sophistication scores
- Detect coordinated campaigns

### 5. Multi-Format Export

Export data for sharing and analysis:

```python
from honeymcp.forensics.exporters import ForensicsExporter
from honeymcp.models.forensics import ExportFormat

exporter = ForensicsExporter()

# Export timeline as JSON
json_data = await exporter.export_timeline(timeline, ExportFormat.JSON)

# Export as CSV for spreadsheet analysis
csv_data = await exporter.export_timeline(timeline, ExportFormat.CSV)

# Export as HTML for human reading
html_data = await exporter.export_timeline(timeline, ExportFormat.HTML)

# Export as STIX 2.1 for threat intelligence sharing
stix_data = await exporter.export_timeline(timeline, ExportFormat.STIX)

# Export report as HTML
report_html = await exporter.export_report(report, ExportFormat.HTML)
```

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                     Forensics System                         │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Replay     │  │   Report     │  │  Forensics   │      │
│  │   Engine     │  │  Generator   │  │  Exporter    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│         │                  │                  │              │
│         └──────────────────┴──────────────────┘              │
│                            │                                 │
│                    ┌───────▼────────┐                        │
│                    │  Event Store   │                        │
│                    └────────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

### Data Models

**AttackTimeline**: Complete attack sequence with timing and statistics
**ReplaySession**: Active replay state with playback control
**ForensicReport**: Comprehensive analysis with recommendations
**TimelineEvent**: Individual event in attack sequence
**STIXBundle**: STIX 2.1 threat intelligence format

## Quick Start

### 1. Basic Replay

```python
from honeymcp.forensics.replay_engine import ReplayEngine
from honeymcp.storage.event_store import list_events

# Get events for a session
events = await list_events(session_id="session_123")

# Create replay engine
engine = ReplayEngine()

# Create timeline
timeline = await engine.create_timeline(events)

# Start replay
replay_id = await engine.start_replay(timeline)

# Play
from honeymcp.models.forensics import ReplayControl
control = ReplayControl(action="play")
await engine.control_replay(replay_id, control)

# Monitor progress
state = engine.get_state(replay_id)
print(f"Progress: {state.progress_percent:.1f}%")
```

### 2. Generate Report

```python
from honeymcp.forensics.report_generator import ReportGenerator

generator = ReportGenerator()

# Generate report
report = await generator.generate_report(timeline)

# Access report data
print(f"Severity: {report.severity}")
print(f"Summary: {report.summary}")
print(f"Recommendations: {report.recommendations}")
```

### 3. Export Data

```python
from honeymcp.forensics.exporters import ForensicsExporter
from honeymcp.models.forensics import ExportFormat

exporter = ForensicsExporter()

# Export as HTML
html = await exporter.export_report(report, ExportFormat.HTML)

# Save to file
with open("attack_report.html", "w") as f:
    f.write(html)
```

## API Reference

### REST API Endpoints

#### Start Replay

```http
POST /replay/start?session_id=session_123
```

**Response:**
```json
{
  "replay_id": "replay_abc123",
  "session_id": "session_123",
  "event_count": 15,
  "duration_seconds": 120.5
}
```

#### Control Replay

```http
POST /replay/{replay_id}/control
Content-Type: application/json

{
  "action": "play"
}
```

**Actions:**
- `play`: Start playback
- `pause`: Pause playback
- `stop`: Stop and reset to beginning
- `seek`: Jump to event (requires `target_index`)
- `speed`: Change speed (requires `speed`)

**Response:**
```json
{
  "replay_id": "replay_abc123",
  "current_index": 5,
  "total_events": 15,
  "is_playing": true,
  "speed": "2x",
  "progress_percent": 33.3,
  "elapsed_time": 40.2,
  "remaining_time": 80.3
}
```

#### Get Replay State

```http
GET /replay/{replay_id}/state
```

Returns current replay state (same format as control response).

#### Stop Replay

```http
DELETE /replay/{replay_id}
```

#### List Active Replays

```http
GET /replay/active
```

**Response:**
```json
["replay_abc123", "replay_def456"]
```

#### Generate Report

```http
POST /reports/generate?session_id=session_123&analyst_notes=Optional+notes
```

**Response:**
```json
{
  "report_id": "report_xyz789",
  "session_id": "session_123",
  "generated_at": "2024-01-15T10:30:00Z",
  "title": "Attack Analysis: Session session_123",
  "summary": "Attack session detected with 15 malicious attempts...",
  "severity": "high",
  "attack_vector": "Remote Code Execution",
  "techniques_used": ["Command Execution", "Credential Harvesting"],
  "indicators_of_compromise": ["High tool diversity: 8 unique tools"],
  "recommendations": ["Immediate investigation required..."],
  "mitigation_steps": ["1. Block session...", "2. Review logs..."],
  "mitre_tactics": ["TA0002", "TA0006"],
  "mitre_techniques": ["T1059", "T1003"]
}
```

#### Compare Sessions

```http
POST /reports/compare?session_ids=session_1&session_ids=session_2
```

**Response:**
```json
{
  "report_id": "comparison_abc123",
  "session_ids": ["session_1", "session_2"],
  "common_tools": ["list_secrets", "execute_command"],
  "common_categories": ["credential_access", "rce"],
  "unique_tools_per_session": {
    "session_1": ["tool_a"],
    "session_2": ["tool_b"]
  },
  "sophistication_scores": {
    "session_1": 0.75,
    "session_2": 0.82
  },
  "analysis": "Comparison of 2 attack sessions...",
  "similarities": ["Common tools: list_secrets, execute_command"],
  "differences": ["Tool diversity varies: 5-8 tools per session"]
}
```

#### Export Timeline

```http
GET /export/timeline/{session_id}?format=html
```

**Formats:** `json`, `csv`, `html`, `stix`

Returns file download with appropriate content type.

## Export Formats

### JSON

Complete structured data export:

```json
{
  "session_id": "session_123",
  "start_time": "2024-01-15T10:00:00Z",
  "end_time": "2024-01-15T10:02:00Z",
  "duration_seconds": 120.0,
  "events": [
    {
      "timestamp": "2024-01-15T10:00:00Z",
      "elapsed_seconds": 0.0,
      "tool_name": "list_secrets",
      "threat_level": "high",
      "attack_category": "credential_access"
    }
  ],
  "unique_tools_used": ["list_secrets", "execute_command"],
  "max_threat_level": "critical"
}
```

### CSV

Tabular format for spreadsheet analysis:

```csv
Timestamp,Elapsed (s),Event Type,Tool Name,Threat Level,Attack Category,Response
2024-01-15T10:00:00Z,0.00,tool_call,list_secrets,high,credential_access,Access denied
2024-01-15T10:00:05Z,5.00,tool_call,execute_command,critical,rce,Command executed
```

### HTML

Human-readable report with styling:

- Executive summary with key metrics
- Visual timeline with color-coded threat levels
- Statistics and analysis sections
- Responsive design for viewing on any device

### STIX 2.1

Threat intelligence sharing format:

```json
{
  "type": "bundle",
  "id": "bundle--abc123",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--xyz789",
      "name": "HoneyMCP Tool: list_secrets",
      "description": "Honeypot tool 'list_secrets' triggered 3 times",
      "pattern": "[x-honeymcp-tool:name = 'list_secrets']",
      "labels": ["honeypot", "attack-pattern", "high"],
      "confidence": 85
    }
  ]
}
```

## Use Cases

### 1. Post-Incident Analysis

**Scenario:** Security team needs to understand what happened during an attack.

```python
# Get attack events
events = await list_events(session_id=incident_session_id)

# Create timeline
timeline = await engine.create_timeline(events)

# Generate detailed report
report = await generator.generate_report(
    timeline=timeline,
    analyst_notes="Incident #2024-001: Unauthorized access attempt"
)

# Export for documentation
html_report = await exporter.export_report(report, ExportFormat.HTML)
with open(f"incident_{incident_session_id}.html", "w") as f:
    f.write(html_report)
```

### 2. Security Team Training

**Scenario:** Train analysts on real attack patterns.

```python
# Start replay for training session
replay_id = await engine.start_replay(timeline, speed=ReplaySpeed.FAST_2X)

# Trainees can control playback
control = ReplayControl(action="pause")
await engine.control_replay(replay_id, control)

# Discuss current event
state = engine.get_state(replay_id)
print(f"Current attack: {state.current_event.tool_name}")
print(f"Category: {state.current_event.attack_category}")

# Continue training
control = ReplayControl(action="play")
await engine.control_replay(replay_id, control)
```

### 3. Threat Intelligence Sharing

**Scenario:** Share attack patterns with security community.

```python
# Export as STIX for sharing
stix_bundle = await exporter.export_timeline(timeline, ExportFormat.STIX)

# Share with threat intelligence platform
# (e.g., MISP, OpenCTI, ThreatConnect)
await threat_intel_platform.submit(stix_bundle)
```

### 4. Compliance Reporting

**Scenario:** Generate reports for compliance audits.

```python
# Get all attacks in date range
events = await list_events(
    start_date=date(2024, 1, 1),
    end_date=date(2024, 1, 31)
)

# Group by session
sessions = {}
for event in events:
    if event.session_id not in sessions:
        sessions[event.session_id] = []
    sessions[event.session_id].append(event)

# Generate report for each session
reports = []
for session_id, session_events in sessions.items():
    timeline = await engine.create_timeline(session_events)
    report = await generator.generate_report(timeline)
    reports.append(report)

# Export all reports
for report in reports:
    html = await exporter.export_report(report, ExportFormat.HTML)
    with open(f"compliance_report_{report.session_id}.html", "w") as f:
        f.write(html)
```

### 5. Campaign Detection

**Scenario:** Identify coordinated attack campaigns.

```python
# Get recent high-severity sessions
high_severity_sessions = [
    session for session in all_sessions
    if session.max_threat_level in ["high", "critical"]
]

# Create timelines
timelines = []
for session_events in high_severity_sessions:
    timeline = await engine.create_timeline(session_events)
    timelines.append(timeline)

# Compare to find patterns
comparison = await generator.compare_sessions(timelines)

if len(comparison.common_tools) >= 3:
    print("⚠️ Potential coordinated campaign detected!")
    print(f"Common tools: {comparison.common_tools}")
    print(f"Affected sessions: {len(timelines)}")
```

## Best Practices

### 1. Regular Report Generation

Generate reports for all high-severity attacks:

```python
# Automated report generation
async def generate_reports_for_high_severity():
    events = await list_events()
    
    # Group by session
    sessions = {}
    for event in events:
        if event.threat_level in ["high", "critical"]:
            if event.session_id not in sessions:
                sessions[event.session_id] = []
            sessions[event.session_id].append(event)
    
    # Generate reports
    for session_id, session_events in sessions.items():
        timeline = await engine.create_timeline(session_events)
        report = await generator.generate_report(timeline)
        
        # Store or send report
        await store_report(report)
```

### 2. Cleanup Old Replays

Prevent memory leaks by cleaning up inactive replays:

```python
# Run periodically (e.g., hourly)
await engine.cleanup_old_sessions(max_age_hours=24)
```

### 3. Export for Archival

Regularly export data for long-term storage:

```python
# Weekly export
async def weekly_export():
    events = await list_events(
        start_date=last_week_start,
        end_date=last_week_end
    )
    
    # Export as JSON for archival
    for session_id in unique_sessions:
        session_events = [e for e in events if e.session_id == session_id]
        timeline = await engine.create_timeline(session_events)
        
        json_data = await exporter.export_timeline(timeline, ExportFormat.JSON)
        
        # Store in archive
        await archive_storage.save(f"{session_id}.json", json_data)
```

### 4. Integrate with Alerting

Automatically generate reports for critical attacks:

```python
# In your alerting system
async def on_critical_attack(session_id: str):
    # Generate report
    events = await list_events(session_id=session_id)
    timeline = await engine.create_timeline(events)
    report = await generator.generate_report(timeline)
    
    # Send to security team
    html_report = await exporter.export_report(report, ExportFormat.HTML)
    await send_email(
        to="security-team@company.com",
        subject=f"Critical Attack Detected: {session_id}",
        body=html_report,
        html=True
    )
```

### 5. Performance Considerations

For large timelines, use pagination and filtering:

```python
# For very long attack sessions
if timeline.event_count > 1000:
    # Use instant speed for initial review
    replay_id = await engine.start_replay(timeline, speed=ReplaySpeed.INSTANT)
    
    # Then seek to interesting events
    high_threat_indices = [
        i for i, event in enumerate(timeline.events)
        if event.threat_level == "critical"
    ]
    
    for index in high_threat_indices:
        control = ReplayControl(action="seek", target_index=index)
        await engine.control_replay(replay_id, control)
        # Analyze critical event
```

## Integration Examples

### With Dashboard

```javascript
// Frontend code to control replay
async function startReplay(sessionId) {
  const response = await fetch(`/replay/start?session_id=${sessionId}`, {
    method: 'POST'
  });
  const { replay_id } = await response.json();
  
  // Start playback
  await fetch(`/replay/${replay_id}/control`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'play' })
  });
  
  // Monitor progress
  const interval = setInterval(async () => {
    const state = await fetch(`/replay/${replay_id}/state`).then(r => r.json());
    updateUI(state);
    
    if (!state.is_playing) {
      clearInterval(interval);
    }
  }, 1000);
}
```

### With Slack

```python
# Send forensic reports to Slack
async def send_report_to_slack(report: ForensicReport):
    html_report = await exporter.export_report(report, ExportFormat.HTML)
    
    # Upload to Slack
    await slack_client.files_upload(
        channels="#security-incidents",
        file=html_report.encode(),
        filename=f"attack_report_{report.session_id}.html",
        title=report.title,
        initial_comment=f"🚨 {report.severity.upper()} severity attack detected\n{report.summary}"
    )
```

## Troubleshooting

### Replay Not Advancing

**Issue:** Replay session stuck at same event.

**Solution:**
```python
# Check if replay is actually playing
state = engine.get_state(replay_id)
if not state.is_playing:
    control = ReplayControl(action="play")
    await engine.control_replay(replay_id, control)

# Check speed setting
if state.speed == ReplaySpeed.REALTIME and timeline.duration_seconds > 3600:
    # Use faster speed for long sessions
    control = ReplayControl(action="speed", speed=ReplaySpeed.FAST_10X)
    await engine.control_replay(replay_id, control)
```

### Export Fails

**Issue:** Export produces empty or invalid output.

**Solution:**
```python
# Verify timeline has events
if timeline.event_count == 0:
    raise ValueError("Cannot export empty timeline")

# Check format support
supported_formats = [ExportFormat.JSON, ExportFormat.CSV, ExportFormat.HTML, ExportFormat.STIX]
if format not in supported_formats:
    raise ValueError(f"Unsupported format: {format}")
```

### Memory Issues with Large Sessions

**Issue:** Large attack sessions consume too much memory.

**Solution:**
```python
# Process in chunks
CHUNK_SIZE = 100

for i in range(0, len(events), CHUNK_SIZE):
    chunk = events[i:i+CHUNK_SIZE]
    # Process chunk
    timeline = await engine.create_timeline(chunk)
    # Export immediately
    await exporter.export_timeline(timeline, ExportFormat.JSON)
```

## Future Enhancements

Planned features for future releases:

1. **Video Export**: Generate video replays of attacks
2. **Interactive Dashboards**: Real-time replay visualization
3. **ML-Based Analysis**: Automated attack classification
4. **Collaborative Analysis**: Multi-analyst review and annotation
5. **Integration APIs**: Direct integration with SIEM platforms

## Related Documentation

- [Pattern Analysis](./pattern-analysis.md) - Detect coordinated attacks
- [Streaming & Alerting](./streaming-and-alerting.md) - Real-time notifications
- [Session Backends](./session-backends.md) - Persistent storage options
- [API Reference](./api-reference.md) - Complete API documentation

## Support

For questions or issues:
- GitHub Issues: https://github.com/yourusername/honeymcp/issues
- Documentation: https://honeymcp.readthedocs.io
- Community: https://discord.gg/honeymcp
