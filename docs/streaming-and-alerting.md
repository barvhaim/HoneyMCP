# Real-time Event Streaming & Advanced Alerting

HoneyMCP provides real-time event streaming via Server-Sent Events (SSE) and a sophisticated multi-channel alerting system with rule-based filtering, deduplication, and retry logic.

## Overview

The streaming and alerting system enables:
- **Real-time event streaming** to dashboards and monitoring tools
- **Multi-channel alerting** (Slack, PagerDuty, Email, Webhooks)
- **Rule-based filtering** with flexible conditions
- **Alert deduplication** to prevent notification fatigue
- **Rate limiting** to control alert volume
- **Retry with exponential backoff** for reliable delivery

## Real-time Event Streaming

### Server-Sent Events (SSE)

HoneyMCP uses SSE for one-way server-to-client streaming, providing:
- Automatic reconnection
- Event history for new clients
- Event type filtering
- Low latency updates

### Streaming Endpoint

```http
GET /stream?event_types=attack,pattern&send_history=true
```

**Query Parameters**:
- `event_types` (optional): Comma-separated list (attack, pattern, alert)
- `send_history` (optional): Send historical events first (default: true)

**Response Format**:
```
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive

event: attack
data: {"event_id":"evt_001","session_id":"sess_abc","ghost_tool":"list_cloud_secrets","threat_level":"high","attack_category":"exfiltration","timestamp":"2026-03-29T07:00:00Z"}

event: pattern
data: {"pattern_id":"pattern_001","pattern_type":"coordinated","confidence":0.85,"severity":"high","session_count":3,"description":"Coordinated attack detected","timestamp":"2026-03-29T07:05:00Z"}

event: alert
data: {"alert_id":"alert_001","title":"🚨 Attack Detected","severity":"warning","timestamp":"2026-03-29T07:10:00Z"}

: keepalive
```

### JavaScript Client Example

```javascript
const eventSource = new EventSource('/stream?event_types=attack,pattern');

eventSource.addEventListener('attack', (event) => {
  const data = JSON.parse(event.data);
  console.log('Attack detected:', data);
  updateDashboard(data);
});

eventSource.addEventListener('pattern', (event) => {
  const data = JSON.parse(event.data);
  console.log('Pattern detected:', data);
  showAlert(data);
});

eventSource.onerror = (error) => {
  console.error('Stream error:', error);
  // Browser will automatically reconnect
};
```

### Python Client Example

```python
import asyncio
import aiohttp

async def stream_events():
    async with aiohttp.ClientSession() as session:
        async with session.get('http://localhost:8001/stream') as response:
            async for line in response.content:
                line = line.decode('utf-8').strip()
                
                if line.startswith('event:'):
                    event_type = line.split(':', 1)[1].strip()
                elif line.startswith('data:'):
                    data = line.split(':', 1)[1].strip()
                    print(f"{event_type}: {data}")

asyncio.run(stream_events())
```

### curl Example

```bash
# Stream all events
curl -N http://localhost:8001/stream

# Stream only attacks
curl -N "http://localhost:8001/stream?event_types=attack"

# Stream without history
curl -N "http://localhost:8001/stream?send_history=false"
```

## Advanced Alerting System

### Alert Rules

Alert rules define when and how to send notifications based on events and patterns.

#### Rule Configuration

```python
from honeymcp.models.alerts import AlertRule, AlertChannel, AlertSeverity

rule = AlertRule(
    rule_id="critical_attacks",
    name="Critical Attack Alerts",
    description="Alert on critical threat level attacks",
    enabled=True,
    
    # Trigger conditions
    event_types=["attack"],
    min_threat_level="critical",
    attack_categories=["rce", "exfiltration"],
    
    # Alert configuration
    channels=[AlertChannel.SLACK, AlertChannel.PAGERDUTY],
    severity=AlertSeverity.CRITICAL,
    
    # Deduplication
    deduplicate=True,
    deduplicate_window_seconds=300,  # 5 minutes
    
    # Rate limiting
    rate_limit_count=10,
    rate_limit_window_seconds=3600,  # 1 hour
)
```

#### Rule Filters

**Event Type Filters**:
- `attack` - Attack events
- `pattern` - Detected patterns
- `alert` - Alert notifications

**Attack Event Filters**:
- `min_threat_level` - Minimum threat level (low, medium, high, critical)
- `attack_categories` - List of categories to match

**Pattern Filters**:
- `pattern_types` - Pattern types (coordinated, campaign, anomaly)
- `min_confidence` - Minimum confidence score (0.0-1.0)

### Alert Channels

#### Slack

**Configuration**:
```python
from honeymcp.models.alerts import AlertConfig

config = AlertConfig(
    slack_webhook_url="https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
    slack_channel="#security-alerts",  # Optional override
)
```

**Environment Variables**:
```bash
export HONEYMCP_SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export HONEYMCP_SLACK_CHANNEL="#security-alerts"
```

**Message Format**:
- Color-coded by severity
- Structured fields (severity, rule, event/pattern IDs)
- Clickable links to dashboard
- Timestamp

#### PagerDuty

**Configuration**:
```python
config = AlertConfig(
    pagerduty_routing_key="YOUR_ROUTING_KEY",
)
```

**Environment Variables**:
```bash
export HONEYMCP_PAGERDUTY_ROUTING_KEY="your_routing_key"
```

**Features**:
- Automatic incident creation
- Severity mapping
- Deduplication via dedup_key
- Custom details with event context

#### Email

**Configuration**:
```python
config = AlertConfig(
    smtp_host="smtp.gmail.com",
    smtp_port=587,
    smtp_username="alerts@example.com",
    smtp_password="your_password",
    smtp_from="HoneyMCP <alerts@example.com>",
    smtp_to=["security@example.com", "ops@example.com"],
)
```

**Environment Variables**:
```bash
export HONEYMCP_SMTP_HOST="smtp.gmail.com"
export HONEYMCP_SMTP_PORT="587"
export HONEYMCP_SMTP_USERNAME="alerts@example.com"
export HONEYMCP_SMTP_PASSWORD="your_password"
export HONEYMCP_SMTP_FROM="alerts@example.com"
export HONEYMCP_SMTP_TO="security@example.com,ops@example.com"
```

**Features**:
- HTML and plain text versions
- Color-coded by severity
- Structured layout
- Event/pattern details

#### Generic Webhooks

**Configuration**:
```python
config = AlertConfig(
    webhook_urls=[
        "https://example.com/webhook1",
        "https://example.com/webhook2",
    ]
)
```

**Payload Format**:
```json
{
  "alert_id": "alert_abc123",
  "rule_id": "rule_001",
  "timestamp": "2026-03-29T07:00:00Z",
  "severity": "warning",
  "title": "🚨 Attack Detected: list_cloud_secrets",
  "message": "**Threat Level:** HIGH\n**Category:** exfiltration\n...",
  "event_id": "evt_001",
  "pattern_id": null,
  "metadata": {
    "event_type": "attack",
    "threat_level": "high",
    "attack_category": "exfiltration"
  }
}
```

### Alert Deduplication

Prevents duplicate alerts within a time window:

```python
rule = AlertRule(
    rule_id="dedup_example",
    name="Deduplicated Alerts",
    description="Prevent alert spam",
    deduplicate=True,
    deduplicate_window_seconds=300,  # 5 minutes
    channels=[AlertChannel.SLACK],
)
```

**How it works**:
1. Alert created with unique key (rule_id + title)
2. Check if same alert sent within window
3. If yes, suppress duplicate
4. If no, send and track

### Rate Limiting

Controls alert volume per rule:

```python
rule = AlertRule(
    rule_id="rate_limited",
    name="Rate Limited Alerts",
    description="Max 10 alerts per hour",
    rate_limit_count=10,
    rate_limit_window_seconds=3600,
    channels=[AlertChannel.SLACK],
)
```

**How it works**:
1. Track alert count per rule
2. Check if count exceeds limit within window
3. If yes, suppress alert
4. If no, send and increment count

### Retry Logic

Automatic retry with exponential backoff:

```python
config = AlertConfig(
    max_retries=3,
    retry_delay_seconds=60,
    retry_backoff_multiplier=2.0,
)
```

**Retry Schedule**:
- Attempt 1: Immediate
- Attempt 2: After 60 seconds
- Attempt 3: After 120 seconds (60 * 2^1)
- Attempt 4: After 240 seconds (60 * 2^2)

**Delivery Status**:
- `pending` - Not yet sent
- `sent` - Successfully delivered
- `failed` - All retries exhausted

## Configuration

### YAML Configuration

```yaml
# honeymcp.yaml
alerting:
  enabled: true
  
  # Slack
  slack_webhook_url: "https://hooks.slack.com/services/..."
  slack_channel: "#security-alerts"
  
  # PagerDuty
  pagerduty_routing_key: "your_routing_key"
  
  # Email
  smtp_host: "smtp.gmail.com"
  smtp_port: 587
  smtp_username: "alerts@example.com"
  smtp_password: "your_password"
  smtp_from: "alerts@example.com"
  smtp_to:
    - "security@example.com"
    - "ops@example.com"
  
  # Webhooks
  webhook_urls:
    - "https://example.com/webhook"
  
  # Retry configuration
  max_retries: 3
  retry_delay_seconds: 60
  retry_backoff_multiplier: 2.0
  
  # Alert rules
  rules:
    - rule_id: "critical_attacks"
      name: "Critical Attack Alerts"
      description: "Alert on critical threats"
      enabled: true
      event_types: ["attack"]
      min_threat_level: "critical"
      channels: ["slack", "pagerduty"]
      severity: "critical"
      deduplicate: true
      deduplicate_window_seconds: 300
    
    - rule_id: "coordinated_patterns"
      name: "Coordinated Attack Patterns"
      description: "Alert on coordinated attacks"
      enabled: true
      event_types: ["pattern"]
      pattern_types: ["coordinated"]
      min_confidence: 0.8
      channels: ["slack", "email"]
      severity: "warning"
      rate_limit_count: 5
      rate_limit_window_seconds: 3600

streaming:
  enabled: true
  max_history: 100  # Events to keep for new clients
```

### Python API

```python
from honeymcp.models.alerts import AlertConfig, AlertRule, AlertChannel
from honeymcp.integrations.alerting import AlertRulesEngine
from honeymcp.integrations.notifiers import NotificationManager

# Create configuration
config = AlertConfig(
    enabled=True,
    slack_webhook_url="https://hooks.slack.com/services/...",
    rules=[
        AlertRule(
            rule_id="high_threats",
            name="High Threat Alerts",
            description="Alert on high/critical threats",
            event_types=["attack"],
            min_threat_level="high",
            channels=[AlertChannel.SLACK],
        )
    ]
)

# Initialize engine
engine = AlertRulesEngine(config)

# Evaluate events
alerts = engine.evaluate_attack_event(attack_event)

# Send alerts
manager = NotificationManager(config)
await manager.send_alerts(alerts)
```

## Usage Examples

### Complete Alerting Workflow

```python
from honeymcp.models.events import AttackFingerprint
from honeymcp.models.alerts import AlertConfig, AlertRule, AlertChannel
from honeymcp.integrations.alerting import AlertRulesEngine
from honeymcp.integrations.notifiers import NotificationManager
from honeymcp.integrations.streaming import StreamManager

# Initialize components
config = AlertConfig.load("config.yaml")
engine = AlertRulesEngine(config)
notifier = NotificationManager(config)
stream = StreamManager.initialize()

# Process attack event
async def handle_attack(event: AttackFingerprint):
    # Evaluate against rules
    alerts = engine.evaluate_attack_event(event)
    
    # Send alerts
    if alerts:
        await notifier.send_alerts(alerts)
    
    # Stream to clients
    await stream.publish_attack(event)

# Process pattern
async def handle_pattern(pattern: AttackPattern):
    # Evaluate against rules
    alerts = engine.evaluate_pattern(pattern)
    
    # Send alerts
    if alerts:
        await notifier.send_alerts(alerts)
    
    # Stream to clients
    await stream.publish_pattern(pattern)
```

### Dashboard Integration

```javascript
// Real-time dashboard updates
class SecurityDashboard {
  constructor() {
    this.eventSource = new EventSource('/stream');
    this.setupListeners();
  }
  
  setupListeners() {
    this.eventSource.addEventListener('attack', (event) => {
      const attack = JSON.parse(event.data);
      this.addAttackToTimeline(attack);
      this.updateMetrics();
      this.showNotification(attack);
    });
    
    this.eventSource.addEventListener('pattern', (event) => {
      const pattern = JSON.parse(event.data);
      this.highlightPattern(pattern);
      this.updatePatternList(pattern);
    });
    
    this.eventSource.addEventListener('alert', (event) => {
      const alert = JSON.parse(event.data);
      this.showCriticalAlert(alert);
    });
  }
  
  addAttackToTimeline(attack) {
    const element = document.createElement('div');
    element.className = `attack-item threat-${attack.threat_level}`;
    element.innerHTML = `
      <span class="time">${new Date(attack.timestamp).toLocaleTimeString()}</span>
      <span class="tool">${attack.ghost_tool}</span>
      <span class="category">${attack.attack_category}</span>
    `;
    document.getElementById('timeline').prepend(element);
  }
}

const dashboard = new SecurityDashboard();
```

### Custom Alert Handler

```python
from honeymcp.integrations.notifiers import NotifierBase

class CustomNotifier(NotifierBase):
    """Custom notification handler."""
    
    def get_channel_name(self) -> str:
        return "custom"
    
    async def send(self, alert: Alert) -> bool:
        """Send to custom system."""
        try:
            # Your custom logic here
            await self.send_to_custom_system(alert)
            return True
        except Exception as e:
            logger.error(f"Custom notifier failed: {e}")
            return False
    
    async def send_to_custom_system(self, alert: Alert):
        # Implement your custom notification logic
        pass
```

## Best Practices

### 1. Rule Design

**Start Conservative**:
```python
# Begin with high thresholds
rule = AlertRule(
    rule_id="initial_rule",
    min_threat_level="critical",  # Only critical
    min_confidence=0.9,            # High confidence
    rate_limit_count=5,            # Limited volume
)
```

**Tune Based on Volume**:
- Monitor alert frequency
- Adjust thresholds gradually
- Use deduplication for noisy rules

### 2. Channel Selection

**Severity-Based Routing**:
```python
# Critical -> PagerDuty (immediate response)
critical_rule = AlertRule(
    severity=AlertSeverity.CRITICAL,
    channels=[AlertChannel.PAGERDUTY, AlertChannel.SLACK]
)

# Warning -> Slack (awareness)
warning_rule = AlertRule(
    severity=AlertSeverity.WARNING,
    channels=[AlertChannel.SLACK]
)

# Info -> Email (daily digest)
info_rule = AlertRule(
    severity=AlertSeverity.INFO,
    channels=[AlertChannel.EMAIL]
)
```

### 3. Deduplication Strategy

**Short Window for Transient Issues**:
```python
rule = AlertRule(
    deduplicate_window_seconds=300,  # 5 minutes
)
```

**Long Window for Persistent Issues**:
```python
rule = AlertRule(
    deduplicate_window_seconds=3600,  # 1 hour
)
```

### 4. Rate Limiting

**Prevent Alert Storms**:
```python
rule = AlertRule(
    rate_limit_count=10,
    rate_limit_window_seconds=3600,  # Max 10/hour
)
```

### 5. Streaming Performance

**Limit History Size**:
```python
stream = StreamManager.initialize(max_history=50)  # Keep last 50 events
```

**Filter Events**:
```javascript
// Only subscribe to needed events
const eventSource = new EventSource('/stream?event_types=attack');
```

## Monitoring & Troubleshooting

### Check Alert Statistics

```python
engine = AlertRulesEngine(config)
stats = engine.get_stats()

print(f"Enabled: {stats['enabled']}")
print(f"Total rules: {stats['total_rules']}")
print(f"Enabled rules: {stats['enabled_rules']}")
print(f"Dedup keys tracked: {stats['tracked_dedup_keys']}")
```

### Check Stream Statistics

```python
stream = StreamManager.get_stream()
stats = stream.get_stats()

print(f"Active clients: {stats['active_clients']}")
print(f"History size: {stats['history_size']}")
print(f"Max history: {stats['max_history']}")
```

### Common Issues

**No Alerts Received**:
1. Check rule is enabled
2. Verify event matches filters
3. Check rate limits not exceeded
4. Verify channel configuration

**Stream Disconnects**:
1. Check network connectivity
2. Verify firewall/proxy settings
3. Check server logs for errors
4. Implement reconnection logic

**Alert Delivery Failures**:
1. Check channel credentials
2. Verify webhook URLs accessible
3. Review retry logs
4. Check rate limits on external services

### Cleanup Old Data

```python
# Cleanup tracking data older than 24 hours
engine.cleanup_old_tracking_data(max_age_hours=24)
```

## Testing

### Test Alert Rules

```bash
pytest tests/test_alerting.py -v
```

### Test Streaming

```bash
pytest tests/test_streaming.py -v
```

### Manual Testing

```bash
# Start API server
make run-ui

# In another terminal, stream events
curl -N http://localhost:8001/stream

# Trigger test attack (in another terminal)
# ... trigger attack event ...

# Should see event in stream
```

## API Reference

### AlertRulesEngine

```python
class AlertRulesEngine:
    def __init__(self, config: AlertConfig):
        """Initialize with configuration."""
    
    def add_rule(self, rule: AlertRule):
        """Add or update rule."""
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove rule."""
    
    def evaluate_attack_event(self, event: AttackFingerprint) -> List[Alert]:
        """Evaluate attack event."""
    
    def evaluate_pattern(self, pattern: AttackPattern) -> List[Alert]:
        """Evaluate pattern."""
    
    def cleanup_old_tracking_data(self, max_age_hours: int = 24):
        """Cleanup old tracking data."""
    
    def get_stats(self) -> Dict[str, any]:
        """Get statistics."""
```

### NotificationManager

```python
class NotificationManager:
    def __init__(self, config: AlertConfig):
        """Initialize with configuration."""
    
    async def send_alert(self, alert: Alert) -> bool:
        """Send single alert."""
    
    async def send_alerts(self, alerts: List[Alert]) -> int:
        """Send multiple alerts."""
```

### EventStream

```python
class EventStream:
    def __init__(self, max_history: int = 100):
        """Initialize stream."""
    
    async def subscribe(
        self,
        client_id: str,
        event_types: Optional[List[str]] = None,
        send_history: bool = True,
    ) -> AsyncIterator[str]:
        """Subscribe to stream."""
    
    async def publish_attack(self, event: AttackFingerprint):
        """Publish attack event."""
    
    async def publish_pattern(self, pattern: AttackPattern):
        """Publish pattern."""
    
    async def publish_alert(self, alert_data: Dict[str, any]):
        """Publish alert."""
    
    async def shutdown(self):
        """Shutdown stream."""
    
    def get_stats(self) -> Dict[str, any]:
        """Get statistics."""
```

## FAQ

**Q: How many concurrent clients can stream support?**
A: Tested with 100+ concurrent clients. Performance depends on event volume and server resources.

**Q: What happens if a channel fails?**
A: Other channels continue. Failed channel retries with exponential backoff.

**Q: Can I use multiple Slack channels?**
A: Yes, create separate rules with different webhook URLs or use Slack's routing.

**Q: How do I test alerts without triggering real attacks?**
A: Use the Python API to create test events and evaluate them against rules.

**Q: Can I customize alert messages?**
A: Yes, modify the alert creation logic in `AlertRulesEngine._create_attack_alert()`.

**Q: How long is event history kept?**
A: Configurable via `max_history` parameter (default: 100 events).

**Q: Can I filter streams by session ID?**
A: Not currently, but you can filter client-side after receiving events.

**Q: What's the latency for real-time updates?**
A: Typically <100ms from event to client delivery.
