# Session Backend Configuration

HoneyMCP supports multiple session storage backends to meet different deployment requirements. Session state includes attacker flags, tool call history, and rate limiting data.

## Available Backends

### In-Memory (Default)
- **Use Case**: Single-instance deployments, development, testing
- **Pros**: Fast, no external dependencies, simple setup
- **Cons**: State lost on restart, not suitable for distributed deployments
- **Requirements**: None (built-in)

### Redis
- **Use Case**: Distributed deployments, high-performance production
- **Pros**: Persistent across restarts, supports multiple instances, automatic TTL
- **Cons**: Requires Redis server
- **Requirements**: `redis[asyncio]` package

### SQLite
- **Use Case**: Single-instance production deployments requiring persistence
- **Pros**: Persistent across restarts, no external server, ACID guarantees
- **Cons**: Not suitable for distributed deployments
- **Requirements**: `aiosqlite` package

## Configuration

### Via YAML Configuration

```yaml
# honeymcp.yaml
session_backend:
  type: memory  # Options: memory, redis, sqlite
  
  # Redis-specific settings (when type=redis)
  redis_url: redis://localhost:6379
  
  # SQLite-specific settings (when type=sqlite)
  sqlite_path: ~/.honeymcp/sessions.db

# Session TTL applies to all backends
sessions:
  ttl: 3600  # 1 hour
  max_size: 10000  # Only for in-memory backend
```

### Via Python API

```python
from honeymcp import honeypot
from pathlib import Path

# In-memory backend (default)
mcp = honeypot(
    mcp,
    session_backend_type="memory",
    session_ttl=3600,
    max_sessions=10000
)

# Redis backend
mcp = honeypot(
    mcp,
    session_backend_type="redis",
    redis_url="redis://localhost:6379",
    session_ttl=3600
)

# SQLite backend
mcp = honeypot(
    mcp,
    session_backend_type="sqlite",
    sqlite_path=Path.home() / ".honeymcp" / "sessions.db",
    session_ttl=3600
)
```

## Installation

### Redis Backend

```bash
# Install Redis server (macOS)
brew install redis
brew services start redis

# Install Python package
pip install "redis[asyncio]"
# or with uv
uv pip install "redis[asyncio]"
```

### SQLite Backend

```bash
# Install Python package
pip install aiosqlite
# or with uv
uv pip install aiosqlite
```

## Backend Comparison

| Feature | In-Memory | Redis | SQLite |
|---------|-----------|-------|--------|
| Persistence | ❌ | ✅ | ✅ |
| Distributed | ❌ | ✅ | ❌ |
| External Server | ❌ | ✅ | ❌ |
| Performance | Excellent | Excellent | Good |
| Setup Complexity | Minimal | Medium | Low |
| Production Ready | ⚠️ | ✅ | ✅ |

## Migration Guide

### From In-Memory to Redis

1. Install Redis and Python package:
   ```bash
   brew install redis
   pip install "redis[asyncio]"
   ```

2. Update configuration:
   ```yaml
   session_backend:
     type: redis
     redis_url: redis://localhost:6379
   ```

3. Restart your server - existing in-memory sessions will be lost (expected)

### From In-Memory to SQLite

1. Install Python package:
   ```bash
   pip install aiosqlite
   ```

2. Update configuration:
   ```yaml
   session_backend:
     type: sqlite
     sqlite_path: ~/.honeymcp/sessions.db
   ```

3. Restart your server - existing in-memory sessions will be lost (expected)

### From SQLite to Redis (for scaling)

1. Install Redis:
   ```bash
   brew install redis
   pip install "redis[asyncio]"
   ```

2. Update configuration:
   ```yaml
   session_backend:
     type: redis
     redis_url: redis://your-redis-server:6379
   ```

3. Restart - SQLite sessions won't be migrated automatically

## Production Recommendations

### Single Instance Deployment
- **Recommended**: SQLite
- **Why**: Persistence without external dependencies
- **Configuration**:
  ```yaml
  session_backend:
    type: sqlite
    sqlite_path: /var/lib/honeymcp/sessions.db
  sessions:
    ttl: 3600
  ```

### Distributed Deployment
- **Recommended**: Redis
- **Why**: Shared state across multiple instances
- **Configuration**:
  ```yaml
  session_backend:
    type: redis
    redis_url: redis://redis-cluster:6379
  sessions:
    ttl: 3600
  ```

### Development/Testing
- **Recommended**: In-Memory
- **Why**: Fast, simple, no setup required
- **Configuration**:
  ```yaml
  session_backend:
    type: memory
  sessions:
    ttl: 3600
    max_size: 1000
  ```

## Monitoring

### Check Session Count

```python
from honeymcp.core.fingerprinter import get_session_backend

backend = get_session_backend()
count = await backend.get_session_count()
print(f"Active sessions: {count}")
```

### Manual Cleanup

```python
# Clean up expired sessions
deleted = await backend.cleanup_expired(ttl_seconds=3600)
print(f"Deleted {deleted} expired sessions")
```

### SQLite Maintenance

```python
# Optimize SQLite database (reclaim space)
from honeymcp.storage.sqlite_backend import SQLiteSessionBackend

backend = SQLiteSessionBackend(db_path=Path("sessions.db"))
await backend.vacuum()
```

## Troubleshooting

### Redis Connection Errors

**Problem**: `ConnectionError: Error connecting to Redis`

**Solutions**:
1. Verify Redis is running: `redis-cli ping`
2. Check Redis URL in configuration
3. Verify network connectivity
4. Check Redis authentication if required

### SQLite Lock Errors

**Problem**: `OperationalError: database is locked`

**Solutions**:
1. Ensure only one process accesses the database
2. Use Redis for distributed deployments
3. Check file permissions on database file

### Memory Backend Growing Too Large

**Problem**: In-memory backend consuming too much memory

**Solutions**:
1. Reduce `max_sessions` limit
2. Reduce `session_ttl` to expire sessions faster
3. Switch to Redis or SQLite for better memory management

## Advanced Configuration

### Redis with Authentication

```yaml
session_backend:
  type: redis
  redis_url: redis://:password@localhost:6379/0
```

### Redis with TLS

```yaml
session_backend:
  type: redis
  redis_url: rediss://localhost:6380  # Note: rediss:// for TLS
```

### Custom SQLite Path

```yaml
session_backend:
  type: sqlite
  sqlite_path: /custom/path/to/sessions.db
```

### Multiple Redis Databases

```yaml
# Use different Redis database numbers for isolation
session_backend:
  type: redis
  redis_url: redis://localhost:6379/1  # Database 1
```

## Performance Tuning

### In-Memory Backend

```yaml
sessions:
  ttl: 1800  # Shorter TTL = less memory usage
  max_size: 5000  # Lower limit = less memory usage
```

### Redis Backend

```yaml
session_backend:
  type: redis
  redis_url: redis://localhost:6379
sessions:
  ttl: 3600  # Redis handles expiration automatically
```

### SQLite Backend

```python
# Periodic vacuum for optimal performance
import asyncio
from honeymcp.storage.sqlite_backend import SQLiteSessionBackend

async def maintenance():
    backend = SQLiteSessionBackend(db_path=Path("sessions.db"))
    while True:
        await asyncio.sleep(86400)  # Daily
        await backend.vacuum()
        await backend.cleanup_expired(ttl_seconds=3600)
```

## Security Considerations

### Redis
- Use authentication: `redis_url: redis://:password@host:6379`
- Enable TLS for production: `rediss://host:6380`
- Use firewall rules to restrict access
- Consider Redis ACLs for fine-grained permissions

### SQLite
- Set appropriate file permissions: `chmod 600 sessions.db`
- Store in secure directory: `/var/lib/honeymcp/`
- Regular backups of database file
- Monitor disk space usage

### In-Memory
- No persistence = no data leakage after restart
- Memory dumps could expose session data
- Use for development only, not production

## API Reference

### SessionBackend Interface

All backends implement this interface:

```python
class SessionBackend(ABC):
    async def mark_attacker(self, session_id: str) -> None:
        """Mark session as attacker."""
        
    async def is_attacker(self, session_id: str) -> bool:
        """Check if session is flagged."""
        
    async def record_tool_call(
        self, session_id: str, tool_name: str, timestamp: datetime
    ) -> None:
        """Record tool call."""
        
    async def get_tool_history(self, session_id: str) -> List[str]:
        """Get tool call history."""
        
    async def check_rate_limit(
        self, session_id: str, max_per_minute: int
    ) -> bool:
        """Check rate limit."""
        
    async def cleanup_expired(self, ttl_seconds: int) -> int:
        """Remove expired sessions."""
        
    async def get_session_count(self) -> int:
        """Get active session count."""
        
    async def clear(self) -> None:
        """Clear all data."""
```

## Testing

Run backend tests:

```bash
# Test all backends
pytest tests/test_session_backends.py -v

# Test specific backend
pytest tests/test_session_backends.py -k "memory" -v
pytest tests/test_session_backends.py -k "redis" -v
pytest tests/test_session_backends.py -k "sqlite" -v

# Skip backends that aren't available
pytest tests/test_session_backends.py -v --tb=short
```

## FAQ

**Q: Can I switch backends without losing data?**
A: No, session data is not automatically migrated. Plan for a maintenance window.

**Q: Which backend is fastest?**
A: In-memory and Redis are comparable. SQLite is slightly slower but still performant.

**Q: Can I use Redis Cluster?**
A: Yes, use the cluster URL: `redis://node1:6379,node2:6379,node3:6379`

**Q: How much memory does in-memory backend use?**
A: Approximately 1-2 KB per session. 10,000 sessions ≈ 10-20 MB.

**Q: Can I use PostgreSQL?**
A: Not currently supported, but the backend interface makes it easy to add.

**Q: Do I need to manually clean up expired sessions?**
A: No, all backends handle expiration automatically. Manual cleanup is optional.
