"""Redis-backed session storage for distributed deployments."""

import json
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, List, Optional

if TYPE_CHECKING:
    import redis.asyncio as redis

try:
    import redis.asyncio as redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

from honeymcp.storage.session_backend import SessionBackend


class RedisSessionBackend(SessionBackend):
    """Redis-backed session store for distributed deployments.

    Features:
    - Distributed session state across multiple instances
    - Automatic TTL-based expiration via Redis
    - High-performance async operations
    - Persistent across server restarts

    Requires: redis[asyncio] package

    Example:
        backend = RedisSessionBackend(
            redis_url="redis://localhost:6379",
            ttl=3600
        )
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        ttl: int = 3600,
        key_prefix: str = "honeymcp:session:",
    ) -> None:
        """Initialize Redis session backend.

        Args:
            redis_url: Redis connection URL
            ttl: Session time-to-live in seconds
            key_prefix: Prefix for all Redis keys

        Raises:
            ImportError: If redis package is not installed
        """
        if not REDIS_AVAILABLE:
            raise ImportError(
                "Redis backend requires 'redis' package. "
                "Install with: pip install redis[asyncio]"
            )

        self.redis_url = redis_url
        self.ttl = ttl
        self.prefix = key_prefix
        self._client: Optional[Any] = None

    async def _get_client(self) -> Any:
        """Get or create Redis client."""
        if self._client is None:
            self._client = await redis.from_url(
                self.redis_url, decode_responses=True, encoding="utf-8"
            )
        return self._client

    async def mark_attacker(self, session_id: str) -> None:
        """Mark a session as having triggered a ghost tool."""
        client = await self._get_client()
        key = f"{self.prefix}{session_id}:attacker"
        await client.setex(key, self.ttl, "1")

    async def is_attacker(self, session_id: str) -> bool:
        """Check if a session has been flagged as an attacker."""
        client = await self._get_client()
        key = f"{self.prefix}{session_id}:attacker"
        result = await client.exists(key)
        return result > 0

    async def record_tool_call(self, session_id: str, tool_name: str, timestamp: datetime) -> None:
        """Record a tool call in the session history."""
        client = await self._get_client()
        key = f"{self.prefix}{session_id}:history"

        # Store as JSON with timestamp
        value = json.dumps({"tool": tool_name, "timestamp": timestamp.isoformat()})

        # Append to list
        await client.rpush(key, value)

        # Set TTL on the list
        await client.expire(key, self.ttl)

    async def get_tool_history(self, session_id: str) -> List[str]:
        """Get the tool call history for a session."""
        client = await self._get_client()
        key = f"{self.prefix}{session_id}:history"

        # Get all items from list
        history = await client.lrange(key, 0, -1)

        # Extract tool names from JSON
        tools = []
        for item in history:
            try:
                data = json.loads(item)
                tools.append(data["tool"])
            except (json.JSONDecodeError, KeyError):
                # Skip malformed entries
                continue

        return tools

    async def check_rate_limit(self, session_id: str, max_per_minute: int) -> bool:
        """Check if session is within rate limit.

        Uses Redis sorted set with timestamps as scores for efficient
        time-window queries.

        Returns True if allowed, False if exceeded.
        """
        client = await self._get_client()
        key = f"{self.prefix}{session_id}:rate"
        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=1)

        # Add current timestamp to sorted set
        await client.zadd(key, {now.isoformat(): now.timestamp()})

        # Remove timestamps older than 1 minute
        await client.zremrangebyscore(key, "-inf", cutoff.timestamp())

        # Count remaining timestamps
        count = await client.zcard(key)

        # Set TTL on the sorted set
        await client.expire(key, 60)

        return count <= max_per_minute

    async def cleanup_expired(self, ttl_seconds: int) -> int:
        """Remove expired sessions based on TTL.

        Note: Redis handles TTL automatically, so this is a no-op.
        Returns 0 as no manual cleanup is needed.
        """
        # Redis handles expiration automatically via TTL
        return 0

    async def get_session_count(self) -> int:
        """Get the total number of tracked sessions.

        Counts unique session IDs by scanning for attacker flag keys.
        """
        client = await self._get_client()
        pattern = f"{self.prefix}*:attacker"

        # Use SCAN to avoid blocking
        count = 0
        async for _ in client.scan_iter(match=pattern, count=100):
            count += 1

        return count

    async def clear(self) -> None:
        """Remove all session data (useful for testing)."""
        client = await self._get_client()
        pattern = f"{self.prefix}*"

        # Use SCAN to find all keys
        keys_to_delete = []
        async for key in client.scan_iter(match=pattern, count=100):
            keys_to_delete.append(key)

        # Delete in batches
        if keys_to_delete:
            await client.delete(*keys_to_delete)

    async def close(self) -> None:
        """Close Redis connection."""
        if self._client is not None:
            await self._client.close()
            self._client = None

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
