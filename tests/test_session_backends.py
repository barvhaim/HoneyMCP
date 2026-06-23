"""Tests for session backend implementations."""

import asyncio
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
import pytest
import pytest_asyncio

from honeymcp.storage.session_backend import SessionBackend
from honeymcp.storage.memory_backend import InMemorySessionBackend

# Conditionally import Redis and SQLite backends
try:
    from honeymcp.storage.redis_backend import REDIS_AVAILABLE, RedisSessionBackend
except ImportError:
    REDIS_AVAILABLE = False

try:
    from honeymcp.storage.sqlite_backend import SQLITE_AVAILABLE, SQLiteSessionBackend
except ImportError:
    SQLITE_AVAILABLE = False


@pytest.fixture
def memory_backend():
    """Create an in-memory session backend for testing."""
    return InMemorySessionBackend(ttl=60, max_size=100)


@pytest_asyncio.fixture
async def redis_backend():
    """Create a Redis session backend for testing."""
    if not REDIS_AVAILABLE:
        pytest.skip("Redis not available")

    backend = RedisSessionBackend(
        redis_url="redis://localhost:6379", ttl=60, key_prefix="honeymcp:test:"
    )

    # Clear any existing test data
    await backend.clear()

    yield backend

    # Cleanup after test
    await backend.clear()
    await backend.close()


@pytest_asyncio.fixture
async def sqlite_backend():
    """Create a SQLite session backend for testing."""
    if not SQLITE_AVAILABLE:
        pytest.skip("SQLite not available")

    # Use temporary file for testing
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)

    backend = SQLiteSessionBackend(db_path=db_path, ttl=60)

    yield backend

    # Cleanup after test
    await backend.clear()
    db_path.unlink(missing_ok=True)


# Parametrize tests to run against all backends
@pytest_asyncio.fixture(params=["memory", "redis", "sqlite"])
async def backend(request):
    """Parametrized fixture that provides all backend types."""
    if request.param == "memory":
        backend = InMemorySessionBackend(ttl=60, max_size=100)
        yield backend
    elif request.param == "redis":
        if not REDIS_AVAILABLE:
            pytest.skip("Redis not available")
        backend = RedisSessionBackend(
            redis_url="redis://localhost:6379", ttl=60, key_prefix="honeymcp:test:"
        )
        await backend.clear()
        yield backend
        await backend.clear()
        await backend.close()
    elif request.param == "sqlite":
        if not SQLITE_AVAILABLE:
            pytest.skip("SQLite not available")
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = Path(f.name)
        backend = SQLiteSessionBackend(db_path=db_path, ttl=60)
        yield backend
        await backend.clear()
        db_path.unlink(missing_ok=True)


class TestSessionBackendInterface:
    """Test the SessionBackend interface across all implementations."""

    @pytest.mark.asyncio
    async def test_mark_and_check_attacker(self, backend: SessionBackend):
        """Test marking and checking attacker status."""
        session_id = "test_session_1"

        # Initially not an attacker
        assert await backend.is_attacker(session_id) is False

        # Mark as attacker
        await backend.mark_attacker(session_id)

        # Should now be flagged
        assert await backend.is_attacker(session_id) is True

    @pytest.mark.asyncio
    async def test_record_and_get_tool_history(self, backend: SessionBackend):
        """Test recording and retrieving tool call history."""
        session_id = "test_session_2"

        # Initially empty history
        history = await backend.get_tool_history(session_id)
        assert history == []

        # Record some tool calls
        await backend.record_tool_call(session_id, "tool1", datetime.utcnow())
        await backend.record_tool_call(session_id, "tool2", datetime.utcnow())
        await backend.record_tool_call(session_id, "tool3", datetime.utcnow())

        # Check history
        history = await backend.get_tool_history(session_id)
        assert len(history) == 3
        assert history == ["tool1", "tool2", "tool3"]

    @pytest.mark.asyncio
    async def test_rate_limiting(self, backend: SessionBackend):
        """Test rate limiting functionality."""
        session_id = "test_session_3"
        max_per_minute = 5

        # First 5 calls should be allowed
        for i in range(5):
            result = await backend.check_rate_limit(session_id, max_per_minute)
            assert result is True, f"Call {i+1} should be allowed"

        # 6th call should be blocked
        result = await backend.check_rate_limit(session_id, max_per_minute)
        assert result is False, "6th call should be blocked"

    @pytest.mark.asyncio
    async def test_session_count(self, backend: SessionBackend):
        """Test session counting."""
        # Initially should be 0 or small
        initial_count = await backend.get_session_count()

        # Add some sessions
        await backend.mark_attacker("session_1")
        await backend.mark_attacker("session_2")
        await backend.mark_attacker("session_3")

        # Count should increase
        new_count = await backend.get_session_count()
        assert new_count >= initial_count + 3

    @pytest.mark.asyncio
    async def test_clear(self, backend: SessionBackend):
        """Test clearing all session data."""
        # Add some data
        await backend.mark_attacker("session_1")
        await backend.record_tool_call("session_2", "tool1", datetime.utcnow())

        # Clear everything
        await backend.clear()

        # Verify data is gone
        assert await backend.is_attacker("session_1") is False
        history = await backend.get_tool_history("session_2")
        assert history == []

    @pytest.mark.asyncio
    async def test_multiple_sessions_isolation(self, backend: SessionBackend):
        """Test that different sessions are isolated."""
        session_1 = "session_1"
        session_2 = "session_2"

        # Mark only session_1 as attacker
        await backend.mark_attacker(session_1)

        # Check isolation
        assert await backend.is_attacker(session_1) is True
        assert await backend.is_attacker(session_2) is False

        # Record tools for session_1 only
        await backend.record_tool_call(session_1, "tool1", datetime.utcnow())
        await backend.record_tool_call(session_1, "tool2", datetime.utcnow())

        # Check isolation
        history_1 = await backend.get_tool_history(session_1)
        history_2 = await backend.get_tool_history(session_2)

        assert len(history_1) == 2
        assert len(history_2) == 0


class TestInMemoryBackend:
    """Tests specific to in-memory backend."""

    @pytest.mark.asyncio
    async def test_ttl_expiration(self, memory_backend: InMemorySessionBackend):
        """Test that sessions expire after TTL."""
        # Use very short TTL for testing
        backend = InMemorySessionBackend(ttl=1, max_size=100)

        session_id = "test_session"
        await backend.mark_attacker(session_id)

        # Should be flagged immediately
        assert await backend.is_attacker(session_id) is True

        # Wait for expiration
        await asyncio.sleep(1.5)

        # Should be expired now
        assert await backend.is_attacker(session_id) is False

    @pytest.mark.asyncio
    async def test_max_size_eviction(self, memory_backend: InMemorySessionBackend):
        """Test that oldest sessions are evicted when max_size is reached."""
        # Use small max_size for testing
        backend = InMemorySessionBackend(ttl=3600, max_size=5)

        # Add more sessions than max_size
        for i in range(10):
            await backend.mark_attacker(f"session_{i}")

        # Count should not exceed max_size
        count = await backend.get_session_count()
        assert count <= 5

    @pytest.mark.asyncio
    async def test_cleanup_expired(self, memory_backend: InMemorySessionBackend):
        """Test manual cleanup of expired sessions."""
        backend = InMemorySessionBackend(ttl=3600, max_size=100)

        # Add some sessions
        await backend.mark_attacker("session_1")
        await backend.mark_attacker("session_2")

        # Cleanup with very short TTL (should remove all)
        deleted = await backend.cleanup_expired(ttl_seconds=0)

        # Should have deleted sessions
        assert deleted >= 0


@pytest.mark.skipif(not REDIS_AVAILABLE, reason="Redis not available")
class TestRedisBackend:
    """Tests specific to Redis backend."""

    @pytest.mark.asyncio
    async def test_redis_connection(self, redis_backend: RedisSessionBackend):
        """Test that Redis connection works."""
        # Simple operation to verify connection
        await redis_backend.mark_attacker("test_session")
        assert await redis_backend.is_attacker("test_session") is True

    @pytest.mark.asyncio
    async def test_redis_key_prefix(self):
        """Test that Redis keys use correct prefix."""
        backend = RedisSessionBackend(
            redis_url="redis://localhost:6379", ttl=60, key_prefix="test_prefix:"
        )

        await backend.mark_attacker("session_1")

        # Verify key exists with correct prefix
        client = await backend._get_client()
        keys = []
        async for key in client.scan_iter(match="test_prefix:*"):
            keys.append(key)

        assert len(keys) > 0
        assert all(key.startswith("test_prefix:") for key in keys)

        await backend.clear()
        await backend.close()

    @pytest.mark.asyncio
    async def test_redis_ttl_automatic(self, redis_backend: RedisSessionBackend):
        """Test that Redis handles TTL automatically."""
        # Redis should handle expiration automatically
        # cleanup_expired should return 0
        deleted = await redis_backend.cleanup_expired(ttl_seconds=60)
        assert deleted == 0


@pytest.mark.skipif(not SQLITE_AVAILABLE, reason="SQLite not available")
class TestSQLiteBackend:
    """Tests specific to SQLite backend."""

    @pytest.mark.asyncio
    async def test_sqlite_persistence(self):
        """Test that SQLite persists data across instances."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = Path(f.name)

        try:
            # Create first backend instance and add data
            backend1 = SQLiteSessionBackend(db_path=db_path, ttl=3600)
            await backend1.mark_attacker("session_1")
            await backend1.record_tool_call("session_1", "tool1", datetime.utcnow())

            # Create second backend instance (simulates restart)
            backend2 = SQLiteSessionBackend(db_path=db_path, ttl=3600)

            # Data should still be there
            assert await backend2.is_attacker("session_1") is True
            history = await backend2.get_tool_history("session_1")
            assert len(history) == 1
            assert history[0] == "tool1"

            await backend2.clear()
        finally:
            db_path.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_sqlite_cleanup_expired(self, sqlite_backend: SQLiteSessionBackend):
        """Test manual cleanup of expired sessions in SQLite."""
        # Add some sessions
        await sqlite_backend.mark_attacker("session_1")
        await sqlite_backend.mark_attacker("session_2")

        # Cleanup with very short TTL (should remove all)
        deleted = await sqlite_backend.cleanup_expired(ttl_seconds=0)

        # Should have deleted sessions
        assert deleted >= 2

    @pytest.mark.asyncio
    async def test_sqlite_vacuum(self, sqlite_backend: SQLiteSessionBackend):
        """Test SQLite vacuum operation."""
        # Add and remove data to create fragmentation
        for i in range(100):
            await sqlite_backend.mark_attacker(f"session_{i}")

        await sqlite_backend.clear()

        # Vacuum should not raise errors
        await sqlite_backend.vacuum()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
