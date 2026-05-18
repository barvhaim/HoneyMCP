"""SQLite-backed session storage for persistent single-instance deployments."""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

try:
    import aiosqlite

    SQLITE_AVAILABLE = True
except ImportError:
    SQLITE_AVAILABLE = False

from honeymcp.storage.session_backend import SessionBackend


class SQLiteSessionBackend(SessionBackend):
    """SQLite-backed session store for persistent single-instance deployments.

    Features:
    - Persistent session state across server restarts
    - No external database server required
    - ACID guarantees for data integrity
    - Automatic schema creation
    - Efficient indexed queries

    Requires: aiosqlite package

    Example:
        backend = SQLiteSessionBackend(
            db_path=Path.home() / ".honeymcp" / "sessions.db",
            ttl=3600
        )
    """

    def __init__(
        self,
        db_path: Path,
        ttl: int = 3600,
    ) -> None:
        """Initialize SQLite session backend.

        Args:
            db_path: Path to SQLite database file
            ttl: Session time-to-live in seconds

        Raises:
            ImportError: If aiosqlite package is not installed
        """
        if not SQLITE_AVAILABLE:
            raise ImportError(
                "SQLite backend requires 'aiosqlite' package. "
                "Install with: pip install aiosqlite"
            )

        self.db_path = db_path
        self.ttl = ttl
        self._initialized = False

    async def _init_db(self) -> None:
        """Initialize database schema if not already done."""
        if self._initialized:
            return

        # Ensure parent directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        async with aiosqlite.connect(self.db_path) as db:
            # Sessions table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    is_attacker INTEGER DEFAULT 0,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Tool calls table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS tool_calls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            """)

            # Rate limit tracking table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS rate_limits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create indexes for performance
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_tool_calls_session 
                ON tool_calls(session_id, timestamp)
            """)

            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_rate_limits_session 
                ON rate_limits(session_id, timestamp)
            """)

            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_updated 
                ON sessions(last_updated)
            """)

            await db.commit()

        self._initialized = True

    async def mark_attacker(self, session_id: str) -> None:
        """Mark a session as having triggered a ghost tool."""
        await self._init_db()

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO sessions (session_id, is_attacker, last_updated)
                VALUES (?, 1, ?)
                ON CONFLICT(session_id) DO UPDATE SET 
                    is_attacker = 1, 
                    last_updated = ?
            """,
                (session_id, datetime.utcnow(), datetime.utcnow()),
            )
            await db.commit()

    async def is_attacker(self, session_id: str) -> bool:
        """Check if a session has been flagged as an attacker."""
        await self._init_db()

        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                SELECT is_attacker FROM sessions 
                WHERE session_id = ? 
                AND datetime(last_updated, '+' || ? || ' seconds') > datetime('now')
            """,
                (session_id, self.ttl),
            )
            row = await cursor.fetchone()
            return row is not None and row[0] == 1

    async def record_tool_call(self, session_id: str, tool_name: str, timestamp: datetime) -> None:
        """Record a tool call in the session history."""
        await self._init_db()

        async with aiosqlite.connect(self.db_path) as db:
            # Ensure session exists
            await db.execute(
                """
                INSERT OR IGNORE INTO sessions (session_id, last_updated)
                VALUES (?, ?)
            """,
                (session_id, datetime.utcnow()),
            )

            # Record tool call
            await db.execute(
                """
                INSERT INTO tool_calls (session_id, tool_name, timestamp)
                VALUES (?, ?, ?)
            """,
                (session_id, tool_name, timestamp),
            )

            # Update session last_updated
            await db.execute(
                """
                UPDATE sessions 
                SET last_updated = ? 
                WHERE session_id = ?
            """,
                (datetime.utcnow(), session_id),
            )

            await db.commit()

    async def get_tool_history(self, session_id: str) -> List[str]:
        """Get the tool call history for a session."""
        await self._init_db()

        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                SELECT tool_name FROM tool_calls
                WHERE session_id = ?
                AND datetime(timestamp, '+' || ? || ' seconds') > datetime('now')
                ORDER BY timestamp ASC
            """,
                (session_id, self.ttl),
            )
            rows = await cursor.fetchall()
            return [row[0] for row in rows]

    async def check_rate_limit(self, session_id: str, max_per_minute: int) -> bool:
        """Check if session is within rate limit.

        Returns True if allowed, False if exceeded.
        """
        await self._init_db()

        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=1)

        async with aiosqlite.connect(self.db_path) as db:
            # Record this call
            await db.execute(
                """
                INSERT INTO rate_limits (session_id, timestamp)
                VALUES (?, ?)
            """,
                (session_id, now),
            )

            # Count calls in the last minute
            cursor = await db.execute(
                """
                SELECT COUNT(*) FROM rate_limits
                WHERE session_id = ?
                AND timestamp > ?
            """,
                (session_id, cutoff),
            )
            row = await cursor.fetchone()
            count = row[0] if row else 0

            # Clean up old entries
            await db.execute(
                """
                DELETE FROM rate_limits
                WHERE timestamp < ?
            """,
                (cutoff,),
            )

            await db.commit()

            return count <= max_per_minute

    async def cleanup_expired(self, ttl_seconds: int) -> int:
        """Remove expired sessions based on TTL.

        Args:
            ttl_seconds: Time-to-live in seconds (overrides instance TTL)

        Returns:
            Number of sessions removed
        """
        await self._init_db()

        cutoff = datetime.utcnow() - timedelta(seconds=ttl_seconds)

        async with aiosqlite.connect(self.db_path) as db:
            # Delete expired sessions
            cursor = await db.execute(
                """
                DELETE FROM sessions 
                WHERE datetime(last_updated, '+' || ? || ' seconds') <= datetime('now')
            """,
                (ttl_seconds,),
            )
            deleted_count = cursor.rowcount

            # Clean up orphaned tool calls
            await db.execute("""
                DELETE FROM tool_calls
                WHERE session_id NOT IN (SELECT session_id FROM sessions)
            """)

            # Clean up old rate limit entries
            await db.execute(
                """
                DELETE FROM rate_limits
                WHERE timestamp < ?
            """,
                (cutoff,),
            )

            await db.commit()

            return deleted_count

    async def get_session_count(self) -> int:
        """Get the total number of tracked sessions."""
        await self._init_db()

        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                SELECT COUNT(*) FROM sessions
                WHERE datetime(last_updated, '+' || ? || ' seconds') > datetime('now')
            """,
                (self.ttl,),
            )
            row = await cursor.fetchone()
            return row[0] if row else 0

    async def clear(self) -> None:
        """Remove all session data (useful for testing)."""
        await self._init_db()

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM rate_limits")
            await db.execute("DELETE FROM tool_calls")
            await db.execute("DELETE FROM sessions")
            await db.commit()

    async def vacuum(self) -> None:
        """Optimize database by reclaiming unused space.

        Should be called periodically in production to maintain performance.
        """
        await self._init_db()

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("VACUUM")
