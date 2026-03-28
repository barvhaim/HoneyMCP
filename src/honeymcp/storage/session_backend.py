"""Abstract session backend interface for pluggable session storage."""

from abc import ABC, abstractmethod
from typing import List
from datetime import datetime


class SessionBackend(ABC):
    """Abstract interface for session state persistence.
    
    Implementations can use different storage backends (in-memory, Redis, SQLite, etc.)
    to persist session state including attacker flags, tool call history, and rate limits.
    """

    @abstractmethod
    async def mark_attacker(self, session_id: str) -> None:
        """Mark a session as having triggered a ghost tool (attacker detected).
        
        Args:
            session_id: The session identifier to mark
        """
        pass

    @abstractmethod
    async def is_attacker(self, session_id: str) -> bool:
        """Check if a session has been flagged as an attacker.
        
        Args:
            session_id: The session identifier to check
            
        Returns:
            True if session is flagged as attacker, False otherwise
        """
        pass

    @abstractmethod
    async def record_tool_call(
        self, session_id: str, tool_name: str, timestamp: datetime
    ) -> None:
        """Record a tool call in the session history.
        
        Args:
            session_id: The session identifier
            tool_name: Name of the tool that was called
            timestamp: When the tool was called
        """
        pass

    @abstractmethod
    async def get_tool_history(self, session_id: str) -> List[str]:
        """Get the tool call history for a session.
        
        Args:
            session_id: The session identifier
            
        Returns:
            List of tool names in chronological order
        """
        pass

    @abstractmethod
    async def check_rate_limit(self, session_id: str, max_per_minute: int) -> bool:
        """Check if a session is within rate limit.
        
        Args:
            session_id: The session identifier
            max_per_minute: Maximum allowed calls per minute
            
        Returns:
            True if within limit (allowed), False if exceeded
        """
        pass

    @abstractmethod
    async def cleanup_expired(self, ttl_seconds: int) -> int:
        """Remove expired sessions based on TTL.
        
        Args:
            ttl_seconds: Time-to-live in seconds
            
        Returns:
            Number of sessions removed
        """
        pass

    @abstractmethod
    async def get_session_count(self) -> int:
        """Get the total number of tracked sessions.
        
        Returns:
            Number of active sessions
        """
        pass

    @abstractmethod
    async def clear(self) -> None:
        """Remove all session data (useful for testing)."""
        pass
