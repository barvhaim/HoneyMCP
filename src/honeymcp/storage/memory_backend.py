"""In-memory session backend implementation."""

import time
import threading
from datetime import datetime
from typing import Dict, List, Tuple
from collections import defaultdict

from honeymcp.storage.session_backend import SessionBackend


class InMemorySessionBackend(SessionBackend):
    """In-memory session store with TTL-based expiration.
    
    This is the default backend that stores all session state in process memory.
    Suitable for single-instance deployments where session persistence across
    restarts is not required.
    
    Features:
    - TTL-based automatic expiration
    - Size-bounded with LRU eviction
    - Thread-safe operations
    - Lazy cleanup on access
    - Periodic full sweeps
    """

    DEFAULT_TTL = 3600  # 1 hour
    DEFAULT_MAX_SIZE = 10_000
    _CLEANUP_INTERVAL = 100  # Full sweep every N writes

    def __init__(
        self,
        ttl: int = DEFAULT_TTL,
        max_size: int = DEFAULT_MAX_SIZE,
    ) -> None:
        """Initialize in-memory session backend.
        
        Args:
            ttl: Session time-to-live in seconds
            max_size: Maximum number of sessions to track
        """
        self._ttl = ttl
        self._max_size = max_size
        self._attacker_detected: Dict[str, Tuple[bool, float]] = {}
        self._tool_history: Dict[str, Tuple[List[str], float]] = {}
        self._call_timestamps: Dict[str, Tuple[List[float], float]] = {}
        self._write_count = 0
        self._lock = threading.Lock()

    # -- Internal helpers --------------------------------------------------

    def _is_expired(self, timestamp: float) -> bool:
        """Check if a timestamp is expired based on TTL."""
        return (time.monotonic() - timestamp) > self._ttl

    def _maybe_cleanup(self) -> None:
        """Run a full sweep every _CLEANUP_INTERVAL writes."""
        self._write_count += 1
        if self._write_count % self._CLEANUP_INTERVAL == 0:
            self._evict_expired()

    def _evict_expired(self) -> None:
        """Remove all expired entries and enforce max_size."""
        now = time.monotonic()
        
        # Remove expired entries
        self._attacker_detected = {
            k: v for k, v in self._attacker_detected.items() 
            if (now - v[1]) <= self._ttl
        }
        self._tool_history = {
            k: v for k, v in self._tool_history.items() 
            if (now - v[1]) <= self._ttl
        }
        self._call_timestamps = {
            k: v for k, v in self._call_timestamps.items() 
            if (now - v[1]) <= self._ttl
        }
        
        # If still over max_size, evict oldest entries (LRU)
        for store in (self._attacker_detected, self._tool_history, self._call_timestamps):
            if len(store) > self._max_size:
                sorted_keys = sorted(store, key=lambda k: store[k][1])
                for key in sorted_keys[: len(store) - self._max_size]:
                    del store[key]

    # -- SessionBackend interface implementation ---------------------------

    async def mark_attacker(self, session_id: str) -> None:
        """Mark a session as having triggered a ghost tool."""
        with self._lock:
            self._attacker_detected[session_id] = (True, time.monotonic())
            self._maybe_cleanup()

    async def is_attacker(self, session_id: str) -> bool:
        """Check if a session has been flagged as an attacker."""
        with self._lock:
            entry = self._attacker_detected.get(session_id)
            if entry is None:
                return False
            if self._is_expired(entry[1]):
                del self._attacker_detected[session_id]
                return False
            return entry[0]

    async def record_tool_call(
        self, session_id: str, tool_name: str, timestamp: datetime
    ) -> None:
        """Record a tool call in the session history."""
        with self._lock:
            entry = self._tool_history.get(session_id)
            if entry is None or self._is_expired(entry[1]):
                self._tool_history[session_id] = ([tool_name], time.monotonic())
            else:
                entry[0].append(tool_name)
                self._tool_history[session_id] = (entry[0], time.monotonic())
            self._maybe_cleanup()

    async def get_tool_history(self, session_id: str) -> List[str]:
        """Get the tool call history for a session."""
        with self._lock:
            entry = self._tool_history.get(session_id)
            if entry is None:
                return []
            if self._is_expired(entry[1]):
                del self._tool_history[session_id]
                return []
            return list(entry[0])

    async def check_rate_limit(self, session_id: str, max_per_minute: int) -> bool:
        """Check if session is within rate limit.
        
        Returns True if allowed, False if exceeded.
        """
        now = time.monotonic()
        with self._lock:
            entry = self._call_timestamps.get(session_id)
            if entry is None or self._is_expired(entry[1]):
                self._call_timestamps[session_id] = ([now], now)
                return True
            
            timestamps, _ = entry
            # Prune timestamps older than 60 seconds
            cutoff = now - 60.0
            timestamps = [t for t in timestamps if t > cutoff]
            timestamps.append(now)
            self._call_timestamps[session_id] = (timestamps, now)
            
            return len(timestamps) <= max_per_minute

    async def cleanup_expired(self, ttl_seconds: int) -> int:
        """Remove expired sessions based on TTL.
        
        Args:
            ttl_seconds: Time-to-live in seconds (overrides instance TTL)
            
        Returns:
            Number of sessions removed
        """
        with self._lock:
            now = time.monotonic()
            
            # Count sessions before cleanup
            before_count = len(set(
                list(self._attacker_detected.keys()) +
                list(self._tool_history.keys()) +
                list(self._call_timestamps.keys())
            ))
            
            # Remove expired entries using provided TTL
            self._attacker_detected = {
                k: v for k, v in self._attacker_detected.items() 
                if (now - v[1]) <= ttl_seconds
            }
            self._tool_history = {
                k: v for k, v in self._tool_history.items() 
                if (now - v[1]) <= ttl_seconds
            }
            self._call_timestamps = {
                k: v for k, v in self._call_timestamps.items() 
                if (now - v[1]) <= ttl_seconds
            }
            
            # Count sessions after cleanup
            after_count = len(set(
                list(self._attacker_detected.keys()) +
                list(self._tool_history.keys()) +
                list(self._call_timestamps.keys())
            ))
            
            return before_count - after_count

    async def get_session_count(self) -> int:
        """Get the total number of tracked sessions."""
        with self._lock:
            # Count unique session IDs across all stores
            keys = set(self._attacker_detected) | set(self._tool_history) | set(self._call_timestamps)
            return len(keys)

    async def clear(self) -> None:
        """Remove all session data (useful for testing)."""
        with self._lock:
            self._attacker_detected.clear()
            self._tool_history.clear()
            self._call_timestamps.clear()
            self._write_count = 0
