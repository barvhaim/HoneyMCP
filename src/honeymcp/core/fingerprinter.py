"""Attack fingerprinting - capture complete attack context."""

import logging
import threading
import time
from datetime import datetime
from uuid import uuid4
from typing import Any, Dict, List, Optional, Tuple
from honeymcp.models.events import AttackFingerprint
from honeymcp.models.ghost_tool_spec import GhostToolSpec
from honeymcp.storage.session_backend import SessionBackend

logger = logging.getLogger(__name__)


# Module-level session backend instance
_session_backend: Optional[SessionBackend] = None
_session_store: Optional["SessionStore"] = None


def configure_session_backend(backend: SessionBackend) -> None:
    """Configure the global session backend.
    
    Should be called once at startup (e.g. from honeypot()).
    
    Args:
        backend: SessionBackend implementation to use
    """
    global _session_backend, _session_store  # pylint: disable=global-statement
    _session_backend = backend
    _session_store = None
    logger.info("Session backend configured: %s", type(backend).__name__)


def configure_session_store(ttl: int = 3600, max_size: int = 10_000) -> None:
    """Configure the default in-memory session backend.

    This keeps the older test/public helper name working while the implementation
    delegates to the pluggable SessionBackend interface.
    """
    global _session_backend, _session_store  # pylint: disable=global-statement

    _session_store = SessionStore(ttl=ttl, max_size=max_size)
    _session_backend = _SessionStoreBackend(_session_store)
    logger.info("Session store configured: ttl=%s max_size=%s", ttl, max_size)


def get_session_store() -> "SessionStore":
    """Get the current legacy in-memory session store."""
    if _session_store is None:
        raise RuntimeError("Session store not configured. Call configure_session_store() first.")
    return _session_store


def get_session_backend() -> SessionBackend:
    """Get the current session backend.
    
    Returns:
        The configured SessionBackend instance
        
    Raises:
        RuntimeError: If backend has not been configured
    """
    if _session_backend is None:
        raise RuntimeError(
            "Session backend not configured. Call configure_session_backend() first."
        )
    return _session_backend


# Backward-compatible SessionStore class (deprecated)
class SessionStore:
    """TTL-bounded session store that auto-evicts expired entries.

    Prevents unbounded memory growth on long-running servers by:
    - Expiring sessions after a configurable TTL (default: 1 hour)
    - Capping the total number of tracked sessions (default: 10,000)
    - Lazily evicting expired entries on access
    - Periodically sweeping all entries every N writes
    """

    DEFAULT_TTL = 3600  # 1 hour
    DEFAULT_MAX_SIZE = 10_000
    _CLEANUP_INTERVAL = 100  # Full sweep every N writes

    def __init__(
        self,
        ttl: int = DEFAULT_TTL,
        max_size: int = DEFAULT_MAX_SIZE,
    ) -> None:
        self._ttl = ttl
        self._max_size = max_size
        self._attacker_detected: Dict[str, Tuple[bool, float]] = {}
        self._tool_history: Dict[str, Tuple[List[str], float]] = {}
        self._call_timestamps: Dict[str, Tuple[List[float], float]] = {}
        self._write_count = 0
        self._lock = threading.Lock()

    # -- internal helpers --------------------------------------------------

    def _is_expired(self, timestamp: float) -> bool:
        return (time.monotonic() - timestamp) > self._ttl

    def _maybe_cleanup(self) -> None:
        """Run a full sweep every ``_CLEANUP_INTERVAL`` writes."""
        self._write_count += 1
        if self._write_count % self._CLEANUP_INTERVAL == 0:
            self._evict_expired()

    def _evict_expired(self) -> None:
        """Remove all expired entries and enforce max_size."""
        now = time.monotonic()
        self._attacker_detected = {
            k: v for k, v in self._attacker_detected.items() if (now - v[1]) <= self._ttl
        }
        self._tool_history = {
            k: v for k, v in self._tool_history.items() if (now - v[1]) <= self._ttl
        }
        self._call_timestamps = {
            k: v for k, v in self._call_timestamps.items() if (now - v[1]) <= self._ttl
        }
        # If still over max_size, evict oldest entries
        for store in (self._attacker_detected, self._tool_history, self._call_timestamps):
            if len(store) > self._max_size:
                sorted_keys = sorted(store, key=lambda k: store[k][1])
                for key in sorted_keys[: len(store) - self._max_size]:
                    del store[key]

    # -- public API --------------------------------------------------------

    def mark_attacker(self, session_id: str) -> None:
        """Mark a session as having triggered a ghost tool."""
        with self._lock:
            self._attacker_detected[session_id] = (True, time.monotonic())
            self._maybe_cleanup()

    def is_attacker(self, session_id: str) -> bool:
        """Check if a session has been flagged as an attacker."""
        with self._lock:
            entry = self._attacker_detected.get(session_id)
            if entry is None:
                return False
            if self._is_expired(entry[1]):
                del self._attacker_detected[session_id]
                return False
            return entry[0]

    def record_tool(self, session_id: str, tool_name: str) -> None:
        """Record a tool call in the session history."""
        with self._lock:
            entry = self._tool_history.get(session_id)
            if entry is None or self._is_expired(entry[1]):
                self._tool_history[session_id] = ([tool_name], time.monotonic())
            else:
                entry[0].append(tool_name)
                self._tool_history[session_id] = (entry[0], time.monotonic())
            self._maybe_cleanup()

    def get_tool_history(self, session_id: str) -> List[str]:
        """Get the tool call history for a session."""
        with self._lock:
            entry = self._tool_history.get(session_id)
            if entry is None:
                return []
            if self._is_expired(entry[1]):
                del self._tool_history[session_id]
                return []
            return list(entry[0])

    def check_rate_limit(self, session_id: str, max_per_minute: int) -> bool:
        """Check if session is within rate limit. Returns True if allowed, False if exceeded."""
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

    @property
    def session_count(self) -> int:
        """Number of unique sessions currently tracked (for monitoring)."""
        with self._lock:
            keys = set(self._attacker_detected) | set(self._tool_history) | set(self._call_timestamps)
            return len(keys)

    def clear(self) -> None:
        """Remove all session data (useful for testing)."""
        with self._lock:
            self._attacker_detected.clear()
            self._tool_history.clear()
            self._call_timestamps.clear()
            self._write_count = 0


class _SessionStoreBackend(SessionBackend):
    """Async adapter for the legacy SessionStore."""

    def __init__(self, store: SessionStore) -> None:
        self._store = store

    async def mark_attacker(self, session_id: str) -> None:
        self._store.mark_attacker(session_id)

    async def is_attacker(self, session_id: str) -> bool:
        return self._store.is_attacker(session_id)

    async def record_tool_call(
        self, session_id: str, tool_name: str, _timestamp: datetime
    ) -> None:
        self._store.record_tool(session_id, tool_name)

    async def get_tool_history(self, session_id: str) -> List[str]:
        return self._store.get_tool_history(session_id)

    async def check_rate_limit(self, session_id: str, max_per_minute: int) -> bool:
        return self._store.check_rate_limit(session_id, max_per_minute)

    async def cleanup_expired(self, _ttl_seconds: int) -> int:
        before = self._store.session_count
        self._store._evict_expired()  # pylint: disable=protected-access
        return before - self._store.session_count

    async def get_session_count(self) -> int:
        return self._store.session_count

    async def clear(self) -> None:
        self._store.clear()


# -- Backward-compatible module-level functions ----------------------------
# These now delegate to the configured backend


def _run_backend_coro(coro):
    """Run a backend coroutine from synchronous compatibility wrappers."""
    import asyncio

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result = None
    error = None

    def run_in_thread() -> None:
        nonlocal result, error
        try:
            result = asyncio.run(coro)
        except Exception as exc:  # pragma: no cover - re-raised in caller thread
            error = exc

    thread = threading.Thread(target=run_in_thread)
    thread.start()
    thread.join()

    if error is not None:
        raise error
    return result


async def async_mark_attacker_detected(session_id: str) -> None:
    """Mark a session as having triggered a ghost tool."""
    backend = get_session_backend()
    await backend.mark_attacker(session_id)


def mark_attacker_detected(session_id: str) -> None:
    """Mark a session as having triggered a ghost tool (attacker detected)."""
    if _session_store is not None:
        _session_store.mark_attacker(session_id)
        return
    _run_backend_coro(async_mark_attacker_detected(session_id))


async def async_is_attacker_detected(session_id: str) -> bool:
    """Check if this session has been flagged as an attacker."""
    backend = get_session_backend()
    return await backend.is_attacker(session_id)


def is_attacker_detected(session_id: str) -> bool:
    """Check if this session has been flagged as an attacker."""
    if _session_store is not None:
        return _session_store.is_attacker(session_id)
    return _run_backend_coro(async_is_attacker_detected(session_id))


async def async_record_tool_call(session_id: str, tool_name: str) -> None:
    """Record a tool call in the session history."""
    backend = get_session_backend()
    await backend.record_tool_call(session_id, tool_name, datetime.utcnow())


def record_tool_call(session_id: str, tool_name: str) -> None:
    """Record a tool call in the session history."""
    if _session_store is not None:
        _session_store.record_tool(session_id, tool_name)
        return
    _run_backend_coro(async_record_tool_call(session_id, tool_name))


async def async_get_session_tool_history(session_id: str) -> List[str]:
    """Get the tool call history for a session."""
    backend = get_session_backend()
    return await backend.get_tool_history(session_id)


def get_session_tool_history(session_id: str) -> List[str]:
    """Get the tool call history for a session."""
    if _session_store is not None:
        return _session_store.get_tool_history(session_id)
    return _run_backend_coro(async_get_session_tool_history(session_id))


async def async_check_session_rate_limit(session_id: str, max_per_minute: int) -> bool:
    """Check if session is within rate limit. Returns True if allowed, False if exceeded."""
    backend = get_session_backend()
    return await backend.check_rate_limit(session_id, max_per_minute)


def check_session_rate_limit(session_id: str, max_per_minute: int) -> bool:
    """Check if session is within rate limit. Returns True if allowed, False if exceeded."""
    if _session_store is not None:
        return _session_store.check_rate_limit(session_id, max_per_minute)
    return _run_backend_coro(async_check_session_rate_limit(session_id, max_per_minute))


async def fingerprint_attack(
    tool_name: str,
    arguments: Dict[str, Any],
    context: Any,
    ghost_spec: GhostToolSpec,
    response_sent: Optional[str] = None,
) -> AttackFingerprint:
    """Capture complete attack context when a ghost tool is triggered.

    Args:
        tool_name: Name of the ghost tool that was called
        arguments: Arguments passed to the ghost tool
        context: MCP context object (varies by framework)
        ghost_spec: Specification of the triggered ghost tool
    Returns:
        Complete attack fingerprint with all available context
    """
    # Extract session ID from context
    session_id = _extract_session_id(context)

    # Get tool call history
    tool_history = await async_get_session_tool_history(session_id)

    # Try to extract conversation history (may not be available in MCP)
    conversation = _extract_conversation_history(context)

    # Extract client metadata
    client_metadata = _extract_client_metadata(context)

    # Use the exact response that was returned by middleware when provided.
    fake_response = response_sent or ghost_spec.response_generator(arguments)

    # Create unique event ID
    event_id = f"evt_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:8]}"

    return AttackFingerprint(
        event_id=event_id,
        timestamp=datetime.utcnow(),
        session_id=session_id,
        ghost_tool_called=tool_name,
        arguments=arguments,
        conversation_history=conversation,
        tool_call_sequence=tool_history,
        threat_level=ghost_spec.threat_level,
        attack_category=ghost_spec.attack_category,
        client_metadata=client_metadata,
        response_sent=fake_response,
    )


def resolve_session_id(context: Any) -> str:
    """Resolve or generate a session ID from MCP context."""
    return _extract_session_id(context)


def _extract_session_id(context: Any) -> str:
    """Extract session ID from MCP context."""
    # Try FastMCP HTTP helper (works even when request_context is missing)
    try:
        from fastmcp.server.dependencies import get_http_request

        request = get_http_request()
        if request is not None and hasattr(request, "query_params"):
            try:
                value = request.query_params.get("session_id")
            except Exception:
                value = None
            if value:
                return str(value)
        if request is not None and hasattr(request, "headers"):
            try:
                value = request.headers.get("mcp-session-id")
            except Exception:
                value = None
            if value:
                return str(value)
    except Exception:
        pass

    # Try FastMCP middleware context first
    if hasattr(context, "fastmcp_context"):
        fast_ctx = getattr(context, "fastmcp_context")
        if fast_ctx is not None:
            # Prefer HTTP query param session_id when present (e.g., /messages?session_id=...)
            req_ctx = getattr(fast_ctx, "request_context", None)
            if req_ctx is not None:
                request = getattr(req_ctx, "request", None)
                if request is not None and hasattr(request, "query_params"):
                    try:
                        value = request.query_params.get("session_id")
                    except Exception:
                        value = None
                    if value:
                        return str(value)
                if request is not None and hasattr(request, "headers"):
                    try:
                        value = request.headers.get("mcp-session-id")
                    except Exception:
                        value = None
                    if value:
                        return str(value)

            # Fall back to FastMCP context session_id if available
            if hasattr(fast_ctx, "session_id"):
                try:
                    return str(fast_ctx.session_id)
                except Exception:
                    pass

    # Try direct attributes on the context
    for attr in ["session_id", "id", "request_id", "connection_id"]:
        if hasattr(context, attr):
            value = getattr(context, attr)
            if value:
                return str(value)

    # Try dict-like contexts
    if isinstance(context, dict):
        for key in ["session_id", "id", "request_id", "connection_id"]:
            value = context.get(key)
            if value:
                return str(value)

    # Try request object for query/path params or headers (FastMCP/Starlette)
    if hasattr(context, "request"):
        request = getattr(context, "request")
        if request is not None:
            if hasattr(request, "query_params"):
                qp = getattr(request, "query_params")
                try:
                    value = qp.get("session_id")
                except Exception:
                    value = None
                if value:
                    return str(value)
            if hasattr(request, "path_params"):
                pp = getattr(request, "path_params")
                try:
                    value = pp.get("session_id")
                except Exception:
                    value = None
                if value:
                    return str(value)
            if hasattr(request, "headers"):
                headers = getattr(request, "headers")
                try:
                    value = (
                        headers.get("x-session-id")
                        or headers.get("session-id")
                        or headers.get("x-mcp-session-id")
                    )
                except Exception:
                    value = None
                if value:
                    return str(value)

    # Fallback: generate a session ID
    return f"sess_{uuid4().hex[:12]}"


def _extract_conversation_history(context: Any) -> Optional[List[Dict]]:
    """Extract conversation history from context if available.

    Note: MCP protocol may not provide conversation history to tools.
    This is a limitation of the protocol, not HoneyMCP.
    """
    if hasattr(context, "conversation_history"):
        return getattr(context, "conversation_history")

    if hasattr(context, "messages"):
        return getattr(context, "messages")

    # Not available
    return None


def _extract_client_metadata(context: Any) -> Dict[str, Any]:
    """Extract available client metadata from context."""
    metadata = {}

    # Try FastMCP HTTP helper for request info
    try:
        from fastmcp.server.dependencies import get_http_request

        request = get_http_request()
        if request is not None:
            if hasattr(request, "headers"):
                try:
                    metadata["headers"] = dict(request.headers)
                except Exception:
                    pass
            if hasattr(request, "client") and request.client:
                try:
                    metadata["client_ip"] = request.client.host
                    metadata["client_port"] = request.client.port
                except Exception:
                    pass
    except Exception:
        pass

    # FastMCP middleware context -> request info
    if hasattr(context, "fastmcp_context"):
        fast_ctx = getattr(context, "fastmcp_context")
        if fast_ctx is not None:
            req_ctx = getattr(fast_ctx, "request_context", None)
            if req_ctx is not None:
                request = getattr(req_ctx, "request", None)
                if request is not None:
                    if hasattr(request, "headers"):
                        try:
                            metadata["headers"] = dict(request.headers)
                        except Exception:
                            pass
                    if hasattr(request, "client") and request.client:
                        try:
                            metadata["client_ip"] = request.client.host
                            metadata["client_port"] = request.client.port
                        except Exception:
                            pass

    # Try to extract user agent
    if hasattr(context, "user_agent"):
        metadata["user_agent"] = getattr(context, "user_agent")

    # Try to extract client info
    if hasattr(context, "client_info"):
        metadata["client_info"] = getattr(context, "client_info")

    # Try to extract request headers
    if hasattr(context, "headers"):
        headers = getattr(context, "headers")
        if isinstance(headers, dict):
            metadata["headers"] = headers

    # If no metadata found, return minimal info
    if not metadata:
        metadata["user_agent"] = "unknown"

    return metadata
