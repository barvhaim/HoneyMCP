"""Tests for SessionStore TTL and max-size eviction."""

import time
from unittest.mock import patch

import pytest

from honeymcp.core.fingerprinter import (
    SessionStore,
    configure_session_store,
    get_session_store,
    mark_attacker_detected,
    is_attacker_detected,
    record_tool_call,
    get_session_tool_history,
)


class TestSessionStore:
    """Core SessionStore behaviour."""

    def test_mark_and_check_attacker(self):
        store = SessionStore()
        assert not store.is_attacker("s1")
        store.mark_attacker("s1")
        assert store.is_attacker("s1")

    def test_record_and_get_tool_history(self):
        store = SessionStore()
        store.record_tool("s1", "tool_a")
        store.record_tool("s1", "tool_b")
        assert store.get_tool_history("s1") == ["tool_a", "tool_b"]

    def test_get_tool_history_returns_copy(self):
        store = SessionStore()
        store.record_tool("s1", "tool_a")
        history = store.get_tool_history("s1")
        history.append("extra")
        assert store.get_tool_history("s1") == ["tool_a"]

    def test_unknown_session_returns_defaults(self):
        store = SessionStore()
        assert not store.is_attacker("unknown")
        assert store.get_tool_history("unknown") == []

    def test_session_count(self):
        store = SessionStore()
        assert store.session_count == 0
        store.mark_attacker("s1")
        assert store.session_count == 1
        store.record_tool("s1", "t")
        assert store.session_count == 1  # same session
        store.record_tool("s2", "t")
        assert store.session_count == 2

    def test_clear(self):
        store = SessionStore()
        store.mark_attacker("s1")
        store.record_tool("s1", "tool_a")
        store.clear()
        assert store.session_count == 0
        assert not store.is_attacker("s1")
        assert store.get_tool_history("s1") == []


class TestSessionStoreTTL:
    """TTL-based expiry."""

    def test_attacker_flag_expires(self):
        store = SessionStore(ttl=1)
        store.mark_attacker("s1")
        assert store.is_attacker("s1")

        # Advance monotonic clock past TTL
        with patch("honeymcp.core.fingerprinter.time") as mock_time:
            mock_time.monotonic.return_value = time.monotonic() + 2
            assert not store.is_attacker("s1")

    def test_tool_history_expires(self):
        store = SessionStore(ttl=1)
        store.record_tool("s1", "tool_a")
        assert store.get_tool_history("s1") == ["tool_a"]

        with patch("honeymcp.core.fingerprinter.time") as mock_time:
            mock_time.monotonic.return_value = time.monotonic() + 2
            assert store.get_tool_history("s1") == []

    def test_recording_resets_ttl(self):
        """New tool calls should refresh the session timestamp."""
        store = SessionStore(ttl=5)
        base = time.monotonic()

        store.record_tool("s1", "a")

        # 3 seconds later — still within TTL
        with patch("honeymcp.core.fingerprinter.time") as mock_time:
            mock_time.monotonic.return_value = base + 3
            store.record_tool("s1", "b")

        # 7 seconds from start but only 4 from last write — still alive
        with patch("honeymcp.core.fingerprinter.time") as mock_time:
            mock_time.monotonic.return_value = base + 7
            assert store.get_tool_history("s1") == ["a", "b"]

    def test_expired_history_starts_fresh(self):
        """After expiry, new records should start a clean history."""
        store = SessionStore(ttl=1)
        store.record_tool("s1", "old_tool")

        with patch("honeymcp.core.fingerprinter.time") as mock_time:
            mock_time.monotonic.return_value = time.monotonic() + 2
            store.record_tool("s1", "new_tool")
            assert store.get_tool_history("s1") == ["new_tool"]


class TestSessionStoreMaxSize:
    """Max-size eviction."""

    def test_evicts_oldest_when_over_max_size(self):
        store = SessionStore(ttl=3600, max_size=3)
        # Fill up the store and trigger a cleanup
        for i in range(store._CLEANUP_INTERVAL):
            sid = f"s{i}"
            store.mark_attacker(sid)

        # After cleanup, only max_size entries remain
        remaining = sum(
            1
            for i in range(store._CLEANUP_INTERVAL)
            if store.is_attacker(f"s{i}")
        )
        assert remaining <= 3

    def test_evicts_oldest_tool_history(self):
        store = SessionStore(ttl=3600, max_size=3)
        for i in range(store._CLEANUP_INTERVAL):
            store.record_tool(f"s{i}", f"tool_{i}")

        remaining = sum(
            1
            for i in range(store._CLEANUP_INTERVAL)
            if store.get_tool_history(f"s{i}")
        )
        assert remaining <= 3


class TestPeriodicCleanup:
    """Periodic sweep every N writes."""

    def test_cleanup_runs_at_interval(self):
        store = SessionStore(ttl=1)

        # Insert an entry then advance time so it's expired
        store.mark_attacker("old")
        base = time.monotonic()

        with patch("honeymcp.core.fingerprinter.time") as mock_time:
            mock_time.monotonic.return_value = base + 2

            # Write entries to trigger periodic sweep
            for i in range(store._CLEANUP_INTERVAL):
                store.mark_attacker(f"new_{i}")

            # The old entry should have been evicted by the sweep
            assert not store.is_attacker("old")


class TestModuleLevelFunctions:
    """Backward-compatible module-level functions delegate to the store."""

    def setup_method(self):
        """Reset the global store before each test."""
        configure_session_store(ttl=3600, max_size=10_000)

    def test_mark_and_check_via_module_functions(self):
        assert not is_attacker_detected("s1")
        mark_attacker_detected("s1")
        assert is_attacker_detected("s1")

    def test_record_and_get_via_module_functions(self):
        record_tool_call("s1", "tool_a")
        record_tool_call("s1", "tool_b")
        assert get_session_tool_history("s1") == ["tool_a", "tool_b"]

    def test_configure_replaces_store(self):
        mark_attacker_detected("s1")
        assert is_attacker_detected("s1")

        configure_session_store(ttl=60, max_size=100)
        # Old data is gone after reconfiguration
        assert not is_attacker_detected("s1")

    def test_get_session_store_returns_current(self):
        store = get_session_store()
        assert isinstance(store, SessionStore)


class TestConfigSessionFields:
    """HoneyMCPConfig includes session tracking fields."""

    def test_default_values(self):
        from honeymcp.models.config import HoneyMCPConfig

        config = HoneyMCPConfig()
        assert config.session_ttl == 3600
        assert config.max_sessions == 10_000

    def test_custom_values(self):
        from honeymcp.models.config import HoneyMCPConfig

        config = HoneyMCPConfig(session_ttl=120, max_sessions=500)
        assert config.session_ttl == 120
        assert config.max_sessions == 500

    def test_yaml_parsing(self, tmp_path):
        from honeymcp.models.config import HoneyMCPConfig

        config_file = tmp_path / "honeymcp.yaml"
        config_file.write_text(
            "sessions:\n  ttl: 300\n  max_size: 2000\n"
        )
        config = HoneyMCPConfig.from_yaml(config_file)
        assert config.session_ttl == 300
        assert config.max_sessions == 2000

    def test_session_ttl_minimum(self):
        from honeymcp.models.config import HoneyMCPConfig
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            HoneyMCPConfig(session_ttl=10)  # below minimum of 60

    def test_max_sessions_minimum(self):
        from honeymcp.models.config import HoneyMCPConfig
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            HoneyMCPConfig(max_sessions=50)  # below minimum of 100
