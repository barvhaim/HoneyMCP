"""Tests for per-session rate limiting."""

import time
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from honeymcp.core.fingerprinter import (
    SessionStore,
    check_session_rate_limit,
    configure_session_store,
)
from honeymcp.models.config import HoneyMCPConfig


class TestSessionStoreRateLimit:
    """SessionStore.check_rate_limit behaviour."""

    def test_calls_within_limit_allowed(self):
        store = SessionStore()
        for _ in range(5):
            assert store.check_rate_limit("s1", max_per_minute=5)

    def test_calls_exceeding_limit_rejected(self):
        store = SessionStore()
        for _ in range(3):
            assert store.check_rate_limit("s1", max_per_minute=3)
        # 4th call exceeds limit
        assert not store.check_rate_limit("s1", max_per_minute=3)

    def test_timestamps_pruned_after_60s(self):
        store = SessionStore()
        base = time.monotonic()

        # Fill up to the limit
        for _ in range(3):
            store.check_rate_limit("s1", max_per_minute=3)

        # Advance 61 seconds — old timestamps should be pruned
        with patch("honeymcp.core.fingerprinter.time") as mock_time:
            mock_time.monotonic.return_value = base + 61
            assert store.check_rate_limit("s1", max_per_minute=3)

    def test_independent_sessions(self):
        store = SessionStore()
        # Exhaust limit for s1
        for _ in range(2):
            store.check_rate_limit("s1", max_per_minute=2)
        assert not store.check_rate_limit("s1", max_per_minute=2)

        # s2 should still be allowed
        assert store.check_rate_limit("s2", max_per_minute=2)

    def test_rate_limit_resets_after_time(self):
        store = SessionStore()
        base = time.monotonic()

        # Exhaust limit
        for _ in range(2):
            store.check_rate_limit("s1", max_per_minute=2)
        assert not store.check_rate_limit("s1", max_per_minute=2)

        # After 61 seconds, limit resets
        with patch("honeymcp.core.fingerprinter.time") as mock_time:
            mock_time.monotonic.return_value = base + 61
            assert store.check_rate_limit("s1", max_per_minute=2)

    def test_expired_session_starts_fresh(self):
        """If the session entry itself expired (TTL), rate limit resets."""
        store = SessionStore(ttl=5)
        base = time.monotonic()

        for _ in range(2):
            store.check_rate_limit("s1", max_per_minute=2)
        assert not store.check_rate_limit("s1", max_per_minute=2)

        # Session TTL expires (> 5s)
        with patch("honeymcp.core.fingerprinter.time") as mock_time:
            mock_time.monotonic.return_value = base + 6
            # Should start fresh — allowed
            assert store.check_rate_limit("s1", max_per_minute=2)

    def test_clear_resets_rate_limits(self):
        store = SessionStore()
        for _ in range(3):
            store.check_rate_limit("s1", max_per_minute=3)
        assert not store.check_rate_limit("s1", max_per_minute=3)

        store.clear()
        assert store.check_rate_limit("s1", max_per_minute=3)

    def test_session_count_includes_rate_limit_sessions(self):
        store = SessionStore()
        store.check_rate_limit("rate_only_session", max_per_minute=10)
        assert store.session_count == 1


class TestModuleLevelRateLimit:
    """Module-level check_session_rate_limit wrapper."""

    def setup_method(self):
        configure_session_store(ttl=3600, max_size=10_000)

    def test_wrapper_delegates_to_store(self):
        assert check_session_rate_limit("s1", max_per_minute=2)
        assert check_session_rate_limit("s1", max_per_minute=2)
        assert not check_session_rate_limit("s1", max_per_minute=2)


class TestRateLimitConfig:
    """YAML config parsing for rate_limit section."""

    def test_defaults(self):
        config = HoneyMCPConfig()
        assert config.rate_limit_max_calls_per_minute is None
        assert config.rate_limit_action == "throttle"

    def test_custom_values(self):
        config = HoneyMCPConfig(rate_limit_max_calls_per_minute=30, rate_limit_action="block")
        assert config.rate_limit_max_calls_per_minute == 30
        assert config.rate_limit_action == "block"

    def test_yaml_parsing(self, tmp_path):
        config_file = tmp_path / "honeymcp.yaml"
        config_file.write_text(
            "rate_limit:\n  max_calls_per_minute: 20\n  action: block\n"
        )
        config = HoneyMCPConfig.from_yaml(config_file)
        assert config.rate_limit_max_calls_per_minute == 20
        assert config.rate_limit_action == "block"

    def test_yaml_parsing_null_limit(self, tmp_path):
        config_file = tmp_path / "honeymcp.yaml"
        config_file.write_text(
            "rate_limit:\n  max_calls_per_minute: null\n  action: throttle\n"
        )
        config = HoneyMCPConfig.from_yaml(config_file)
        assert config.rate_limit_max_calls_per_minute is None
        assert config.rate_limit_action == "throttle"

    def test_yaml_partial_rate_limit(self, tmp_path):
        config_file = tmp_path / "honeymcp.yaml"
        config_file.write_text("rate_limit:\n  max_calls_per_minute: 10\n")
        config = HoneyMCPConfig.from_yaml(config_file)
        assert config.rate_limit_max_calls_per_minute == 10
        assert config.rate_limit_action == "throttle"  # default


class TestMiddlewareRateLimit:
    """Rate limiting behaviour inside the middleware interceptor."""

    FIXED_SESSION = "test-session-fixed"

    @pytest.mark.asyncio
    async def test_block_action_returns_error(self):
        """When action=block and limit exceeded, a ToolError is raised.

        Denials are raised rather than returned: a substituted ToolResult must
        satisfy the real tool's declared outputSchema, which a generic error
        payload cannot do in general. See _deny() in core/middleware.py.
        """
        from fastmcp import FastMCP
        from fastmcp.exceptions import ToolError
        from honeymcp.core.middleware import honeypot
        from honeymcp.core.fingerprinter import configure_session_store

        configure_session_store(ttl=3600, max_size=10_000)

        server = FastMCP("test")

        @server.tool()
        def echo(msg: str) -> str:
            return msg

        server = honeypot(
            server,
            ghost_tools=[],
            use_dynamic_tools=False,
            rate_limit_max_calls_per_minute=2,
            rate_limit_action="block",
        )

        with patch("honeymcp.core.middleware.resolve_session_id", return_value=self.FIXED_SESSION):
            # First 2 calls should pass through
            for _ in range(2):
                result = await server.call_tool("echo", {"msg": "hi"})
                if hasattr(result, "meta") and result.meta:
                    assert not result.meta.get("is_error", False)

            # 3rd call should be blocked
            with pytest.raises(ToolError, match="Rate limit exceeded"):
                await server.call_tool("echo", {"msg": "hi"})

    @pytest.mark.asyncio
    async def test_throttle_action_adds_delay(self):
        """When action=throttle and limit exceeded, asyncio.sleep is called."""
        from fastmcp import FastMCP
        from honeymcp.core.middleware import honeypot
        from honeymcp.core.fingerprinter import configure_session_store

        configure_session_store(ttl=3600, max_size=10_000)

        server = FastMCP("test")

        @server.tool()
        def echo(msg: str) -> str:
            return msg

        server = honeypot(
            server,
            ghost_tools=[],
            use_dynamic_tools=False,
            rate_limit_max_calls_per_minute=1,
            rate_limit_action="throttle",
        )

        with patch("honeymcp.core.middleware.resolve_session_id", return_value=self.FIXED_SESSION):
            # First call: within limit
            await server.call_tool("echo", {"msg": "hi"})

            # Second call: exceeds limit, should sleep
            with patch("honeymcp.core.middleware.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
                await server.call_tool("echo", {"msg": "hi"})
                mock_sleep.assert_awaited_once_with(2.0)

    @pytest.mark.asyncio
    async def test_no_rate_limit_when_not_configured(self):
        """When rate_limit_max_calls_per_minute is None, no limiting occurs."""
        from fastmcp import FastMCP
        from honeymcp.core.middleware import honeypot
        from honeymcp.core.fingerprinter import configure_session_store

        configure_session_store(ttl=3600, max_size=10_000)

        server = FastMCP("test")

        @server.tool()
        def echo(msg: str) -> str:
            return msg

        server = honeypot(
            server,
            ghost_tools=[],
            use_dynamic_tools=False,
            rate_limit_max_calls_per_minute=None,
        )

        with patch("honeymcp.core.middleware.resolve_session_id", return_value=self.FIXED_SESSION):
            # Should be able to make many calls without issue
            for _ in range(50):
                result = await server.call_tool("echo", {"msg": "hi"})
                if hasattr(result, "meta") and result.meta:
                    assert not result.meta.get("is_error", False)
