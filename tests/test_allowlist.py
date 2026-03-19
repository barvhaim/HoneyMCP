"""Tests for session allowlist."""

import pytest
from unittest.mock import patch, AsyncMock

from honeymcp.models.config import HoneyMCPConfig


class TestAllowlistConfig:
    """Config parsing for allowlist section."""

    def test_default_is_empty_list(self):
        config = HoneyMCPConfig()
        assert config.allowlist_session_ids == []

    def test_custom_values(self):
        config = HoneyMCPConfig(allowlist_session_ids=["bot-1", "qa-session"])
        assert config.allowlist_session_ids == ["bot-1", "qa-session"]

    def test_yaml_parsing(self, tmp_path):
        config_file = tmp_path / "honeymcp.yaml"
        config_file.write_text(
            "allowlist:\n  session_ids:\n    - health-check\n    - qa-bot\n"
        )
        config = HoneyMCPConfig.from_yaml(config_file)
        assert config.allowlist_session_ids == ["health-check", "qa-bot"]

    def test_yaml_empty_list(self, tmp_path):
        config_file = tmp_path / "honeymcp.yaml"
        config_file.write_text("allowlist:\n  session_ids: []\n")
        config = HoneyMCPConfig.from_yaml(config_file)
        assert config.allowlist_session_ids == []

    def test_yaml_no_allowlist_section(self, tmp_path):
        config_file = tmp_path / "honeymcp.yaml"
        config_file.write_text("protection_mode: SCANNER\n")
        config = HoneyMCPConfig.from_yaml(config_file)
        assert config.allowlist_session_ids == []


class TestAllowlistMiddleware:
    """Allowlisted sessions bypass ghost tool detection."""

    ALLOWLISTED_SESSION = "allowed-session-1"

    @pytest.mark.asyncio
    async def test_allowlisted_session_not_flagged_as_attacker(self):
        from fastmcp import FastMCP
        from honeymcp.core.middleware import honeypot
        from honeymcp.core.fingerprinter import configure_session_store, is_attacker_detected

        configure_session_store(ttl=3600, max_size=10_000)

        server = FastMCP("test")

        @server.tool()
        def echo(msg: str) -> str:
            return msg

        server = honeypot(
            server,
            ghost_tools=["list_cloud_secrets"],
            use_dynamic_tools=False,
            allowlist_session_ids=[self.ALLOWLISTED_SESSION],
        )

        with patch(
            "honeymcp.core.middleware.resolve_session_id",
            return_value=self.ALLOWLISTED_SESSION,
        ):
            await server.call_tool("list_cloud_secrets", {})
            # Session should NOT be marked as attacker
            assert not is_attacker_detected(self.ALLOWLISTED_SESSION)

    @pytest.mark.asyncio
    async def test_non_allowlisted_session_still_detected(self):
        from fastmcp import FastMCP
        from honeymcp.core.middleware import honeypot
        from honeymcp.core.fingerprinter import configure_session_store, is_attacker_detected

        configure_session_store(ttl=3600, max_size=10_000)

        server = FastMCP("test")

        @server.tool()
        def echo(msg: str) -> str:
            return msg

        server = honeypot(
            server,
            ghost_tools=["list_cloud_secrets"],
            use_dynamic_tools=False,
            allowlist_session_ids=["other-session"],
        )

        with patch(
            "honeymcp.core.middleware.resolve_session_id",
            return_value="attacker-session",
        ):
            with patch("honeymcp.core.middleware.store_event", new_callable=AsyncMock):
                await server.call_tool("list_cloud_secrets", {})
                assert is_attacker_detected("attacker-session")

    @pytest.mark.asyncio
    async def test_allowlisted_session_skips_rate_limiting(self):
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
            rate_limit_action="block",
            allowlist_session_ids=[self.ALLOWLISTED_SESSION],
        )

        with patch(
            "honeymcp.core.middleware.resolve_session_id",
            return_value=self.ALLOWLISTED_SESSION,
        ):
            # Should not be rate-limited despite exceeding limit
            for _ in range(5):
                result = await server.call_tool("echo", {"msg": "hi"})
                if hasattr(result, "meta") and result.meta:
                    assert not result.meta.get("is_error", False)

    @pytest.mark.asyncio
    async def test_allowlisted_session_skips_scanner_block(self):
        from fastmcp import FastMCP
        from honeymcp.core.middleware import honeypot
        from honeymcp.core.fingerprinter import (
            configure_session_store,
            mark_attacker_detected,
        )

        configure_session_store(ttl=3600, max_size=10_000)

        server = FastMCP("test")

        @server.tool()
        def echo(msg: str) -> str:
            return msg

        server = honeypot(
            server,
            ghost_tools=[],
            use_dynamic_tools=False,
            allowlist_session_ids=[self.ALLOWLISTED_SESSION],
        )

        # Even if manually marked as attacker, allowlisted session bypasses
        mark_attacker_detected(self.ALLOWLISTED_SESSION)

        with patch(
            "honeymcp.core.middleware.resolve_session_id",
            return_value=self.ALLOWLISTED_SESSION,
        ):
            result = await server.call_tool("echo", {"msg": "hi"})
            # Should get the real response, not "Service temporarily unavailable"
            assert result.content[0].text == "hi"
