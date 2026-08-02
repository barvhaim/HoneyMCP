"""Behavioral tests for protection-mode enforcement through a real server.

`test_protection_modes.py` only asserts on the ProtectionMode enum, so it stayed
green while enforcement was completely broken on FastMCP 3.x: honeypot() patched
the `server.call_tool` attribute, but FastMCP 3 dispatches tool calls through
its own middleware chain, so the interceptor never ran on the live path. Ghost
tools still fired (they are registered as ordinary tools) while lockout,
COGNITIVE mocks, rate limiting, the allowlist and tool-call recording silently
no-op'd.

These tests drive tool calls the way the transport does, so they fail if the
interceptor is ever bypassed again.
"""

import pytest
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

import honeymcp.core.fingerprinter as fingerprinter
from honeymcp.core.middleware import honeypot
from honeymcp.models.protection_mode import ProtectionMode

GHOST = "export_user_data"


@pytest.fixture(autouse=True)
def _fresh_session_state():
    """Give every test a clean backend and no legacy session store.

    Do NOT call configure_session_store() here. It installs the legacy
    SessionStore, which mark_attacker_detected() writes to while the
    protection-mode check reads the configured SessionBackend -- two separate
    stores, so the attacker flag is never seen and lockout silently no-ops.
    honeypot() configures the real backend itself.
    """
    fingerprinter._legacy_session_store = None
    fingerprinter._session_backend = None
    fingerprinter._fallback_session_id = None
    yield
    fingerprinter._legacy_session_store = None
    fingerprinter._session_backend = None
    fingerprinter._fallback_session_id = None


def _build(**kwargs):
    """A server with one real tool plus a single static honeypot."""
    server = FastMCP("test")

    @server.tool()
    def echo(msg: str) -> str:
        """Echo a message."""
        return msg

    @server.tool()
    def numbers() -> list[int]:
        """A tool whose output schema is a list, not a string."""
        return [1, 2, 3]

    kwargs.setdefault("ghost_tools", [GHOST])
    kwargs.setdefault("use_dynamic_tools", False)
    return honeypot(server, **kwargs)


def _text(result) -> str:
    return result.content[0].text if getattr(result, "content", None) else ""


class TestInterceptorReachable:
    """The interceptor must actually run on the dispatch path."""

    @pytest.mark.asyncio
    async def test_ghost_tool_is_registered_and_callable(self):
        server = _build()
        names = [t.name for t in await server.list_tools()]
        assert GHOST in names
        assert "echo" in names

    @pytest.mark.asyncio
    async def test_tool_call_sequence_is_recorded(self):
        """Recording happens at the top of the interceptor.

        An empty sequence after several calls means the interceptor was skipped
        -- the exact symptom of the FastMCP 3 dispatch bug.
        """
        from honeymcp.core.fingerprinter import get_session_backend, resolve_session_id

        server = _build()
        await server.call_tool("echo", {"msg": "one"})
        await server.call_tool("echo", {"msg": "two"})

        backend = get_session_backend()
        session_id = resolve_session_id({})
        history = await backend.get_tool_history(session_id)
        assert "echo" in history


class TestScannerLockout:
    @pytest.mark.asyncio
    async def test_real_tool_blocked_after_ghost_trigger(self):
        server = _build(protection_mode=ProtectionMode.SCANNER)

        # Legitimate call first: must be untouched (zero false positives).
        assert _text(await server.call_tool("echo", {"msg": "hi"})) == "hi"

        # Trip the honeypot.
        await server.call_tool(GHOST, {"limit": 100})

        # Session is now burned: previously-working real tools must fail.
        with pytest.raises(ToolError, match="unavailable"):
            await server.call_tool("echo", {"msg": "hi"})

    @pytest.mark.asyncio
    async def test_lockout_applies_to_non_string_output_schema(self):
        """Denial must not depend on the blocked tool's output schema.

        Returning a substituted ToolResult fails here: `numbers` declares a
        list, so a generic {"result": ...} payload is rejected by the client as
        invalid structured content. Raising is the only schema-safe denial.
        """
        server = _build(protection_mode=ProtectionMode.SCANNER)
        await server.call_tool(GHOST, {"limit": 100})

        with pytest.raises(ToolError, match="unavailable"):
            await server.call_tool("numbers", {})

    @pytest.mark.asyncio
    async def test_ghost_tool_returns_fake_data_not_an_error(self):
        """The honeypot itself must stay convincing -- never error."""
        server = _build(protection_mode=ProtectionMode.SCANNER)
        result = await server.call_tool(GHOST, {"limit": 100})
        assert _text(result)
        assert "unavailable" not in _text(result).lower()


class TestAllowlistBypass:
    @pytest.mark.asyncio
    async def test_allowlisted_session_is_never_locked_out(self):
        from honeymcp.core.fingerprinter import resolve_session_id

        session_id = resolve_session_id({})
        server = _build(
            protection_mode=ProtectionMode.SCANNER,
            allowlist_session_ids=[session_id],
        )

        await server.call_tool(GHOST, {"limit": 100})
        # Allowlisted: still served after touching a honeypot.
        assert _text(await server.call_tool("echo", {"msg": "hi"})) == "hi"


class TestSessionIdStability:
    def test_fallback_session_id_is_stable_across_calls(self):
        """Session-scoped state requires a stable id when the transport has none.

        A fresh uuid per call meant mark_attacker() and is_attacker() used
        different keys, so nothing session-scoped could ever work over stdio.
        """
        from honeymcp.core.fingerprinter import resolve_session_id

        assert resolve_session_id({}) == resolve_session_id({})
