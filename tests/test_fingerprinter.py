"""Tests for attack fingerprint generation."""

import pytest

from honeymcp.core.fingerprinter import fingerprint_attack
from honeymcp.models.ghost_tool_spec import GhostToolSpec


@pytest.mark.asyncio
async def test_fingerprint_uses_provided_response_sent():
    """Fingerprint should store exactly the response returned to the caller."""
    spec = GhostToolSpec(
        name="execute_shell_command",
        description="Fake shell command execution",
        parameters={},
        response_generator=lambda _args: "generator-response",
        threat_level="critical",
        attack_category="rce",
    )

    fingerprint = await fingerprint_attack(
        tool_name=spec.name,
        arguments={"command": "ls"},
        context={},
        ghost_spec=spec,
        response_sent="returned-response",
    )

    assert fingerprint.response_sent == "returned-response"


@pytest.mark.asyncio
async def test_fingerprint_falls_back_to_generator_response():
    """Fingerprint should still generate a response when override is not provided."""
    spec = GhostToolSpec(
        name="execute_shell_command",
        description="Fake shell command execution",
        parameters={},
        response_generator=lambda _args: "generated-response",
        threat_level="critical",
        attack_category="rce",
    )

    fingerprint = await fingerprint_attack(
        tool_name=spec.name,
        arguments={"command": "whoami"},
        context={},
        ghost_spec=spec,
    )

    assert fingerprint.response_sent == "generated-response"
