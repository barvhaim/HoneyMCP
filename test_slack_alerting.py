"""Tests for Slack webhook alerting integration."""

from datetime import datetime, timezone

import pytest

from honeymcp.core import middleware
from honeymcp.integrations.slack import build_slack_payload, send_slack_webhook
from honeymcp.models.events import AttackFingerprint


def _sample_fingerprint() -> AttackFingerprint:
    return AttackFingerprint(
        event_id="evt_20260206_123000_abcd1234",
        timestamp=datetime(2026, 2, 6, 12, 30, 0, tzinfo=timezone.utc),
        session_id="sess_1234567890",
        ghost_tool_called="list_cloud_secrets",
        arguments={
            "username": "analyst",
            "api_token": "very-secret-value",
            "prompt": "x" * 500,
        },
        conversation_history=None,
        tool_call_sequence=[
            "safe_calculator",
            "search_docs",
            "list_cloud_secrets",
            "another_tool",
            "t5",
            "t6",
            "t7",
        ],
        threat_level="critical",
        attack_category="exfiltration",
        client_metadata={"user_agent": "test-agent"},
        response_sent="AWS_ACCESS_KEY_ID=AKIA...",
    )


def test_build_slack_payload_redacts_and_truncates() -> None:
    payload = build_slack_payload(_sample_fingerprint())

    assert payload["text"].startswith("ATTACK DETECTED")
    assert payload["blocks"][0]["type"] == "section"
    args_text = payload["blocks"][2]["text"]["text"]
    assert "api_token': '[REDACTED]'" in args_text or 'api_token": "[REDACTED]"' in args_text
    assert "..." in args_text
    assert "-> ..." in payload["blocks"][1]["fields"][3]["text"]


@pytest.mark.asyncio
async def test_send_slack_webhook_success(monkeypatch: pytest.MonkeyPatch) -> None:
    called = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

    def fake_post(url: str, json: dict, timeout: float) -> FakeResponse:
        called["url"] = url
        called["json"] = json
        called["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("honeymcp.integrations.slack.requests.post", fake_post)

    payload = {"text": "ok"}
    await send_slack_webhook("https://hooks.slack.test/abc", payload, timeout=1.5)

    assert called["url"] == "https://hooks.slack.test/abc"
    assert called["json"] == payload
    assert called["timeout"] == 1.5


@pytest.mark.asyncio
async def test_send_slack_webhook_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        def raise_for_status(self) -> None:
            raise RuntimeError("bad status")

    def fake_post(url: str, json: dict, timeout: float) -> FakeResponse:
        _ = (url, json, timeout)
        return FakeResponse()

    monkeypatch.setattr("honeymcp.integrations.slack.requests.post", fake_post)

    with pytest.raises(RuntimeError, match="bad status"):
        await send_slack_webhook("https://hooks.slack.test/abc", {"text": "x"})


def test_honeypot_from_config_passes_webhook_url(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "honeymcp.yaml"
    config_path.write_text(
        (
            "protection_mode: SCANNER\n"
            "alerting:\n"
            "  webhook_url: https://hooks.slack.test/abc\n"
            "dynamic_tools:\n"
            "  enabled: false\n"
            "ghost_tools:\n"
            "  - list_cloud_secrets\n"
        ),
        encoding="utf-8",
    )

    captured = {}

    def fake_honeypot(**kwargs):
        captured.update(kwargs)
        return kwargs["server"]

    monkeypatch.setattr(middleware, "honeypot", fake_honeypot)

    server = object()
    result = middleware.honeypot_from_config(server=server, config_path=config_path)

    assert result is server
    assert captured["webhook_url"] == "https://hooks.slack.test/abc"
