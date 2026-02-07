"""Slack webhook alerting for HoneyMCP attack events."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict

import requests

from honeymcp.models.events import AttackFingerprint

logger = logging.getLogger(__name__)

MAX_FIELD_CHARS = 300
MAX_SEQUENCE_LEN = 6


def _compact(value: Any, max_chars: int = MAX_FIELD_CHARS) -> str:
    text = str(value).replace("\n", " ").strip()
    if len(text) <= max_chars:
        return text
    return f"{text[: max_chars - 3]}..."


def _redacted_arguments(arguments: Dict[str, Any]) -> str:
    if not arguments:
        return "{}"
    redacted = {}
    for key, value in arguments.items():
        key_text = str(key).lower()
        if any(token in key_text for token in ("token", "secret", "password", "key", "credential")):
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = _compact(value, max_chars=80)
    return _compact(redacted)


def build_slack_payload(fingerprint: AttackFingerprint) -> Dict[str, Any]:
    """Build a compact Slack webhook payload from an attack fingerprint."""
    sequence = " -> ".join(fingerprint.tool_call_sequence[:MAX_SEQUENCE_LEN]) or "single call"
    if len(fingerprint.tool_call_sequence) > MAX_SEQUENCE_LEN:
        sequence = f"{sequence} -> ..."

    timestamp = fingerprint.timestamp.isoformat()
    arguments = _redacted_arguments(fingerprint.arguments)

    summary = (
        f"ATTACK DETECTED | threat={fingerprint.threat_level} "
        f"category={fingerprint.attack_category} tool={fingerprint.ghost_tool_called}"
    )

    return {
        "text": summary,
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        "*HoneyMCP attack detected*\n"
                        f"*Threat:* `{_compact(fingerprint.threat_level)}`\n"
                        f"*Category:* `{_compact(fingerprint.attack_category)}`\n"
                        f"*Ghost tool:* `{_compact(fingerprint.ghost_tool_called)}`"
                    ),
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Event ID*\n`{_compact(fingerprint.event_id)}`"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Session ID*\n`{_compact(fingerprint.session_id)}`",
                    },
                    {"type": "mrkdwn", "text": f"*Timestamp (UTC)*\n`{_compact(timestamp)}`"},
                    {"type": "mrkdwn", "text": f"*Tool Sequence*\n`{_compact(sequence)}`"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Arguments (redacted)*\n```{arguments}```",
                },
            },
        ],
    }


async def send_slack_webhook(
    webhook_url: str, payload: Dict[str, Any], timeout: float = 3.0
) -> None:
    """Send Slack webhook payload and raise on delivery errors."""

    def _post() -> None:
        response = requests.post(webhook_url, json=payload, timeout=timeout)
        response.raise_for_status()

    await asyncio.to_thread(_post)
