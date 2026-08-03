"""Tests for HoneyMCP FastAPI app."""

import asyncio
from datetime import datetime

from fastapi.testclient import TestClient

from honeymcp.api.app import create_app
from honeymcp.models.events import AttackFingerprint
from honeymcp.storage.event_store import store_event


def test_delete_events_endpoint(tmp_path):
    """DELETE /events removes stored event data."""
    storage_path = tmp_path / "events"
    config_path = tmp_path / "honeymcp.yaml"
    config_path.write_text(
        f"storage:\n  event_path: {storage_path}\n",
        encoding="utf-8",
    )

    app = create_app(config_path=config_path)
    client = TestClient(app)

    fingerprint = AttackFingerprint(
        event_id="api_delete_test",
        timestamp=datetime.now(),
        session_id="api_delete_session",
        ghost_tool_called="api_delete_tool",
        arguments={},
        threat_level="high",
        attack_category="exfiltration",
        response_sent="Fake response",
    )

    # Seed one event in the configured storage location.
    asyncio.run(store_event(fingerprint, storage_path=storage_path))

    delete_response = client.delete("/events")
    assert delete_response.status_code == 200
    body = delete_response.json()
    assert body["deleted_events"] == 1

    list_response = client.get("/events")
    assert list_response.status_code == 200
    assert list_response.json()["total"] == 0


def test_replay_start_filters_events_by_session(tmp_path):
    """POST /replay/start only loads events for the requested session."""
    storage_path = tmp_path / "events"
    config_path = tmp_path / "honeymcp.yaml"
    config_path.write_text(
        f"storage:\n  event_path: {storage_path}\n",
        encoding="utf-8",
    )

    app = create_app(config_path=config_path)
    client = TestClient(app)

    for session_id in ("target_session", "other_session"):
        fingerprint = AttackFingerprint(
            event_id=f"{session_id}_event",
            timestamp=datetime.now(),
            session_id=session_id,
            ghost_tool_called="api_replay_tool",
            arguments={},
            threat_level="high",
            attack_category="exfiltration",
            response_sent="Fake response",
        )
        asyncio.run(store_event(fingerprint, storage_path=storage_path))

    response = client.post("/replay/start", params={"session_id": "target_session"})

    assert response.status_code == 200
    body = response.json()
    assert body["session_id"] == "target_session"
    assert body["event_count"] == 1
