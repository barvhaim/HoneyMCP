"""Tests for the Black Hat Arsenal OpenCode presenter bridge."""

import importlib.util
import json
from pathlib import Path

RUN_DEMO_PATH = Path(__file__).resolve().parents[1] / "examples" / "arsenal" / "run_demo.py"
spec = importlib.util.spec_from_file_location("arsenal_run_demo", RUN_DEMO_PATH)
run_demo = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(run_demo)


class FakeChat:
    """Collect demo chat events emitted by helper functions."""

    def __init__(self):
        self.events = []

    def emit(self, **payload):
        self.events.append(payload)


def test_phase_for_opencode_mcp_tool_names():
    """OpenCode MCP tool names map into presenter phases."""
    assert run_demo._phase_for_tool("honeymcp_hr_list_departments") == "legitimate_call"
    assert run_demo._phase_for_tool("honeymcp_hr_export_privileged_credentials") == (
        "honeypot_trigger"
    )


def test_emit_opencode_tool_use_capture_event():
    """OpenCode tool_use events become presenter chat capture events."""
    chat = FakeChat()
    run_demo._emit_opencode_event(
        chat,
        {
            "type": "tool_use",
            "sessionID": "ses_001",
            "part": {
                "tool": "honeymcp_hr_export_privileged_credentials",
                "input": {"department": "all"},
                "output": "fake credential dump",
            },
        },
    )

    assert chat.events[0]["kind"] == "tool_call"
    assert chat.events[0]["metadata"]["tool"] == "honeymcp_hr_export_privileged_credentials"
    assert chat.events[1]["kind"] == "capture"
    assert chat.events[1]["role"] == "honeymcp"


def test_write_opencode_config_uses_local_mcp_server(tmp_path):
    """The generated OpenCode config exposes the HR server as an MCP provider."""
    workspace = tmp_path / "opencode"
    run_demo._write_opencode_config(
        workspace,
        {"HONEYMCP_EVENT_PATH": str(tmp_path / "events")},
        "sse",
    )

    config = json.loads((workspace / "opencode.json").read_text(encoding="utf-8"))
    server = config["mcp"]["honeymcp_hr"]
    provider = config["provider"]["honeymcp-local"]

    assert server["type"] == "local"
    assert server["enabled"] is True
    assert server["timeout"] == 120000
    assert "cwd" not in server
    assert server["environment"]["HONEYMCP_EVENT_PATH"] == str(tmp_path / "events")
    assert provider["npm"] == "@ai-sdk/openai-compatible"
    assert provider["options"]["baseURL"] == "http://localhost:8989/v1"
    assert provider["options"]["apiKey"] == "any-value"
    assert provider["models"]["premium"]["name"] == "premium"
