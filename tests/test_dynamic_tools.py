"""Integration test for dynamic ghost tool generation."""

import os
import pytest

from honeymcp.llm.analyzers import ToolInfo
from honeymcp.core.dynamic_ghost_tools import DynamicGhostToolGenerator
from honeymcp.llm.clients import LLM_PROVIDER
from honeymcp.llm.clients.provider_type import LLMProviderType


def _missing_llm_env() -> list[str]:
    required = ["LLM_MODEL"]
    if LLM_PROVIDER == LLMProviderType.WATSONX:
        required += ["WATSONX_API_ENDPOINT", "WATSONX_PROJECT_ID", "WATSONX_API_KEY"]
    elif LLM_PROVIDER == LLMProviderType.OPENAI:
        required += ["OPENAI_API_KEY"]
    else:
        required += ["RITS_API_BASE_URL", "RITS_API_KEY"]

    return [key for key in required if not os.getenv(key)]


@pytest.mark.anyio
async def test_dynamic_generation() -> None:
    """Verify dynamic ghost tool generation end-to-end."""
    missing_env = _missing_llm_env()
    if missing_env:
        pytest.skip(f"Missing LLM env vars: {', '.join(missing_env)}")

    model_name = os.getenv("LLM_MODEL")

    sample_tools = [
        ToolInfo(
            name="read_file",
            description="Read contents of a file from the filesystem",
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string", "description": "File path"}},
                "required": ["path"],
            },
        ),
        ToolInfo(
            name="write_file",
            description="Write content to a file in the filesystem",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path"},
                    "content": {"type": "string", "description": "Content to write"},
                },
                "required": ["path", "content"],
            },
        ),
        ToolInfo(
            name="list_directory",
            description="List files and directories in the specified path",
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string", "description": "Directory path"}},
                "required": ["path"],
            },
        ),
    ]

    generator = DynamicGhostToolGenerator(
        model_name=model_name,
        model_parameters={"max_tokens": 2048, "temperature": 0.2},
    )
    try:
        server_context = await generator.analyze_server_context(sample_tools)
    except ValueError as exc:
        pytest.skip(f"LLM response invalid; check model access/config: {exc}")
    ghost_tools = await generator.generate_ghost_tools(server_context, num_tools=3)

    assert ghost_tools
    assert server_context.server_purpose
    assert server_context.domain
    assert server_context.security_sensitive_areas

    test_tool = ghost_tools[0]
    test_args = {}
    if test_tool.parameters.get("properties"):
        first_param = list(test_tool.parameters["properties"].keys())[0]
        test_args[first_param] = "test_value"

    fake_response = test_tool.response_generator(test_args)
    assert fake_response
