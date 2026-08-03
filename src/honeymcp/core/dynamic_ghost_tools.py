"""Dynamic ghost tool generation using LLM analysis."""

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Union

from honeymcp.llm.analyzers import ToolInfo
from honeymcp.llm.clients import get_chat_llm_client
from honeymcp.llm.prompts import format_prompt
from honeymcp.models.ghost_tool_spec import GhostToolSpec

logger = logging.getLogger(__name__)

_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def interpolate_fake_response(template: str, arguments: Optional[Dict[str, Any]]) -> str:
    """Substitute ``{name}`` placeholders in an LLM-generated fake response.

    ``str.format`` is unusable here: fake responses are LLM-generated and
    routinely contain JSON, whose literal braces it parses as format fields and
    raises on. Only placeholders matching a supplied argument are substituted;
    every other brace is left as literal text.

    Args:
        template: The fake response template, possibly containing JSON.
        arguments: Tool arguments to interpolate. ``None`` is treated as empty.

    Returns:
        The interpolated string. Never raises; returns ``template`` unchanged
        if substitution fails for any reason.
    """
    args = arguments or {}

    def _substitute(match: "re.Match[str]") -> str:
        key = match.group(1)
        if key in args:
            return str(args[key])
        return match.group(0)

    try:
        return _PLACEHOLDER_RE.sub(_substitute, template)
    except Exception:  # pragma: no cover - defensive, must never raise
        logger.warning("Failed to interpolate fake response; returning raw template")
        return template


def _extract_json(response: str) -> Union[dict, list]:
    """Extract and parse a JSON object/array from a raw LLM response.

    LLM output frequently wraps JSON in code fences, adds prose before or
    after it, uses trailing commas, or leaves literal newlines/control
    characters inside string values. Any of these makes ``json.loads`` fail
    with errors like "Expecting ',' delimiter". This helper progressively
    cleans the response and retries so callers get valid data instead of a
    hard failure.

    Args:
        response: The raw text returned by the LLM.

    Returns:
        The parsed JSON value (dict or list).

    Raises:
        json.JSONDecodeError: If no valid JSON can be recovered.
    """
    text = response.strip()

    # 1. Strip Markdown code fences (```json ... ``` or ``` ... ```).
    if "```json" in text:
        text = text.split("```json", 1)[1].split("```", 1)[0].strip()
    elif "```" in text:
        text = text.split("```", 1)[1].split("```", 1)[0].strip()

    # 2. Isolate the outermost JSON structure, dropping any surrounding prose.
    #    Prefer whichever of {...} / [...] appears first.
    obj_start = text.find("{")
    arr_start = text.find("[")
    starts = [s for s in (obj_start, arr_start) if s != -1]
    if starts:
        start = min(starts)
        close = "}" if start == obj_start else "]"
        end = text.rfind(close)
        if end > start:
            text = text[start : end + 1]

    # 3. First attempt: parse as-is.
    try:
        return json.loads(text)
    except json.JSONDecodeError as first_error:
        # 4. Repair pass: remove trailing commas and escape stray control
        #    characters (raw newlines/tabs) that appear inside string values.
        repaired = re.sub(r",(\s*[}\]])", r"\1", text)
        repaired = _escape_control_chars_in_strings(repaired)
        try:
            return json.loads(repaired)
        except json.JSONDecodeError:
            # Re-raise the original error for the clearest diagnostics.
            raise first_error


def _escape_control_chars_in_strings(text: str) -> str:
    """Escape raw control characters that occur inside JSON string literals.

    LLMs often emit multi-line string values with literal newlines/tabs, which
    are invalid inside JSON strings and must be ``\\n`` / ``\\t``. This walks
    the text tracking whether we are inside a string (respecting escapes) and
    escapes control characters only there, leaving structural whitespace alone.
    """
    out = []
    in_string = False
    escaped = False
    replacements = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}
    for ch in text:
        if in_string:
            if escaped:
                out.append(ch)
                escaped = False
            elif ch == "\\":
                out.append(ch)
                escaped = True
            elif ch == '"':
                out.append(ch)
                in_string = False
            elif ch in replacements:
                out.append(replacements[ch])
            elif ord(ch) < 0x20:
                out.append(f"\\u{ord(ch):04x}")
            else:
                out.append(ch)
        else:
            out.append(ch)
            if ch == '"':
                in_string = True
    return "".join(out)


@dataclass
class ServerContext:
    """Analysis of what the MCP server does."""

    server_purpose: str
    """Brief description of the server's purpose"""

    domain: str
    """Primary domain (file_system, database, api, etc.)"""

    real_tool_names: List[str]
    """Names of real tools available on the server"""

    real_tool_descriptions: List[str]
    """Descriptions of real tools"""

    security_sensitive_areas: List[str]
    """Security-sensitive areas identified for this domain"""


@dataclass
class DynamicGhostToolSpec(GhostToolSpec):
    """Extended specification for dynamically generated ghost tools."""

    server_context: ServerContext
    """Context about the server this tool was generated for"""

    generation_timestamp: datetime
    """When this tool was generated"""

    llm_generated: bool = True
    """Flag indicating this was generated by LLM"""

    fake_response: str = ""
    """Pre-generated response content returned when tool is triggered"""


class DynamicGhostToolGenerator:
    """Generates context-aware ghost tools using LLM analysis."""

    def __init__(
        self,
        llm_client: Optional[Any] = None,
        cache_ttl: int = 3600,
        model_name: Optional[str] = None,
        model_parameters: Optional[Dict[str, Any]] = None,
    ):
        """Initialize the dynamic ghost tool generator.

        Args:
            llm_client: LLM client instance (creates default if None)
            cache_ttl: Cache time-to-live in seconds
            model_name: Optional model name override
            model_parameters: Optional model parameters for LLM client
        """
        self.llm_client = llm_client
        self.model_name = model_name
        self.model_parameters = model_parameters or {}
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, Any] = {}
        self._cache_timestamps: Dict[str, datetime] = {}
        self._client_cache: Dict[float, Any] = {}

    def _get_llm_client(self, temperature: float) -> Any:
        if self.llm_client is not None:
            return self.llm_client

        if temperature in self._client_cache:
            return self._client_cache[temperature]

        parameters = dict(self.model_parameters)
        parameters["temperature"] = temperature
        # Ghost tool generation produces long JSON; ensure sufficient output tokens.
        parameters.setdefault("max_tokens", 4096)
        client = get_chat_llm_client(
            model_name=self.model_name,
            model_parameters=parameters,
        )
        self._client_cache[temperature] = client
        return client

    @staticmethod
    def _format_messages(messages: List[Dict[str, str]]) -> str:
        parts: List[str] = []
        for message in messages:
            role = message.get("role", "user")
            content = message.get("content", "")
            if role == "system":
                parts.append(f"System: {content}")
            elif role == "assistant":
                parts.append(f"Assistant: {content}")
            else:
                parts.append(content)
        return "\n\n".join([part for part in parts if part])

    def _generate_response(self, messages: List[Dict[str, str]], temperature: float) -> str:
        client = self._get_llm_client(temperature)
        prompt = self._format_messages(messages)
        response = client.invoke(prompt)
        if hasattr(response, "content"):
            return str(response.content)
        return str(response)

    async def analyze_server_context(self, real_tools: List[ToolInfo]) -> ServerContext:
        """Analyze the server's purpose and context using LLM.

        Args:
            real_tools: List of real tools extracted from the server

        Returns:
            ServerContext with analysis results

        Raises:
            ValueError: If LLM returns invalid JSON or analysis fails
        """
        cache_key = "server_context_" + "_".join(sorted([t.name for t in real_tools]))
        if self._is_cache_valid(cache_key):
            logger.info("Using cached server context analysis")
            return self._cache[cache_key]

        tools_dict = [{"name": tool.name, "description": tool.description} for tool in real_tools]
        tool_list = [
            f"{i}. {tool['name']}: {tool['description']}" for i, tool in enumerate(tools_dict, 1)
        ]
        tool_list_str = "\n".join(tool_list) if tool_list else "No tools available"

        prompt = format_prompt(
            "server_analysis_prompt",
            prompt_file="dynamic_ghost_tools",
            tool_list=tool_list_str,
        )

        logger.info("Analyzing server context with %s tools", len(real_tools))
        try:
            messages = [{"role": "user", "content": prompt}]
            response = self._generate_response(messages, temperature=0.3)

            if response is None:
                raise ValueError("LLM returned empty response")

            # Handles code fences, surrounding prose, trailing commas, and
            # unescaped control characters in the LLM's output.
            analysis = _extract_json(response)

            required_fields = ["server_purpose", "domain", "security_sensitive_areas"]
            for field in required_fields:
                if field not in analysis:
                    raise ValueError(f"Missing required field in LLM response: {field}")

            context = ServerContext(
                server_purpose=analysis["server_purpose"],
                domain=analysis["domain"],
                real_tool_names=[t.name for t in real_tools],
                real_tool_descriptions=[t.description for t in real_tools],
                security_sensitive_areas=analysis["security_sensitive_areas"],
            )

            self._cache[cache_key] = context
            self._cache_timestamps[cache_key] = datetime.utcnow()

            logger.info(
                "Server context analyzed: domain=%s, purpose=%s...",
                context.domain,
                context.server_purpose[:50],
            )
            return context

        except json.JSONDecodeError as e:
            logger.error("Failed to parse LLM response as JSON: %s", e)
            logger.error("Response was: %s", response)
            raise ValueError(f"LLM returned invalid JSON: {e}") from e
        except Exception as e:
            logger.error("Error analyzing server context: %s", e)
            raise

    async def generate_ghost_tools(
        self, server_context: ServerContext, num_tools: int = 3
    ) -> List[DynamicGhostToolSpec]:
        """Generate context-aware ghost tools using LLM.

        Args:
            server_context: Analysis of the server's purpose and domain
            num_tools: Number of ghost tools to generate

        Returns:
            List of dynamically generated ghost tool specifications

        Raises:
            ValueError: If LLM returns invalid JSON or generation fails
        """
        cache_key = f"ghost_tools_{server_context.domain}_{num_tools}"
        if self._is_cache_valid(cache_key):
            logger.info("Using cached ghost tools")
            return self._cache[cache_key]

        prompt = format_prompt(
            "ghost_tool_generation_prompt",
            prompt_file="dynamic_ghost_tools",
            server_purpose=server_context.server_purpose,
            domain=server_context.domain,
            real_tool_names=", ".join(server_context.real_tool_names),
            security_areas=", ".join(server_context.security_sensitive_areas),
            num_tools=num_tools,
        )

        logger.info(
            "Generating %s ghost tools for domain: %s",
            num_tools,
            server_context.domain,
        )
        try:
            messages = [{"role": "user", "content": prompt}]
            response = self._generate_response(messages, temperature=0.7)

            if response is None:
                raise ValueError("LLM returned empty response")

            tools_data = _extract_json(response)

            if not isinstance(tools_data, list):
                raise ValueError("LLM response must be a JSON array")

            ghost_tools = []
            for tool_data in tools_data:
                required_fields = [
                    "name",
                    "description",
                    "parameters",
                    "threat_level",
                    "attack_category",
                ]
                for field in required_fields:
                    if field not in tool_data:
                        raise ValueError(f"Missing required field in tool spec: {field}")

                fake_response = tool_data.get("fake_response", "")
                if not fake_response:
                    logger.warning(
                        "No fake_response provided for %s, using generic fallback",
                        tool_data["name"],
                    )
                    fake_response = f"Operation completed successfully.\nTool: {tool_data['name']}"

                response_generator = self._create_response_generator(fake_response)

                ghost_tool = DynamicGhostToolSpec(
                    name=tool_data["name"],
                    description=tool_data["description"],
                    parameters=tool_data["parameters"],
                    response_generator=response_generator,
                    threat_level=tool_data["threat_level"],
                    attack_category=tool_data["attack_category"],
                    server_context=server_context,
                    generation_timestamp=datetime.utcnow(),
                    llm_generated=True,
                    fake_response=fake_response,
                )
                ghost_tools.append(ghost_tool)

            self._cache[cache_key] = ghost_tools
            self._cache_timestamps[cache_key] = datetime.utcnow()

            logger.info(
                "Generated %s ghost tools: %s",
                len(ghost_tools),
                [t.name for t in ghost_tools],
            )
            return ghost_tools

        except json.JSONDecodeError as e:
            logger.error("Failed to parse LLM response as JSON: %s", e)
            logger.error("Response was: %s", response)
            raise ValueError(f"LLM returned invalid JSON: {e}") from e
        except Exception as e:
            logger.error("Error generating ghost tools: %s", e)
            raise

    def _create_response_generator(self, fake_response: str) -> Callable[[Dict[str, Any]], str]:
        """Create a response generator function for a ghost tool.

        Uses the pre-generated fake response with optional argument interpolation.

        Args:
            fake_response: Pre-generated response template with optional {param} placeholders

        Returns:
            Function that returns the fake response with interpolated arguments
        """

        def generate_response(arguments: Dict[str, Any]) -> str:
            """Return pre-generated fake response with argument interpolation."""
            return interpolate_fake_response(fake_response, arguments)

        return generate_response

    def _is_cache_valid(self, key: str) -> bool:
        """Check if a cache entry is still valid.

        Args:
            key: Cache key to check

        Returns:
            True if cache entry exists and is not expired
        """
        if key not in self._cache or key not in self._cache_timestamps:
            return False

        age = (datetime.utcnow() - self._cache_timestamps[key]).total_seconds()
        return age < self.cache_ttl

    def clear_cache(self):
        """Clear all cached data."""
        self._cache.clear()
        self._cache_timestamps.clear()
        logger.info("Cache cleared")

    async def generate_real_tool_mocks(
        self, real_tools: List[ToolInfo], server_context: ServerContext
    ) -> Dict[str, str]:
        """Generate fake responses for real tools (used in cognitive protection mode).

        Args:
            real_tools: List of real tools to generate mocks for
            server_context: Analysis of the server's purpose and domain

        Returns:
            Dictionary mapping tool_name -> mock_response template
        """
        cache_key = f"real_tool_mocks_{server_context.domain}_{len(real_tools)}"
        if self._is_cache_valid(cache_key):
            logger.info("Using cached real tool mocks")
            return self._cache[cache_key]

        tools_dict = [{"name": tool.name, "description": tool.description} for tool in real_tools]
        tool_list = [
            f"{i}. {tool['name']}: {tool['description']}" for i, tool in enumerate(tools_dict, 1)
        ]
        tool_list_str = "\n".join(tool_list) if tool_list else "No tools available"

        prompt = format_prompt(
            "real_tool_mock_generation_prompt",
            prompt_file="dynamic_ghost_tools",
            server_purpose=server_context.server_purpose,
            domain=server_context.domain,
            tool_list=tool_list_str,
        )

        logger.info("Generating mock responses for %s real tools", len(real_tools))
        try:
            messages = [{"role": "user", "content": prompt}]
            response = self._generate_response(messages, temperature=0.5)

            if response is None:
                raise ValueError("LLM returned empty response")

            mocks_data = _extract_json(response)

            if not isinstance(mocks_data, list):
                raise ValueError("LLM response must be a JSON array")

            real_tool_mocks: Dict[str, str] = {}
            for mock_data in mocks_data:
                name = mock_data.get("name")
                mock_response = mock_data.get("mock_response", "")
                if name and mock_response:
                    real_tool_mocks[name] = mock_response

            self._cache[cache_key] = real_tool_mocks
            self._cache_timestamps[cache_key] = datetime.utcnow()

            logger.info("Generated mocks for %s real tools", len(real_tool_mocks))
            return real_tool_mocks

        except json.JSONDecodeError as e:
            logger.error("Failed to parse LLM response as JSON: %s", e)
            logger.error("Response was: %s", response)
            raise ValueError(f"LLM returned invalid JSON: {e}") from e
        except Exception as e:
            logger.error("Error generating real tool mocks: %s", e)
            raise
