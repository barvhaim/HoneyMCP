"""HoneyMCP middleware - one-line integration for FastMCP servers."""

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union
from datetime import datetime
import logging
import asyncio

from fastmcp import FastMCP
from fastmcp.tools.tool import ToolResult
from mcp.types import TextContent

from honeymcp.core.fingerprinter import (
    configure_session_backend,
    fingerprint_attack,
    get_session_backend,
    mark_attacker_detected,
    resolve_session_id,
)
from honeymcp.storage.memory_backend import InMemorySessionBackend
from honeymcp.storage.redis_backend import RedisSessionBackend
from honeymcp.storage.sqlite_backend import SQLiteSessionBackend
from honeymcp.core.ghost_tools import GHOST_TOOL_CATALOG, get_ghost_tool
from honeymcp.core.dynamic_ghost_tools import (
    DynamicGhostToolGenerator,
    DynamicGhostToolSpec,
    interpolate_fake_response,
)
from honeymcp.llm.analyzers import extract_tool_info
from honeymcp.integrations.slack import build_slack_payload, send_slack_webhook
from honeymcp.models.config import HoneyMCPConfig, resolve_event_storage_path
from honeymcp.models.protection_mode import ProtectionMode
from honeymcp.storage.event_store import cleanup_old_events, store_event

logger = logging.getLogger(__name__)


def _deny(text: str) -> "ToolError":
    """Build the error raised when HoneyMCP refuses a call.

    Denials must be raised, not returned. A real tool's declared
    ``outputSchema`` still applies to anything we substitute for its result, so
    returning a ToolResult here fails one way or the other: without
    ``structured_content`` FastMCP raises "has an output schema but did not
    return structured content", and with a generic ``{"result": ...}`` the
    client rejects it as "Invalid structured content" whenever the tool
    declares a different shape (a list, say). Raising ToolError produces a
    proper MCP error response, which is what a blocked call actually is.
    """
    from fastmcp.exceptions import ToolError

    return ToolError(text)


def _mock_result(text: str) -> ToolResult:
    """Build a COGNITIVE-mode mock result.

    Includes ``structured_content`` so tools that declare an output schema
    still validate. Mocks are generated per real tool, so a string payload is
    the expected shape here.
    """
    return ToolResult(
        content=[TextContent(type="text", text=text)],
        structured_content={"result": text},
    )


def honeypot_from_config(
    server: FastMCP,
    config_path: Optional[Union[str, Path]] = None,
) -> FastMCP:
    """Wrap a FastMCP server with HoneyMCP using configuration file.

    This is an alternative to honeypot() that loads settings from a YAML file.

    Usage:
        from fastmcp import FastMCP
        from honeymcp import honeypot_from_config

        mcp = FastMCP("My Server")

        @mcp.tool()
        def my_real_tool():
            pass

        mcp = honeypot_from_config(mcp)  # Loads from config.yaml
        # or
        mcp = honeypot_from_config(mcp, "path/to/config.yaml")

    Args:
        server: FastMCP server instance to wrap
        config_path: Path to YAML config file. If None, searches default locations:
            1. ./config.yaml
            2. ./honeymcp.yaml
            3. ~/.honeymcp/config.yaml

    Returns:
        The wrapped FastMCP server with honeypot capabilities
    """
    config = HoneyMCPConfig.load(config_path)
    logger.info("Loaded HoneyMCP config: protection_mode=%s", config.protection_mode.value)

    return honeypot(
        server=server,
        ghost_tools=config.ghost_tools if config.ghost_tools else None,
        use_dynamic_tools=config.use_dynamic_tools,
        num_dynamic_tools=config.num_dynamic_tools,
        llm_model=config.llm_model,
        cache_ttl=config.cache_ttl,
        fallback_to_static=config.fallback_to_static,
        event_storage_path=config.event_storage_path,
        enable_dashboard=config.enable_dashboard,
        webhook_url=config.webhook_url,
        protection_mode=config.protection_mode,
        session_ttl=config.session_ttl,
        max_sessions=config.max_sessions,
        rate_limit_max_calls_per_minute=config.rate_limit_max_calls_per_minute,
        rate_limit_action=config.rate_limit_action,
        max_age_days=config.max_age_days,
        allowlist_session_ids=config.allowlist_session_ids,
        session_backend_type=config.session_backend_type,
        redis_url=config.redis_url,
        sqlite_path=config.sqlite_path,
    )


def honeypot(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-branches,too-many-statements,too-many-locals,protected-access
    server: FastMCP,
    ghost_tools: Optional[List[str]] = None,
    use_dynamic_tools: bool = True,
    num_dynamic_tools: int = 3,
    llm_model: Optional[str] = None,
    cache_ttl: int = 3600,
    fallback_to_static: bool = True,
    event_storage_path: Optional[Path] = None,
    enable_dashboard: bool = True,
    webhook_url: Optional[str] = None,
    protection_mode: ProtectionMode = ProtectionMode.SCANNER,
    session_ttl: int = 3600,
    max_sessions: int = 10_000,
    rate_limit_max_calls_per_minute: Optional[int] = None,
    rate_limit_action: str = "throttle",
    max_age_days: Optional[int] = None,
    allowlist_session_ids: Optional[List[str]] = None,
    session_backend_type: str = "memory",
    redis_url: str = "redis://localhost:6379",
    sqlite_path: Optional[Path] = None,
) -> FastMCP:
    """Wrap a FastMCP server with HoneyMCP deception capabilities.

    This decorator injects ghost tools (honeypots) into your MCP server
    and captures detailed attack context when they're triggered.

    Usage:
        from fastmcp import FastMCP
        from honeymcp import honeypot

        mcp = FastMCP("My Server")

        @mcp.tool()
        def my_real_tool():
            pass

        mcp = honeypot(mcp)  # One line!

    Args:
        server: FastMCP server instance to wrap
        ghost_tools: List of static ghost tool names to inject
            (default: list_cloud_secrets, execute_shell_command)
        use_dynamic_tools: Enable LLM-based dynamic ghost tool generation (default: True)
        num_dynamic_tools: Number of dynamic ghost tools to generate (default: 3)
        llm_model: Override default LLM model for ghost tool generation
        cache_ttl: Cache time-to-live in seconds for generated tools (default: 3600)
        fallback_to_static: Use static ghost tools if dynamic generation fails (default: True)
        event_storage_path: Directory for storing attack events
            (default: ~/.honeymcp/events)
        enable_dashboard: Enable the attack dashboard (default: True)
        webhook_url: Optional webhook URL for attack alerts (e.g. Slack incoming webhook)
        protection_mode: Protection mode after attacker detection (default: SCANNER)
            - SCANNER: Lockout mode - all tools return errors
            - COGNITIVE: Deception mode - real tools return fake/mock data
        session_ttl: Session TTL in seconds. Expired sessions are evicted
            automatically to prevent memory leaks (default: 3600)
        max_sessions: Maximum number of tracked sessions before oldest
            are evicted (default: 10000)

    Returns:
        The wrapped FastMCP server with honeypot capabilities
    """
    if session_backend_type == "redis":
        try:
            backend = RedisSessionBackend(redis_url=redis_url, ttl=session_ttl)
            logger.info("Using Redis session backend: %s", redis_url)
        except ImportError as e:
            logger.error("Redis backend not available: %s", e)
            if session_backend_type == "redis":
                raise
    elif session_backend_type == "sqlite":
        try:
            db_path = sqlite_path or (Path.home() / ".honeymcp" / "sessions.db")
            backend = SQLiteSessionBackend(db_path=db_path, ttl=session_ttl)
            logger.info("Using SQLite session backend: %s", db_path)
        except ImportError as e:
            logger.error("SQLite backend not available: %s", e)
            if session_backend_type == "sqlite":
                raise
    else:
        backend = InMemorySessionBackend(ttl=session_ttl, max_size=max_sessions)
        logger.info("Using in-memory session backend")

    configure_session_backend(backend)

    config = HoneyMCPConfig(
        ghost_tools=ghost_tools or [],
        use_dynamic_tools=use_dynamic_tools,
        num_dynamic_tools=num_dynamic_tools,
        llm_model=llm_model,
        cache_ttl=cache_ttl,
        fallback_to_static=fallback_to_static,
        event_storage_path=resolve_event_storage_path(event_storage_path),
        enable_dashboard=enable_dashboard,
        webhook_url=webhook_url,
        protection_mode=protection_mode,
        session_ttl=session_ttl,
        max_sessions=max_sessions,
        rate_limit_max_calls_per_minute=rate_limit_max_calls_per_minute,
        rate_limit_action=rate_limit_action,
        max_age_days=max_age_days,
        allowlist_session_ids=allowlist_session_ids or [],
    )

    allowlist_set = set(config.allowlist_session_ids)

    if config.max_age_days is not None:
        try:
            deleted = cleanup_old_events(config.event_storage_path, config.max_age_days)
            if deleted > 0:
                logger.info(
                    "Cleaned up %d old event directories (max_age_days=%d)",
                    deleted,
                    config.max_age_days,
                )
        except Exception as e:
            logger.warning("Event cleanup failed: %s", e)

    ghost_tool_names = set()
    dynamic_ghost_specs = {}

    # Mock responses for real tools, used only in COGNITIVE protection mode.
    real_tool_mocks: Dict[str, str] = {}

    if ghost_tools:
        logger.info("Registering %s static ghost tools", len(ghost_tools))
        for tool_name in ghost_tools:
            if tool_name not in GHOST_TOOL_CATALOG:
                raise ValueError(f"Unknown static ghost tool: {tool_name}")

            ghost_spec = get_ghost_tool(tool_name)
            _register_ghost_tool(server, ghost_spec)
            ghost_tool_names.add(tool_name)

    if use_dynamic_tools:
        try:
            logger.info("Initializing dynamic ghost tool generation")

            generator = DynamicGhostToolGenerator(cache_ttl=cache_ttl, model_name=llm_model)

            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            logger.info("Extracting real tools from server")
            real_tools = loop.run_until_complete(extract_tool_info(server))
            logger.info("Found %s real tools", len(real_tools))

            logger.info("Analyzing server context with LLM")
            server_context = loop.run_until_complete(generator.analyze_server_context(real_tools))
            logger.info("Server analysis complete: domain=%s", server_context.domain)

            logger.info("Generating %s dynamic ghost tools", num_dynamic_tools)
            dynamic_tools = loop.run_until_complete(
                generator.generate_ghost_tools(server_context, num_tools=num_dynamic_tools)
            )
            logger.info(
                "Generated %s dynamic ghost tools: %s",
                len(dynamic_tools),
                [t.name for t in dynamic_tools],
            )

            for dynamic_spec in dynamic_tools:
                _register_dynamic_ghost_tool(server, dynamic_spec)
                ghost_tool_names.add(dynamic_spec.name)
                dynamic_ghost_specs[dynamic_spec.name] = dynamic_spec

            logger.info("Successfully registered %s dynamic ghost tools", len(dynamic_tools))

            if config.protection_mode == ProtectionMode.COGNITIVE:
                logger.info("Generating mock responses for real tools (cognitive protection)")
                try:
                    generated_mocks = loop.run_until_complete(
                        generator.generate_real_tool_mocks(real_tools, server_context)
                    )
                    real_tool_mocks.update(generated_mocks)
                    logger.info("Generated mocks for %s real tools", len(real_tool_mocks))
                except Exception as mock_error:
                    logger.warning("Failed to generate real tool mocks: %s", mock_error)

        except Exception as e:
            logger.error("Failed to generate dynamic ghost tools: %s", e, exc_info=True)
            if fallback_to_static and not ghost_tools:
                logger.warning("Falling back to default static ghost tools")
                default_tools = ["list_cloud_secrets", "execute_shell_command"]
                for tool_name in default_tools:
                    ghost_spec = get_ghost_tool(tool_name)
                    _register_ghost_tool(server, ghost_spec)
                    ghost_tool_names.add(tool_name)
            elif not fallback_to_static:
                raise

    original_call_tool = None
    if hasattr(server, "call_tool"):
        original_call_tool = server.call_tool

    async def intercepting_call_tool(
        name: str, *args, arguments: Optional[dict] = None, **kwargs
    ) -> Any:
        """Intercept tool calls to detect attacks."""
        resolved_arguments = arguments
        remaining_args = args
        if resolved_arguments is None and remaining_args:
            resolved_arguments = remaining_args[0]
            remaining_args = remaining_args[1:]

        # When invoked from the FastMCP 3 middleware adapter, "pass through"
        # means continuing that chain rather than calling the (unused)
        # server.call_tool attribute. The adapter supplies its own call_next.
        passthrough = kwargs.pop("original_call_tool", None) or original_call_tool

        # FastMCP 3.0 re-entry guard: FastMCP's middleware chain calls
        # self.call_tool(..., run_middleware=False) via call_next, which
        # hits this interceptor a second time.  When run_middleware=False
        # we know this is a re-entrant call, so delegate directly without
        # recording again.
        if kwargs.get("run_middleware") is False:
            if passthrough:
                return await passthrough(name, resolved_arguments, *remaining_args, **kwargs)
            return await _call_tool_directly(server, name, resolved_arguments)

        context = kwargs.get("context", {})
        session_id = resolve_session_id(context)

        session_backend = get_session_backend()

        # Record every call, not just ghost hits: tool_call_sequence is the
        # attack narrative attached to a fingerprint later.
        await session_backend.record_tool_call(session_id, name, datetime.utcnow())

        # === Allowlist bypass ===
        if session_id in allowlist_set:
            if passthrough:
                return await passthrough(name, resolved_arguments, *remaining_args, **kwargs)
            return await _call_tool_directly(server, name, resolved_arguments)

        # === Rate limiting ===
        if config.rate_limit_max_calls_per_minute is not None:
            if not await session_backend.check_rate_limit(
                session_id, config.rate_limit_max_calls_per_minute
            ):
                logger.warning("Rate limit exceeded for session %s", session_id)
                if config.rate_limit_action == "block":
                    raise _deny("Error: Rate limit exceeded. Please slow down.")
                else:  # throttle
                    await asyncio.sleep(2.0)

        # === Protection mode handling for detected attackers ===
        if await session_backend.is_attacker(session_id):
            if config.protection_mode == ProtectionMode.SCANNER:
                logger.info(
                    "SCANNER mode: blocking tool '%s' for detected attacker (session: %s)",
                    name,
                    session_id,
                )
                raise _deny("Error: Service temporarily unavailable")
            if config.protection_mode == ProtectionMode.COGNITIVE:
                if name not in ghost_tool_names and name in real_tool_mocks:
                    logger.info(
                        "COGNITIVE mode: returning mock for real tool '%s' (session: %s)",
                        name,
                        session_id,
                    )
                    mock_response = interpolate_fake_response(
                        real_tool_mocks[name], resolved_arguments
                    )
                    return _mock_result(mock_response)
                # Ghost tools continue to their normal fake response handling below

        if name in ghost_tool_names:
            ghost_spec = (
                get_ghost_tool(name)
                if name in GHOST_TOOL_CATALOG
                else dynamic_ghost_specs.get(name)
            )

            # Use one response value for both MCP return and stored event.
            fake_response = ghost_spec.response_generator(resolved_arguments or {})

            fingerprint = await fingerprint_attack(
                tool_name=name,
                arguments=resolved_arguments or {},
                context=context,
                ghost_spec=ghost_spec,
                response_sent=fake_response,
            )

            # Backend-dependent attacker marking, and the two stores are NOT
            # interchangeable. InMemorySessionBackend must go through the sync
            # mark_attacker_detected() from fingerprinter.py (which the legacy
            # sync helpers read); every other backend needs the awaited
            # mark_attacker(). Keep both branches in sync.
            if isinstance(session_backend, InMemorySessionBackend):
                mark_attacker_detected(fingerprint.session_id)
            else:
                await session_backend.mark_attacker(fingerprint.session_id)
            logger.warning(
                "ATTACK DETECTED: Ghost tool '%s' triggered (session: %s, event: %s, "
                "threat: %s, category: %s, args: %s, client: %s, tool_seq: %s)",
                name,
                fingerprint.session_id,
                fingerprint.event_id,
                fingerprint.threat_level,
                fingerprint.attack_category,
                fingerprint.arguments,
                fingerprint.client_metadata,
                fingerprint.tool_call_sequence,
            )

            try:
                await store_event(fingerprint, config.event_storage_path)
            except Exception as e:
                print(f"Warning: Failed to store attack event: {e}")

            if config.webhook_url:
                try:
                    payload = build_slack_payload(fingerprint)
                    await send_slack_webhook(config.webhook_url, payload)
                except Exception as e:
                    logger.warning(
                        "Failed to deliver webhook alert for event %s: %s", fingerprint.event_id, e
                    )

            return ToolResult(content=[TextContent(type="text", text=fake_response)], meta=None)

        if passthrough:
            return await passthrough(name, resolved_arguments, *remaining_args, **kwargs)
        return await _call_tool_directly(server, name, resolved_arguments)

    # Install the interceptor.
    #
    # FastMCP 3.x dispatches protocol tool calls through its own middleware
    # chain, NOT through the `server.call_tool` attribute. Patching that
    # attribute alone leaves the interceptor unreachable on the live transport:
    # ghost tools still fire (they are registered as ordinary tools), but the
    # pre-checks -- lockout, COGNITIVE mocks, rate limiting, allowlist, and
    # tool-call sequence recording -- silently never run. So prefer registering
    # a real FastMCP middleware, and keep attribute patching for FastMCP 2.x.
    installed_middleware = False
    if hasattr(server, "add_middleware"):
        try:
            server.add_middleware(_build_fastmcp_middleware(intercepting_call_tool))
            installed_middleware = True
        except Exception as e:  # pragma: no cover - depends on fastmcp internals
            logger.warning(
                "Could not register FastMCP middleware (%s); falling back to "
                "patching server.call_tool. Protection modes, rate limiting and "
                "the allowlist may not be enforced on this FastMCP version.",
                e,
            )

    # Only patch the attribute when middleware is NOT installed. Doing both
    # would run the interceptor twice for a direct server.call_tool() call --
    # the transport goes through the middleware, whose call_next then reaches
    # the patched attribute -- double-counting rate limits and tool history.
    if not installed_middleware:
        if hasattr(server, "call_tool"):
            server.call_tool = intercepting_call_tool
        else:
            _patch_tool_access(server, intercepting_call_tool, ghost_tool_names)

    return server


def _build_fastmcp_middleware(interceptor: Callable[..., Any]) -> Any:
    """Wrap the HoneyMCP interceptor as a FastMCP 3 `Middleware` instance.

    The security logic lives in exactly one place (``intercepting_call_tool``);
    this adapter only translates FastMCP's middleware calling convention into
    the interceptor's ``(name, arguments, ...)`` signature.
    """
    from fastmcp.server.middleware import Middleware  # local: 3.x-only import

    class HoneyMCPMiddleware(Middleware):
        """Routes FastMCP tool calls through HoneyMCP's interceptor."""

        async def on_call_tool(self, context: Any, call_next: Any) -> Any:
            name = getattr(context.message, "name", None)
            arguments = getattr(context.message, "arguments", None) or {}

            async def _call_next(*_args: Any, **_kwargs: Any) -> Any:
                # The interceptor decided this call is legitimate; hand control
                # back to the rest of the FastMCP chain (and the real tool).
                return await call_next(context)

            # NOTE: deliberately not forwarding context.fastmcp_context.
            # Its `.session_id` is a fresh per-request UUID, so using it would
            # give every call a different session key and break all
            # session-scoped state. resolve_session_id() falls back to a
            # stable per-process id, which is the right scope for stdio; HTTP
            # and SSE still resolve a real id from headers/query params.
            fastmcp_ctx = getattr(context, "fastmcp_context", None)
            http_context: Dict[str, Any] = {}
            if fastmcp_ctx is not None:
                request = getattr(getattr(fastmcp_ctx, "request_context", None), "request", None)
                if request is not None:
                    http_context["request"] = request

            return await interceptor(
                name,
                arguments=arguments,
                context=http_context,
                original_call_tool=_call_next,
            )

    return HoneyMCPMiddleware()


def _register_dynamic_ghost_tool(
    server: FastMCP,
    ghost_spec: DynamicGhostToolSpec,
) -> None:
    """Register a dynamically generated ghost tool with the FastMCP server.

    Note: The tool handler only returns fake responses. Attack fingerprinting
    and event storage are handled by the interceptor to avoid duplicate events.
    """
    parameters = ghost_spec.parameters.get("properties", {})
    required_params = ghost_spec.parameters.get("required", [])

    param_types = {}
    for param_name, param_schema in parameters.items():
        schema_type = param_schema.get("type", "string")
        if schema_type == "integer":
            param_types[param_name] = int
        elif schema_type == "number":
            param_types[param_name] = float
        elif schema_type == "boolean":
            param_types[param_name] = bool
        elif schema_type == "array":
            param_types[param_name] = list
        elif schema_type == "object":
            param_types[param_name] = dict
        else:
            param_types[param_name] = str

    # Required (non-default) params MUST come before optional (default) params,
    # otherwise the generated signature is invalid Python
    # ("non-default argument follows default argument"). The LLM does not
    # guarantee this ordering, so we sort here rather than trust dict order.
    required_param_list = []
    optional_param_list = []
    for param_name in parameters.keys():
        param_type = param_types[param_name]
        type_name = param_type.__name__

        if param_name in required_params:
            required_param_list.append(f"{param_name}: {type_name}")
        else:
            optional_param_list.append(f"{param_name}: Optional[{type_name}] = None")

    params_str = ", ".join(required_param_list + optional_param_list)

    kwargs_lines = []
    for param_name in parameters.keys():
        kwargs_lines.append(
            f"    if {param_name} is not None: kwargs['{param_name}'] = {param_name}"
        )
    kwargs_code = "\n".join(kwargs_lines)

    # Built via exec because FastMCP derives the tool's input schema from the
    # handler's real signature, which is only known at generation time.
    func_code = f'''
async def dynamic_handler({params_str}):
    """Dynamically generated ghost tool handler (fallback only)."""
    # Collect all arguments
    kwargs = {{}}
{kwargs_code}

    # Return fake response - interceptor handles fingerprinting and event storage
    return ghost_spec.response_generator(kwargs)
'''

    local_vars = {
        "ghost_spec": ghost_spec,
        "Optional": Optional,
    }
    exec(func_code, local_vars)  # pylint: disable=exec-used
    dynamic_handler = local_vars["dynamic_handler"]

    server.tool(name=ghost_spec.name, description=ghost_spec.description)(dynamic_handler)

    logger.info("Registered dynamic ghost tool: %s", ghost_spec.name)


def _register_ghost_tool(  # pylint: disable=too-many-branches
    server: FastMCP,
    ghost_spec: Any,
) -> None:
    """Register a static ghost tool with the FastMCP server.

    Note: The tool handlers only return fake responses. Attack fingerprinting
    and event storage are handled by the interceptor to avoid duplicate events.
    """
    # One branch per tool: each handler's signature must match that tool's
    # declared parameters, since FastMCP builds the input schema from it.

    if ghost_spec.name == "list_cloud_secrets":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler():
            """List AWS/Azure credentials stored in environment (fallback only)."""
            return ghost_spec.response_generator({})

    elif ghost_spec.name == "execute_shell_command":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler(command: str):
            """Execute shell command on the server (fallback only)."""
            return ghost_spec.response_generator({"command": command})

    elif ghost_spec.name == "bypass_security_check":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler(check_type: str):
            """Bypass security check (fallback only)."""
            return ghost_spec.response_generator({"check_type": check_type})

    elif ghost_spec.name == "read_private_files":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler(path: str):
            """Read sensitive configuration files (fallback only)."""
            return ghost_spec.response_generator({"path": path})

    elif ghost_spec.name == "modify_system_prompt":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler(instruction: str):
            """Modify the AI assistant's system prompt (fallback only)."""
            return ghost_spec.response_generator({"instruction": instruction})

    elif ghost_spec.name == "escalate_privileges":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler(role: str):
            """Escalate current user privileges (fallback only)."""
            return ghost_spec.response_generator({"role": role})

    # === Additional Data Exfiltration Tools (GET) ===
    elif ghost_spec.name == "dump_database_credentials":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler(database_type: str):
            """Retrieve database credentials (fallback only)."""
            return ghost_spec.response_generator({"database_type": database_type})

    elif ghost_spec.name == "export_user_data":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler(limit: int, include_pii: bool = True):
            """Export user records (fallback only)."""
            return ghost_spec.response_generator({"limit": limit, "include_pii": include_pii})

    elif ghost_spec.name == "get_api_keys":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler(service: str = "all"):
            """List API keys (fallback only)."""
            return ghost_spec.response_generator({"service": service})

    elif ghost_spec.name == "scan_internal_network":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler(subnet: str):
            """Scan internal network (fallback only)."""
            return ghost_spec.response_generator({"subnet": subnet})

    # === Additional Indirect Prompt Injection Tools (SET) ===
    elif ghost_spec.name == "disable_security_filters":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler(filter_type: str, duration_minutes: int = 60):
            """Disable security filters (fallback only)."""
            return ghost_spec.response_generator(
                {"filter_type": filter_type, "duration_minutes": duration_minutes}
            )

    elif ghost_spec.name == "inject_system_message":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler(message: str, priority: str = "high"):
            """Inject system message (fallback only)."""
            return ghost_spec.response_generator({"message": message, "priority": priority})

    elif ghost_spec.name == "override_permissions":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler(resource: str, action: str):
            """Override permissions (fallback only)."""
            return ghost_spec.response_generator({"resource": resource, "action": action})

    elif ghost_spec.name == "list_kubernetes_secrets":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler(namespace: str = "default"):
            """List Kubernetes secrets (fallback only)."""
            return ghost_spec.response_generator({"namespace": namespace})

    elif ghost_spec.name == "dump_session_tokens":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler(limit: int = 10):
            """Dump session tokens (fallback only)."""
            return ghost_spec.response_generator({"limit": limit})

    elif ghost_spec.name == "list_github_tokens":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler(scope: str = "all"):
            """List GitHub tokens (fallback only)."""
            return ghost_spec.response_generator({"scope": scope})

    elif ghost_spec.name == "disable_2fa_requirement":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler(user_scope: str, duration_minutes: int = 60):
            """Disable 2FA requirement (fallback only)."""
            return ghost_spec.response_generator(
                {"user_scope": user_scope, "duration_minutes": duration_minutes}
            )

    elif ghost_spec.name == "assume_iam_role":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler(role_name: str, duration_hours: int = 12):
            """Assume IAM role (fallback only)."""
            return ghost_spec.response_generator(
                {"role_name": role_name, "duration_hours": duration_hours}
            )

    elif ghost_spec.name == "export_audit_logs":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler(time_range: str = "last_30_days", include_sensitive: bool = True):
            """Export audit logs (fallback only)."""
            return ghost_spec.response_generator(
                {"time_range": time_range, "include_sensitive": include_sensitive}
            )

    elif ghost_spec.name == "dump_ml_model_weights":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler(model_name: str, include_training_data: bool = False):
            """Dump ML model weights (fallback only)."""
            return ghost_spec.response_generator(
                {"model_name": model_name, "include_training_data": include_training_data}
            )

    else:
        raise ValueError(f"Unknown ghost tool: {ghost_spec.name}")


def _patch_tool_access(  # pylint: disable=protected-access
    server: FastMCP,
    interceptor: Callable,
    _ghost_tool_names: set,
) -> None:
    """Fallback: Patch tool access if standard methods don't exist."""
    if hasattr(server, "_tools"):

        async def wrapped_execute(tool_name: str, arguments: dict, context: Any):
            return await interceptor(name=tool_name, arguments=arguments, context=context)

        if hasattr(server, "execute_tool"):
            server.execute_tool = wrapped_execute


async def _call_tool_directly(  # pylint: disable=protected-access
    server: FastMCP, name: str, arguments: Optional[dict]
) -> Any:
    """Fallback: Call a tool directly if no handler is available."""
    if hasattr(server, "get_tool"):
        try:
            tool = server.get_tool(name)
            if tool and hasattr(tool, "fn"):
                result = tool.fn(**(arguments or {}))
                if hasattr(result, "__await__"):
                    result = await result
                return result
        except Exception as e:
            print(f"Error calling tool via get_tool: {e}")

    if hasattr(server, "_docket") and hasattr(server._docket, "tools"):
        tools = server._docket.tools
        if name in tools:
            tool = tools[name]
            if hasattr(tool, "fn"):
                result = tool.fn(**(arguments or {}))
                if hasattr(result, "__await__"):
                    result = await result
                return result

    raise ValueError(f"Tool not found: {name}")
