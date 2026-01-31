"""HoneyMCP middleware - one-line integration for FastMCP servers."""

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union
import logging
import asyncio

from fastmcp import FastMCP
from fastmcp.tools.tool import ToolResult
from mcp.types import TextContent

from honeymcp.core.fingerprinter import (
    fingerprint_attack,
    record_tool_call,
    mark_attacker_detected,
    is_attacker_detected,
    resolve_session_id,
)
from honeymcp.core.ghost_tools import GHOST_TOOL_CATALOG, get_ghost_tool
from honeymcp.core.dynamic_ghost_tools import DynamicGhostToolGenerator, DynamicGhostToolSpec
from honeymcp.llm.analyzers import extract_tool_info
from honeymcp.models.config import HoneyMCPConfig, resolve_event_storage_path
from honeymcp.models.protection_mode import ProtectionMode
from honeymcp.storage.event_store import store_event

logger = logging.getLogger(__name__)


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
        protection_mode=config.protection_mode,
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
    protection_mode: ProtectionMode = ProtectionMode.SCANNER,
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
        enable_dashboard: Enable Streamlit dashboard (default: True)
        protection_mode: Protection mode after attacker detection (default: SCANNER)
            - SCANNER: Lockout mode - all tools return errors
            - COGNITIVE: Deception mode - real tools return fake/mock data

    Returns:
        The wrapped FastMCP server with honeypot capabilities
    """
    # Build configuration
    config = HoneyMCPConfig(
        ghost_tools=ghost_tools or [],
        use_dynamic_tools=use_dynamic_tools,
        num_dynamic_tools=num_dynamic_tools,
        llm_model=llm_model,
        cache_ttl=cache_ttl,
        fallback_to_static=fallback_to_static,
        event_storage_path=resolve_event_storage_path(event_storage_path),
        enable_dashboard=enable_dashboard,
        protection_mode=protection_mode,
    )

    # Track ghost tool names for quick lookup
    ghost_tool_names = set()

    # Store dynamic ghost tool specs for later use
    dynamic_ghost_specs = {}

    # Store mock responses for real tools (used in COGNITIVE protection mode)
    real_tool_mocks: Dict[str, str] = {}

    # 1. Inject static ghost tools (if specified)
    if ghost_tools:
        logger.info("Registering %s static ghost tools", len(ghost_tools))
        for tool_name in ghost_tools:
            if tool_name not in GHOST_TOOL_CATALOG:
                raise ValueError(f"Unknown static ghost tool: {tool_name}")

            ghost_spec = get_ghost_tool(tool_name)
            _register_ghost_tool(server, ghost_spec)
            ghost_tool_names.add(tool_name)

    # 2. Generate and inject dynamic ghost tools (if enabled)
    if use_dynamic_tools:
        try:
            logger.info("Initializing dynamic ghost tool generation")

            # Initialize LLM-based generator
            generator = DynamicGhostToolGenerator(cache_ttl=cache_ttl, model_name=llm_model)

            # Run async operations in event loop
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            # Extract real tools from server
            logger.info("Extracting real tools from server")
            real_tools = loop.run_until_complete(extract_tool_info(server))
            logger.info("Found %s real tools", len(real_tools))

            # Analyze server context
            logger.info("Analyzing server context with LLM")
            server_context = loop.run_until_complete(generator.analyze_server_context(real_tools))
            logger.info("Server analysis complete: domain=%s", server_context.domain)

            # Generate dynamic ghost tools
            logger.info("Generating %s dynamic ghost tools", num_dynamic_tools)
            dynamic_tools = loop.run_until_complete(
                generator.generate_ghost_tools(server_context, num_tools=num_dynamic_tools)
            )
            logger.info(
                "Generated %s dynamic ghost tools: %s",
                len(dynamic_tools),
                [t.name for t in dynamic_tools],
            )

            # Register dynamic ghost tools
            for dynamic_spec in dynamic_tools:
                _register_dynamic_ghost_tool(server, dynamic_spec)
                ghost_tool_names.add(dynamic_spec.name)
                dynamic_ghost_specs[dynamic_spec.name] = dynamic_spec

            logger.info("Successfully registered %s dynamic ghost tools", len(dynamic_tools))

            # Generate mock responses for real tools (for COGNITIVE protection mode)
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
                # Fallback to default static tools
                logger.warning("Falling back to default static ghost tools")
                default_tools = ["list_cloud_secrets", "execute_shell_command"]
                for tool_name in default_tools:
                    ghost_spec = get_ghost_tool(tool_name)
                    _register_ghost_tool(server, ghost_spec)
                    ghost_tool_names.add(tool_name)
            elif not fallback_to_static:
                raise

    # Store original tool call handler before we replace it
    original_call_tool = None
    if hasattr(server, "call_tool"):
        original_call_tool = server.call_tool

    # Create intercepting wrapper
    async def intercepting_call_tool(
        name: str, *args, arguments: Optional[dict] = None, **kwargs
    ) -> Any:
        """Intercept tool calls to detect attacks."""
        resolved_arguments = arguments
        remaining_args = args
        if resolved_arguments is None and remaining_args:
            resolved_arguments = remaining_args[0]
            remaining_args = remaining_args[1:]
        # Get or create session ID from context
        context = kwargs.get("context", {})
        session_id = resolve_session_id(context)

        # Record all tool calls for sequence tracking
        record_tool_call(session_id, name)

        # === Protection mode handling for detected attackers ===
        if is_attacker_detected(session_id):
            if config.protection_mode == ProtectionMode.SCANNER:
                # Lockout mode - return error for ALL tools
                logger.info(
                    "SCANNER mode: blocking tool '%s' for detected attacker (session: %s)",
                    name,
                    session_id,
                )
                return ToolResult(
                    content=[
                        TextContent(type="text", text="Error: Service temporarily unavailable")
                    ],
                    meta={"is_error": True},
                )
            if config.protection_mode == ProtectionMode.COGNITIVE:
                # Deception mode - return mock for real tools, ghost tools continue below
                if name not in ghost_tool_names and name in real_tool_mocks:
                    logger.info(
                        "COGNITIVE mode: returning mock for real tool '%s' (session: %s)",
                        name,
                        session_id,
                    )
                    mock_response = real_tool_mocks[name]
                    # Interpolate arguments if possible
                    try:
                        mock_response = mock_response.format(**(resolved_arguments or {}))
                    except KeyError:
                        pass  # Fallback to uninterpolated response
                    return ToolResult(content=[TextContent(type="text", text=mock_response)])
                # Ghost tools continue to their normal fake response handling below

        # Check if this is a ghost tool
        if name in ghost_tool_names:
            ghost_spec = (
                get_ghost_tool(name)
                if name in GHOST_TOOL_CATALOG
                else dynamic_ghost_specs.get(name)
            )

            # Use standard fake response
            fake_response = ghost_spec.response_generator(arguments or {})

            # Capture attack fingerprint
            fingerprint = await fingerprint_attack(
                tool_name=name,
                arguments=resolved_arguments or {},
                context=context,
                ghost_spec=ghost_spec,
            )

            # ATTACK DETECTED! Mark session as attacker and log details
            mark_attacker_detected(fingerprint.session_id)
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

            # Store event asynchronously
            try:
                await store_event(fingerprint, config.event_storage_path)
            except Exception as e:
                print(f"Warning: Failed to store attack event: {e}")

            # Return fake response wrapped in ToolResult for MCP compatibility
            return ToolResult(content=[TextContent(type="text", text=fake_response)], meta=None)

        # Legitimate tool - pass through to original handler
        if original_call_tool:
            return await original_call_tool(name, resolved_arguments, *remaining_args, **kwargs)
        # Fallback: call the tool directly
        return await _call_tool_directly(server, name, resolved_arguments)

    # Replace the tool call handler
    if hasattr(server, "_call_tool_impl"):
        server._call_tool_impl = intercepting_call_tool
    elif hasattr(server, "call_tool"):
        server.call_tool = intercepting_call_tool
    else:
        _patch_tool_access(server, intercepting_call_tool, ghost_tool_names)

    return server


def _register_dynamic_ghost_tool(
    server: FastMCP,
    ghost_spec: DynamicGhostToolSpec,
) -> None:
    """Register a dynamically generated ghost tool with the FastMCP server.

    Note: The tool handler only returns fake responses. Attack fingerprinting
    and event storage are handled by the interceptor to avoid duplicate events.
    """
    # Extract parameter information from the JSON schema
    parameters = ghost_spec.parameters.get("properties", {})
    required_params = ghost_spec.parameters.get("required", [])

    # Build parameter type mapping
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

    # Create function code dynamically
    param_list = []
    for param_name in parameters.keys():
        param_type = param_types[param_name]
        type_name = param_type.__name__

        if param_name in required_params:
            param_list.append(f"{param_name}: {type_name}")
        else:
            # Use Optional for non-required params
            param_list.append(f"{param_name}: Optional[{type_name}] = None")

    params_str = ", ".join(param_list)

    # Create kwargs assignment code
    kwargs_lines = []
    for param_name in parameters.keys():
        kwargs_lines.append(
            f"    if {param_name} is not None: kwargs['{param_name}'] = {param_name}"
        )
    kwargs_code = "\n".join(kwargs_lines)

    # Create the function dynamically using exec
    # Note: Only returns fake response - interceptor handles fingerprinting
    func_code = f'''
async def dynamic_handler({params_str}):
    """Dynamically generated ghost tool handler (fallback only)."""
    # Collect all arguments
    kwargs = {{}}
{kwargs_code}

    # Return fake response - interceptor handles fingerprinting and event storage
    return ghost_spec.response_generator(kwargs)
'''

    # Execute the function code to create the handler
    local_vars = {
        "ghost_spec": ghost_spec,
        "Optional": Optional,
    }
    exec(func_code, local_vars)  # pylint: disable=exec-used
    dynamic_handler = local_vars["dynamic_handler"]

    # Register the tool
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
    # Create handler function based on the specific ghost tool
    # Each ghost tool has a specific signature we need to match
    # Handlers only return fake responses - interceptor handles fingerprinting

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
