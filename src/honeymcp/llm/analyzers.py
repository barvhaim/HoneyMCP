"""Tool and server analysis utilities."""

import inspect
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP

logger = logging.getLogger(__name__)


@dataclass
class ToolInfo:
    """Information about a tool extracted from an MCP server."""

    name: str
    """Tool name"""

    description: str
    """Tool description"""

    parameters: Dict[str, Any]
    """JSON schema for tool parameters"""

    category: Optional[str] = None
    """Optional category classification"""


async def extract_tool_info(  # pylint: disable=too-many-branches,too-many-statements,too-many-nested-blocks,protected-access
    server: FastMCP,
) -> List[ToolInfo]:
    """Extract tool information from a FastMCP server.

    This function attempts to extract tool information using multiple methods
    to ensure compatibility with different FastMCP versions.

    Args:
        server: FastMCP server instance

    Returns:
        List of ToolInfo objects containing tool metadata

    Raises:
        ValueError: If no tools can be extracted from the server
    """
    tools = []

    # Method 1: Try using the public list_tools method if available
    if hasattr(server, "list_tools"):
        try:
            tool_list = await server.list_tools()
            for tool in tool_list:
                # Handle both dict and object formats
                if isinstance(tool, dict):
                    name = tool.get("name", "unknown")
                    description = tool.get("description", "No description")
                    parameters = tool.get("inputSchema", {})
                else:
                    # Handle FunctionTool or similar objects
                    name = getattr(tool, "name", "unknown")
                    description = getattr(tool, "description", "No description")
                    parameters = getattr(tool, "inputSchema", {})
                    if not parameters and hasattr(tool, "parameters"):
                        parameters = tool.parameters

                tools.append(
                    ToolInfo(
                        name=name,
                        description=description,
                        parameters=parameters,
                        category=None,
                    )
                )
            if tools:
                logger.info("Extracted %s tools using list_tools method", len(tools))
                return tools
        except Exception as e:
            logger.warning("Failed to extract tools using list_tools: %s", e)

    # Method 2: Try accessing internal _tools dictionary
    if hasattr(server, "_tools"):
        try:
            internal_tools = server._tools
            for tool_name, tool_obj in internal_tools.items():
                description = "No description"
                parameters = {}

                # Extract description
                if hasattr(tool_obj, "description"):
                    description = tool_obj.description
                elif hasattr(tool_obj, "__doc__") and tool_obj.__doc__:
                    description = tool_obj.__doc__.strip()

                # Extract parameters from function signature if available
                if hasattr(tool_obj, "fn"):
                    sig = inspect.signature(tool_obj.fn)
                    properties = {}
                    required = []

                    for param_name, param in sig.parameters.items():
                        if param_name in ("self", "cls"):
                            continue

                        param_type = "string"  # Default type
                        if param.annotation != inspect.Parameter.empty:
                            if param.annotation == int:
                                param_type = "integer"
                            elif param.annotation == float:
                                param_type = "number"
                            elif param.annotation == bool:
                                param_type = "boolean"
                            elif param.annotation == list:
                                param_type = "array"
                            elif param.annotation == dict:
                                param_type = "object"

                        properties[param_name] = {
                            "type": param_type,
                            "description": f"Parameter {param_name}",
                        }

                        if param.default == inspect.Parameter.empty:
                            required.append(param_name)

                    if properties:
                        parameters = {
                            "type": "object",
                            "properties": properties,
                            "required": required,
                        }

                tools.append(
                    ToolInfo(
                        name=tool_name,
                        description=description,
                        parameters=parameters,
                        category=None,
                    )
                )

            if tools:
                logger.info("Extracted %s tools using _tools dictionary", len(tools))
                return tools
        except Exception as e:
            logger.warning("Failed to extract tools using _tools: %s", e)

    # Method 3: Try accessing internal docket
    if hasattr(server, "_docket") and hasattr(server._docket, "tools"):
        try:
            docket_tools = server._docket.tools
            for tool_name, tool_obj in docket_tools.items():
                description = "No description"
                parameters = {}

                if hasattr(tool_obj, "description"):
                    description = tool_obj.description

                if hasattr(tool_obj, "parameters"):
                    parameters = tool_obj.parameters
                elif hasattr(tool_obj, "input_schema"):
                    parameters = tool_obj.input_schema

                tools.append(
                    ToolInfo(
                        name=tool_name,
                        description=description,
                        parameters=parameters,
                        category=None,
                    )
                )

            if tools:
                logger.info("Extracted %s tools using _docket", len(tools))
                return tools
        except Exception as e:
            logger.warning("Failed to extract tools using _docket: %s", e)

    # If no tools were extracted, raise an error
    if not tools:
        raise ValueError(
            "Could not extract tools from FastMCP server. "
            "The server may not have any tools registered, or the FastMCP version "
            "may not be compatible with the extraction methods."
        )

    return tools


def categorize_tools(tools: List[ToolInfo]) -> Dict[str, List[ToolInfo]]:
    """Categorize tools based on their names and descriptions.

    Args:
        tools: List of ToolInfo objects

    Returns:
        Dictionary mapping category names to lists of tools
    """
    categories = {
        "file_system": [],
        "database": [],
        "api": [],
        "security": [],
        "development": [],
        "communication": [],
        "data_processing": [],
        "other": [],
    }

    # Keywords for each category
    category_keywords = {
        "file_system": [
            "file",
            "read",
            "write",
            "directory",
            "path",
            "folder",
            "upload",
            "download",
        ],
        "database": [
            "database",
            "query",
            "sql",
            "table",
            "record",
            "insert",
            "update",
            "delete",
        ],
        "api": ["api", "request", "response", "endpoint", "http", "rest", "graphql"],
        "security": [
            "auth",
            "token",
            "credential",
            "password",
            "key",
            "secret",
            "permission",
        ],
        "development": [
            "build",
            "deploy",
            "test",
            "debug",
            "compile",
            "run",
            "execute",
        ],
        "communication": ["send", "message", "email", "notify", "alert", "webhook"],
        "data_processing": [
            "process",
            "transform",
            "parse",
            "convert",
            "analyze",
            "calculate",
        ],
    }

    for tool in tools:
        text = f"{tool.name} {tool.description}".lower()
        categorized = False

        for category, keywords in category_keywords.items():
            if any(keyword in text for keyword in keywords):
                categories[category].append(tool)
                tool.category = category
                categorized = True
                break

        if not categorized:
            categories["other"].append(tool)
            tool.category = "other"

    # Remove empty categories
    return {k: v for k, v in categories.items() if v}
