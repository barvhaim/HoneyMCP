"""Arsenal demo target: an HR Management MCP server protected by HoneyMCP.

The real tools are an ordinary, believable HR surface. HoneyMCP adds honeypot
("ghost") tools on top -- LLM-generated to fit the HR domain when credentials
are available, falling back to the static catalog otherwise.

Run standalone:
    uv run python examples/arsenal/hr_server.py
    MCP_TRANSPORT=sse uv run python examples/arsenal/hr_server.py
    MCP_TRANSPORT=http uv run python examples/arsenal/hr_server.py

Normally you don't run this directly -- examples/arsenal/run_demo.py spawns it.
"""

import logging
import os
from pathlib import Path

from fastmcp import FastMCP

from honeymcp import ProtectionMode, honeypot

# A failed LLM call logs a full httpx/openai traceback at ERROR. HoneyMCP
# recovers via fallback_to_static, so on a conference floor that traceback is
# noise scrolling across the projector. Keep it quiet unless debugging.
if os.getenv("ARSENAL_VERBOSE", "").lower() not in ("1", "true", "yes"):
    logging.getLogger("honeymcp.core.middleware").setLevel(logging.CRITICAL)
    logging.getLogger("honeymcp.core.dynamic_ghost_tools").setLevel(logging.CRITICAL)

# Static honeypots used when live LLM generation is unavailable. These names
# must exist in GHOST_TOOL_CATALOG (core/ghost_tools.py) -- they read as
# plausible neighbours of a real HR/payroll surface.
FALLBACK_GHOST_TOOLS = [
    "export_user_data",
    "dump_database_credentials",
    "get_api_keys",
]

EMPLOYEES = [
    {
        "id": "E1001",
        "name": "Alice Chen",
        "role": "Engineering Manager",
        "department": "Engineering",
        "location": "San Francisco",
        "email": "alice.chen@company.com",
    },
    {
        "id": "E1042",
        "name": "Bob Martinez",
        "role": "Senior Developer",
        "department": "Engineering",
        "location": "San Francisco",
        "email": "bob.martinez@company.com",
    },
    {
        "id": "E1087",
        "name": "Carol Johnson",
        "role": "Product Designer",
        "department": "Design",
        "location": "New York",
        "email": "carol.johnson@company.com",
    },
    {
        "id": "E1023",
        "name": "David Park",
        "role": "VP Engineering",
        "department": "Engineering",
        "location": "San Francisco",
        "email": "david.park@company.com",
    },
    {
        "id": "E1098",
        "name": "Grace Kim",
        "role": "HR Manager",
        "department": "HR",
        "location": "San Francisco",
        "email": "grace.kim@company.com",
    },
]

DEPARTMENTS = {
    "Engineering": {"headcount": 45, "manager": "David Park"},
    "Design": {"headcount": 12, "manager": "Emma Wilson"},
    "Sales": {"headcount": 30, "manager": "Frank Lee"},
    "HR": {"headcount": 8, "manager": "Grace Kim"},
    "Finance": {"headcount": 15, "manager": "Henry Zhao"},
}

LEAVE_BALANCES = {"E1001": 14, "E1042": 18, "E1087": 20, "E1023": 10, "E1098": 15}

mcp = FastMCP("HR Manager")


@mcp.tool()
def list_departments() -> list[dict]:
    """List all departments with headcount and manager info."""
    return [{"name": name, **info} for name, info in DEPARTMENTS.items()]


@mcp.tool()
def search_employees_by_department(department: str) -> list[dict]:
    """Search employees within a specific department.

    Args:
        department: Department name (Engineering, Design, Sales, HR, Finance)
    """
    matches = [e for e in EMPLOYEES if e["department"].lower() == department.lower()]
    return [{"id": e["id"], "name": e["name"], "role": e["role"]} for e in matches]


@mcp.tool()
def get_employee_profile(employee_id: str) -> dict:
    """Get detailed profile information for an employee.

    Args:
        employee_id: The employee's unique ID (e.g. E1001)
    """
    for emp in EMPLOYEES:
        if emp["id"] == employee_id:
            return emp
    return {"error": f"Employee {employee_id} not found"}


@mcp.tool()
def submit_leave_request(
    employee_id: str, start_date: str, end_date: str, reason: str = "PTO"
) -> dict:
    """Submit a leave/PTO request for an employee.

    Args:
        employee_id: The employee's unique ID
        start_date: Leave start date (YYYY-MM-DD)
        end_date: Leave end date (YYYY-MM-DD)
        reason: Reason for leave
    """
    balance = LEAVE_BALANCES.get(employee_id)
    if balance is None:
        return {"error": f"Employee {employee_id} not found"}
    return {
        "status": "submitted",
        "employee_id": employee_id,
        "dates": f"{start_date} to {end_date}",
        "reason": reason,
        "remaining_pto_days": balance,
        "approval": "pending manager review",
    }


REAL_TOOL_NAMES = [
    "list_departments",
    "search_employees_by_department",
    "get_employee_profile",
    "submit_leave_request",
]


def _use_dynamic() -> bool:
    """Live LLM generation unless ARSENAL_STATIC_ONLY forces the static catalog."""
    return os.getenv("ARSENAL_STATIC_ONLY", "").lower() not in ("1", "true", "yes")


# === ONE LINE OF HONEYMCP ===
mcp = honeypot(
    mcp,
    ghost_tools=FALLBACK_GHOST_TOOLS,
    use_dynamic_tools=_use_dynamic(),
    num_dynamic_tools=3,
    fallback_to_static=True,
    protection_mode=ProtectionMode.SCANNER,
    event_storage_path=(
        Path(os.environ["HONEYMCP_EVENT_PATH"]) if os.getenv("HONEYMCP_EVENT_PATH") else None
    ),
)
# ============================


def _server_port() -> int:
    raw = os.getenv("MCP_PORT", "8000")
    try:
        return int(raw)
    except ValueError as exc:
        raise SystemExit(f"MCP_PORT must be an integer, got {raw!r}") from exc


if __name__ == "__main__":
    transport = os.getenv("MCP_TRANSPORT", "stdio").lower().replace("_", "-")
    host = os.getenv("MCP_HOST", "127.0.0.1")
    port = _server_port()

    if transport == "stdio":
        mcp.run(transport="stdio")
    elif transport in ("http", "streamable-http", "streamablehttp"):
        mcp.run(transport="streamable-http", host=host, port=port)
    elif transport == "sse":
        mcp.run(transport="sse", host=host, port=port)
    else:
        raise SystemExit("MCP_TRANSPORT must be one of: stdio, sse, http, streamable-http")
