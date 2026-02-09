"""Simple HR Management MCP Server.

A straightforward MCP server for employee management.
This is the "before" version — no HoneyMCP protection.

Usage:
    uv run python examples/demo_video_before.py
    Then open MCP Inspector → connect to http://localhost:8000/sse
"""

from fastmcp import FastMCP

mcp = FastMCP("HR Manager")

# --- In-memory employee database ---

EMPLOYEES = [
    {"id": "E1001", "name": "Alice Chen", "role": "Engineering Manager", "department": "Engineering", "location": "San Francisco", "start_date": "2022-03-15", "manager": "David Park", "email": "alice.chen@company.com"},
    {"id": "E1042", "name": "Bob Martinez", "role": "Senior Developer", "department": "Engineering", "location": "San Francisco", "start_date": "2021-08-01", "manager": "Alice Chen", "email": "bob.martinez@company.com"},
    {"id": "E1087", "name": "Carol Johnson", "role": "Product Designer", "department": "Design", "location": "New York", "start_date": "2023-01-10", "manager": "Emma Wilson", "email": "carol.johnson@company.com"},
    {"id": "E1023", "name": "David Park", "role": "VP Engineering", "department": "Engineering", "location": "San Francisco", "start_date": "2020-06-01", "manager": "Sarah Liu", "email": "david.park@company.com"},
    {"id": "E1055", "name": "Emma Wilson", "role": "Design Lead", "department": "Design", "location": "New York", "start_date": "2021-11-15", "manager": "Sarah Liu", "email": "emma.wilson@company.com"},
    {"id": "E1071", "name": "Frank Lee", "role": "Sales Director", "department": "Sales", "location": "Chicago", "start_date": "2022-09-20", "manager": "Sarah Liu", "email": "frank.lee@company.com"},
    {"id": "E1098", "name": "Grace Kim", "role": "HR Manager", "department": "HR", "location": "San Francisco", "start_date": "2021-04-12", "manager": "Sarah Liu", "email": "grace.kim@company.com"},
    {"id": "E1112", "name": "Henry Zhao", "role": "Finance Director", "department": "Finance", "location": "New York", "start_date": "2020-11-30", "manager": "Sarah Liu", "email": "henry.zhao@company.com"},
]

DEPARTMENTS = {
    "Engineering": {"headcount": 45, "manager": "David Park"},
    "Design": {"headcount": 12, "manager": "Emma Wilson"},
    "Sales": {"headcount": 30, "manager": "Frank Lee"},
    "HR": {"headcount": 8, "manager": "Grace Kim"},
    "Finance": {"headcount": 15, "manager": "Henry Zhao"},
}

LEAVE_BALANCES = {
    "E1001": 14, "E1042": 18, "E1087": 20, "E1023": 10,
    "E1055": 16, "E1071": 12, "E1098": 15, "E1112": 9,
}


@mcp.tool()
def search_employees_by_department(department: str) -> list[dict]:
    """Search employees within a specific department.

    Args:
        department: Department name (Engineering, Design, Sales, HR, Finance)
    """
    results = [e for e in EMPLOYEES if e["department"].lower() == department.lower()]
    return [{"id": e["id"], "name": e["name"], "role": e["role"]} for e in results]


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
def submit_leave_request(employee_id: str, start_date: str, end_date: str, reason: str = "PTO") -> dict:
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


@mcp.tool()
def list_departments() -> list[dict]:
    """List all departments with headcount and manager info."""
    return [{"name": name, **info} for name, info in DEPARTMENTS.items()]


if __name__ == "__main__":
    print("HR Manager - MCP Server (no protection)")
    print("=" * 50)
    print("Tools: search_employees_by_department, get_employee_profile, submit_leave_request, list_departments")
    print()
    print("Connect MCP Inspector to: http://localhost:8000/sse")
    print()
    mcp.run(transport="sse", host="localhost", port=8000)
