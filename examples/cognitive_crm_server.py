"""CRM/support demo MCP server using HoneyMCP COGNITIVE protection mode.

This example shows the deception flow after a ghost tool is triggered:
the session stays alive, but real business tools can return synthetic
LLM-generated data instead of production-like results.

Usage:
    # SSE transport (default - good for MCP Inspector):
    uv run python examples/cognitive_crm_server.py

    # Streamable HTTP transport:
    MCP_TRANSPORT=http uv run python examples/cognitive_crm_server.py

    # stdio transport:
    MCP_TRANSPORT=stdio uv run python examples/cognitive_crm_server.py
"""

import hashlib
import os

from fastmcp import FastMCP

from honeymcp import ProtectionMode, honeypot

mcp = FastMCP("HoneyMCP Cognitive CRM Demo Server")


def _stable_id(*parts: object) -> str:
    """Create deterministic demo identifiers without relying on Python hash randomization."""
    digest = hashlib.sha256(":".join(str(part) for part in parts).encode()).hexdigest()
    return digest[:8].upper()


@mcp.tool()
def lookup_customer(customer_id: str) -> str:
    """Look up a customer profile by customer ID.

    Args:
        customer_id: Customer account identifier

    Returns:
        A customer profile summary
    """
    return (
        f"Customer {customer_id}: Riley Chen, enterprise plan, health score 87, "
        "renewal date 2026-11-15, owner: maya@company.example"
    )


@mcp.tool()
def list_support_tickets(customer_id: str, status: str = "open") -> str:
    """List support tickets for a customer.

    Args:
        customer_id: Customer account identifier
        status: Ticket status filter, such as open, pending, or closed

    Returns:
        Matching support tickets
    """
    tickets = [
        ("P1", "SSO login failures for finance users", "pending engineering"),
        ("P2", "Invoice export missing tax columns", "waiting on customer"),
        ("P3", "Request for renewal usage report", "open"),
    ]
    rows = "\n".join(
        f"- {priority} CRM-{_stable_id(customer_id, title)} {title} ({state})"
        for priority, title, state in tickets
        if status == "open" or state.startswith(status)
    )
    return f"Support tickets for {customer_id}:\n{rows or 'No matching tickets'}"


@mcp.tool()
def create_support_ticket(customer_id: str, title: str, priority: str = "P3") -> str:
    """Create a support ticket for a customer.

    Args:
        customer_id: Customer account identifier
        title: Ticket title
        priority: Ticket priority, such as P1, P2, or P3

    Returns:
        Ticket creation confirmation
    """
    ticket_id = f"CRM-{_stable_id(customer_id, title, priority)}"
    return f"Created {priority} ticket {ticket_id} for customer {customer_id}: {title}"


@mcp.tool()
def summarize_contract(customer_id: str) -> str:
    """Summarize the current customer contract.

    Args:
        customer_id: Customer account identifier

    Returns:
        Contract summary
    """
    return (
        f"Contract for {customer_id}: enterprise annual subscription, 240 seats, "
        "$168,000 ARR, standard data processing addendum, auto-renewal enabled"
    )


# ==============================================================================
# COGNITIVE MODE INTEGRATION
# ==============================================================================

if os.getenv("HONEYMCP_DISABLE") != "1":
    force_static = os.getenv("HONEYMCP_FORCE_STATIC") == "1"
    mcp = honeypot(
        mcp,
        ghost_tools=[
            "export_user_data",
            "dump_database_credentials",
        ],
        use_dynamic_tools=not force_static,
        num_dynamic_tools=3,
        fallback_to_static=True,
        protection_mode=ProtectionMode.COGNITIVE,
    )

# ==============================================================================


if __name__ == "__main__":
    transport = os.getenv("MCP_TRANSPORT", "sse")

    print("HoneyMCP Cognitive CRM Demo Server")
    print("=" * 50)
    print(f"Transport: {transport}")
    print("Protection mode: COGNITIVE")
    print("Ghost tools: dynamic CRM-aware tools plus static fallback")
    print("\nLegitimate tools:")
    print("  - lookup_customer")
    print("  - list_support_tickets")
    print("  - create_support_ticket")
    print("  - summarize_contract")
    print("\nTry this flow in an MCP client:")
    print("  1. Call lookup_customer for cust_123")
    print("  2. Call a suspicious ghost tool such as export_user_data")
    print("  3. Call lookup_customer again and observe the deception response")
    print("=" * 50)

    if transport == "stdio":
        mcp.run(transport="stdio")
    elif transport == "http":
        print("\nStarting Streamable HTTP server on http://localhost:8000/mcp\n")
        mcp.run(transport="streamable-http", host="localhost", port=8000)
    else:
        print("\nStarting SSE server on http://localhost:8000/sse\n")
        mcp.run(transport="sse", host="localhost", port=8000)
