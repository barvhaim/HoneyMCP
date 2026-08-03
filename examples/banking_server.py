"""Fintech/Banking Demo MCP Server with HoneyMCP integration.

A more realistic MCP server that exposes banking-style tools. This gives the
dynamic (LLM-generated) ghost tools rich domain context to mimic, and runs in
COGNITIVE protection mode so a detected attacker stays engaged with fake data.

Dynamic ghost tools are generated via your configured LLM provider (see
`.env` -> LLM_PROVIDER / LLM_MODEL). With the LiteLLM proxy setup that means
provider `rits`, base URL http://localhost:8989, model `premium`.

Usage:
    # SSE transport (default - good for MCP Inspector):
    uv run python examples/banking_server.py

    # Streamable HTTP transport (requires Claude Pro/Max/Team/Enterprise):
    MCP_TRANSPORT=http uv run python examples/banking_server.py

    # stdio transport (for Claude Desktop):
    MCP_TRANSPORT=stdio uv run python examples/banking_server.py
"""

import os
from fastmcp import FastMCP
from honeymcp import honeypot, ProtectionMode

mcp = FastMCP("HoneyMCP Banking Demo Server")


@mcp.tool()
def get_account_balance(account_id: str) -> str:
    """Get the current balance for a customer account.

    A legitimate tool demonstrating normal banking functionality.

    Args:
        account_id: The customer account identifier

    Returns:
        The account balance and currency
    """
    # Fake data for demo purposes
    return f"Account {account_id}: $4,215.87 USD (available: $4,015.87)"


@mcp.tool()
def list_transactions(account_id: str, limit: int = 5) -> str:
    """List recent transactions for a customer account.

    Args:
        account_id: The customer account identifier
        limit: Maximum number of transactions to return

    Returns:
        A summary of recent transactions
    """
    sample = [
        "2026-06-30  -$52.10   Grocery Store",
        "2026-06-29  -$14.99   Streaming Service",
        "2026-06-28  +$2,400.00 Payroll Deposit",
        "2026-06-27  -$120.00  Electric Utility",
        "2026-06-26  -$8.75    Coffee Shop",
    ]
    rows = "\n".join(sample[: max(1, min(limit, len(sample)))])
    return f"Recent transactions for {account_id}:\n{rows}"


@mcp.tool()
def transfer_funds(from_account: str, to_account: str, amount: float) -> str:
    """Transfer funds between two accounts.

    Args:
        from_account: Source account identifier
        to_account: Destination account identifier
        amount: Amount to transfer in USD

    Returns:
        A transfer confirmation message
    """
    if amount <= 0:
        raise ValueError("Transfer amount must be positive")
    return (
        f"Transferred ${amount:,.2f} from {from_account} to {to_account}. "
        f"Confirmation: TXN-2026-{hash((from_account, to_account)) % 1_000_000:06d}"
    )


# ==============================================================================
# ONE LINE INTEGRATION - Add honeypot capabilities
# ==============================================================================

if os.getenv("HONEYMCP_DISABLE") != "1":
    mcp = honeypot(
        mcp,
        # Static honeypots used as fallback if the LLM is unavailable.
        ghost_tools=[
            "dump_database_credentials",  # exfiltration honeypot
            "export_user_data",  # PII exfiltration honeypot
        ],
        # Dynamic honeypots generated via the configured LLM proxy.
        use_dynamic_tools=True,
        num_dynamic_tools=3,
        fallback_to_static=True,
        # Keep a detected attacker engaged with LLM-generated fake data.
        protection_mode=ProtectionMode.COGNITIVE,
    )

# ==============================================================================


if __name__ == "__main__":
    transport = os.getenv("MCP_TRANSPORT", "sse")

    print("🍯 HoneyMCP Banking Demo Server")
    print("=" * 50)
    print(f"Transport: {transport}")
    print("Protection mode: COGNITIVE (deceive detected attackers)")
    print("Ghost tools: dynamic (LLM) + static fallback")
    print("\nLegitimate tools:")
    print("  - get_account_balance")
    print("  - list_transactions")
    print("  - transfer_funds")
    print("=" * 50)

    if transport == "stdio":
        print("\n📡 Starting stdio server (Claude Desktop spawns this)\n")
        mcp.run(transport="stdio")
    elif transport == "http":
        print("\n📡 Starting Streamable HTTP server on http://localhost:8000/mcp\n")
        mcp.run(transport="streamable-http", host="localhost", port=8000)
    else:
        print("\n📡 Starting SSE server on http://localhost:8000/sse\n")
        mcp.run(transport="sse", host="localhost", port=8000)
