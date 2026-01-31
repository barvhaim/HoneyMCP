"""HoneyMCP CLI - Command line tools for HoneyMCP setup and management."""

import argparse
import sys
from pathlib import Path

CONFIG_TEMPLATE = """\
# HoneyMCP Configuration
# ======================
# Configure ghost tool injection and attack detection behavior

# Protection Mode
# ---------------
# SCANNER: Lock out attackers after ghost tool trigger (all tools return errors)
# COGNITIVE: Deceive attackers with fake data (real tools return mocks)
protection_mode: SCANNER

# Static Ghost Tools
# ------------------
# Select which pre-defined ghost tools to inject from the catalog.
# Available tools:
#
# Data Exfiltration (GET):
#   - list_cloud_secrets: List AWS/Azure credentials
#   - read_private_files: Read sensitive config files
#   - dump_database_credentials: Retrieve database connection strings
#   - export_user_data: Export user records including PII
#   - get_api_keys: List all API keys for external services
#   - scan_internal_network: Scan internal network for services
#
# Indirect Prompt Injection (SET):
#   - execute_shell_command: Execute shell commands
#   - bypass_security_check: Bypass auth/authz checks
#   - modify_system_prompt: Modify AI system prompt
#   - escalate_privileges: Escalate to admin/root
#   - disable_security_filters: Disable security filters
#   - inject_system_message: Inject message into AI context
#   - override_permissions: Override access control
#
ghost_tools:
  - list_cloud_secrets
  - execute_shell_command

# Dynamic Ghost Tools (LLM-generated)
# -----------------------------------
# Enable LLM to analyze your server and generate context-aware ghost tools.
# Requires LLM credentials in .env file.
dynamic_tools:
  enabled: false                  # Set to true to enable (requires LLM credentials)
  num_tools: 3                    # Number of tools to generate (1-10)
  fallback_to_static: true        # Use static tools if LLM generation fails
  cache_ttl: 3600                 # Cache duration in seconds (0 = no cache)
  llm_model: null                 # Override LLM model (null = use default from .env)

# Storage
# -------
# Configure where attack events are stored
storage:
  event_path: ~/.honeymcp/events  # Directory for attack event JSON files

# Dashboard
# ---------
# Real-time attack visualization
dashboard:
  enabled: true
"""

ENV_TEMPLATE = """\
# HoneyMCP Environment Configuration
# ==================================
# Required only for dynamic ghost tools (LLM-generated)

# LLM Provider Configuration
# --------------------------
# Supported providers: openai, watsonx, ollama
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o-mini

# OpenAI Configuration
# --------------------
# Required if LLM_PROVIDER=openai
OPENAI_API_KEY=your_openai_api_key_here

# watsonx.ai Configuration
# ------------------------
# Required if LLM_PROVIDER=watsonx
# WATSONX_URL=https://us-south.ml.cloud.ibm.com/
# WATSONX_APIKEY=your_watsonx_api_key_here
# WATSONX_PROJECT_ID=your_project_id_here

# Ollama Configuration
# --------------------
# Required if LLM_PROVIDER=ollama
# OLLAMA_API_BASE=http://localhost:11434
# LLM_MODEL=llama3.2
"""


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize HoneyMCP configuration files in current directory."""
    target_dir = Path(args.directory).resolve()

    if not target_dir.exists():
        print(f"Error: Directory does not exist: {target_dir}")
        return 1

    config_path = target_dir / "honeymcp.yaml"
    env_path = target_dir / ".env.honeymcp"

    files_created = []
    files_skipped = []

    # Create config.yaml
    if config_path.exists() and not args.force:
        files_skipped.append(config_path.name)
    else:
        config_path.write_text(CONFIG_TEMPLATE)
        files_created.append(config_path.name)

    # Create .env.example
    if env_path.exists() and not args.force:
        files_skipped.append(env_path.name)
    else:
        env_path.write_text(ENV_TEMPLATE)
        files_created.append(env_path.name)

    # Print results
    if files_created:
        print("Created:")
        for f in files_created:
            print(f"  - {f}")

    if files_skipped:
        print("Skipped (already exists, use --force to overwrite):")
        for f in files_skipped:
            print(f"  - {f}")

    print()
    print("Next steps:")
    print("  1. Edit honeymcp.yaml to configure ghost tools")
    print("  2. Add LLM credentials to .env.honeymcp (for dynamic tools)")
    print("  3. Add to your MCP server:")
    print()
    print("     from honeymcp import honeypot_from_config")
    print("     mcp = honeypot_from_config(mcp)")
    print()

    return 0


def cmd_version(args: argparse.Namespace) -> int:
    """Print HoneyMCP version."""
    from honeymcp import __version__

    print(f"honeymcp {__version__}")
    return 0


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="honeymcp",
        description="HoneyMCP - Deception middleware for MCP servers",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # init command
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize HoneyMCP configuration files",
        description="Create honeymcp.yaml and .env.example in the specified directory",
    )
    init_parser.add_argument(
        "-d",
        "--directory",
        default=".",
        help="Target directory (default: current directory)",
    )
    init_parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Overwrite existing files",
    )
    init_parser.set_defaults(func=cmd_init)

    # version command
    version_parser = subparsers.add_parser(
        "version",
        help="Show HoneyMCP version",
    )
    version_parser.set_defaults(func=cmd_version)

    # Parse and execute
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
