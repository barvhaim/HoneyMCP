"""CLI command for creating new honeypot tools."""

import sys
from pathlib import Path
from typing import Optional

from honeymcp.core.tool_creator import ToolCreatorAgent
from honeymcp.core.catalog_updater import CatalogUpdater


def create_tool_command(description: str, project_root: Optional[Path] = None) -> int:
    """CLI command to create a new honeypot tool.

    Args:
        description: Natural language description of the tool
        project_root: Optional project root path

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    print("🍯 HoneyMCP Tool Creator")
    print("=" * 50)
    print(f"\nDescription: {description}\n")

    print("Step 1: Analyzing description and generating tool specification...")
    agent = ToolCreatorAgent()
    success, tool_spec, errors = agent.create_tool(description)

    if not success:
        print("❌ Failed to create tool specification:")
        for error in errors:
            print(f"  - {error}")
        return 1

    print(f"✅ Tool specification created: {tool_spec.name}")
    print(f"   Category: {tool_spec.attack_category}")
    print(f"   Threat Level: {tool_spec.threat_level}")

    state = agent.get_state_summary()
    if state["reasoning"]:
        print("\n📝 Agent Reasoning:")
        for i, thought in enumerate(state["reasoning"], 1):
            print(f"   {i}. {thought}")

    if state["reflections"]:
        print("\n🔍 Quality Reflections:")
        for i, reflection in enumerate(state["reflections"], 1):
            print(f"   {i}. {reflection}")

    print("\nStep 2: Extracting response generator code...")
    # We need to regenerate the code since we can't extract it from the spec
    # This is a limitation - in production, we'd store it in the agent
    from honeymcp.core.tool_creator import ToolSpecification

    temp_spec = ToolSpecification(
        name=tool_spec.name,
        description=tool_spec.description,
        parameters=tool_spec.parameters,
        required_params=tool_spec.parameters.get("required", []),
        category=agent._determine_category(description),
        threat_level=agent._determine_threat_level(description),
        response_template="",
    )
    response_func_code = agent._generate_response_function(temp_spec)
    print(f"✅ Response generator created ({len(response_func_code)} chars)")

    print("\nStep 3: Adding tool to catalog...")
    updater = CatalogUpdater(project_root)
    success, errors = updater.add_tool_complete(tool_spec, response_func_code)

    if not success:
        print("❌ Failed to update catalog:")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("✅ Tool added to ghost_tools.py")
    print("✅ Handler added to middleware.py")

    print("\n" + "=" * 50)
    print("✅ Tool creation complete!")
    print(f"\nNew tool: {tool_spec.name}")
    print(f"Description: {tool_spec.description}")
    print(f"\nTo use this tool:")
    print(f'  mcp = honeypot(mcp, ghost_tools=["{tool_spec.name}"])')
    print("\nOr it will be available in dynamic mode automatically.")

    return 0


def main():
    """Main CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: honeymcp create-tool <description>")
        print("\nExample:")
        print('  honeymcp create-tool "dump container registry credentials"')
        return 1

    description = " ".join(sys.argv[1:])
    return create_tool_command(description)


if __name__ == "__main__":
    sys.exit(main())
