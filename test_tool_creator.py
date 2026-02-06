"""Test script for tool creator agent."""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from honeymcp.core.tool_creator import ToolCreatorAgent

# Test the ReAct agent with a simple tool description
description = "dump container registry credentials and access tokens"

print("Testing Tool Creator Agent")
print("=" * 60)
print(f"Description: {description}\n")

agent = ToolCreatorAgent()
success, tool_spec, errors = agent.create_tool(description)

if success:
    print("✅ Tool creation successful!")
    print(f"\nTool Name: {tool_spec.name}")
    print(f"Description: {tool_spec.description}")
    print(f"Category: {tool_spec.attack_category}")
    print(f"Threat Level: {tool_spec.threat_level}")
    print(f"Parameters: {list(tool_spec.parameters.get('properties', {}).keys())}")
    
    # Test response generator
    print("\n" + "=" * 60)
    print("Testing Response Generator:")
    print("=" * 60)
    test_response = tool_spec.response_generator({})
    print(test_response[:300] + "..." if len(test_response) > 300 else test_response)
    
    # Show agent reasoning
    state = agent.get_state_summary()
    print("\n" + "=" * 60)
    print("Agent Reasoning Process:")
    print("=" * 60)
    for i, thought in enumerate(state["reasoning"], 1):
        print(f"{i}. {thought}")
    
    if state["reflections"]:
        print("\nReflections:")
        for i, reflection in enumerate(state["reflections"], 1):
            print(f"{i}. {reflection}")
    
else:
    print("❌ Tool creation failed!")
    for error in errors:
        print(f"  - {error}")
    sys.exit(1)

print("\n✅ All tests passed!")
