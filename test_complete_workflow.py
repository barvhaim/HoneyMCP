"""Test complete workflow: create tool and add to catalog."""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from honeymcp.core.tool_creator import ToolCreatorAgent
from honeymcp.core.catalog_updater import CatalogUpdater

# Test description
description = "list terraform state files with infrastructure secrets"

print("🍯 Complete Tool Creation Workflow Test")
print("=" * 70)
print(f"Description: {description}\n")

# Step 1: Create tool with ReAct agent
print("Step 1: Creating tool specification with ReAct agent...")
agent = ToolCreatorAgent()
success, tool_spec, errors = agent.create_tool(description)

if not success:
    print("❌ Failed to create tool:")
    for error in errors:
        print(f"  - {error}")
    sys.exit(1)

print(f"✅ Tool created: {tool_spec.name}")
print(f"   Category: {tool_spec.attack_category}")
print(f"   Threat: {tool_spec.threat_level}")

# Show reasoning
state = agent.get_state_summary()
print("\n📝 Agent Reasoning:")
for thought in state["reasoning"]:
    print(f"   - {thought}")

# Step 2: Generate response function code
print("\nStep 2: Generating response function code...")
from honeymcp.core.tool_creator import ToolSpecification, ToolCategory, ThreatLevel

temp_spec = ToolSpecification(
    name=tool_spec.name,
    description=tool_spec.description,
    parameters=tool_spec.parameters,
    required_params=tool_spec.parameters.get("required", []),
    category=ToolCategory.EXFILTRATION,
    threat_level=ThreatLevel.CRITICAL,
    response_template=""
)
response_func_code = agent._generate_response_function(temp_spec)
print(f"✅ Response function generated ({len(response_func_code)} chars)")

# Step 3: Test response generator
print("\nStep 3: Testing response generator...")
test_response = tool_spec.response_generator({})
print("Sample response:")
print(test_response[:200] + "..." if len(test_response) > 200 else test_response)

# Step 4: Validate catalog updater (dry run - don't actually update)
print("\nStep 4: Validating catalog updater...")
updater = CatalogUpdater(PROJECT_ROOT)

# Check if tool already exists
if updater._tool_exists(tool_spec.name):
    print(f"⚠️  Tool '{tool_spec.name}' already exists in catalog (expected for test)")
else:
    print(f"✅ Tool '{tool_spec.name}' is new and can be added")

# Validate paths exist
print(f"\nValidating file paths:")
print(f"  ghost_tools.py: {'✅' if updater.ghost_tools_path.exists() else '❌'}")
print(f"  middleware.py: {'✅' if updater.middleware_path.exists() else '❌'}")

# Step 5: Generate catalog entry (preview only)
print("\nStep 5: Preview catalog entry:")
catalog_entry = updater._generate_catalog_entry(tool_spec)
print(catalog_entry[:200] + "..." if len(catalog_entry) > 200 else catalog_entry)

# Step 6: Generate handler code (preview only)
print("\nStep 6: Preview middleware handler:")
handler_code = updater._generate_handler_code(tool_spec)
print(handler_code[:300] + "..." if len(handler_code) > 300 else handler_code)

print("\n" + "=" * 70)
print("✅ Complete workflow test passed!")
print("\nThe tool creation system is working correctly.")
print("To actually add a tool, use: honeymcp create-tool <description>")
