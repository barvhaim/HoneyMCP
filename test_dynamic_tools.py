"""Quick test script for dynamic ghost tool generation."""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from honeymcp.llm.analyzers import ToolInfo
from honeymcp.core.dynamic_ghost_tools import DynamicGhostToolGenerator
from llm_client_watsonx import LLMClient


async def test_dynamic_generation():
    """Test the dynamic ghost tool generation pipeline."""
    
    print("=" * 60)
    print("Testing Dynamic Ghost Tool Generation")
    print("=" * 60)
    print()
    
    # Create sample tools (simulating a file system server)
    sample_tools = [
        ToolInfo(
            name="read_file",
            description="Read contents of a file from the filesystem",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path"}
                },
                "required": ["path"]
            }
        ),
        ToolInfo(
            name="write_file",
            description="Write content to a file in the filesystem",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path"},
                    "content": {"type": "string", "description": "Content to write"}
                },
                "required": ["path", "content"]
            }
        ),
        ToolInfo(
            name="list_directory",
            description="List files and directories in the specified path",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory path"}
                },
                "required": ["path"]
            }
        ),
    ]
    
    try:
        # Initialize LLM client and generator
        print("1. Initializing LLM client...")
        llm_client = LLMClient()
        generator = DynamicGhostToolGenerator(llm_client)
        print("   ✓ LLM client initialized")
        print()
        
        # Analyze server context
        print("2. Analyzing server context...")
        server_context = await generator.analyze_server_context(sample_tools)
        print(f"   ✓ Server Purpose: {server_context.server_purpose}")
        print(f"   ✓ Domain: {server_context.domain}")
        print(f"   ✓ Security Areas: {', '.join(server_context.security_sensitive_areas)}")
        print()
        
        # Generate ghost tools
        print("3. Generating ghost tools...")
        ghost_tools = await generator.generate_ghost_tools(server_context, num_tools=3)
        print(f"   ✓ Generated {len(ghost_tools)} ghost tools:")
        for tool in ghost_tools:
            print(f"     - {tool.name}: {tool.description[:60]}...")
            print(f"       Threat Level: {tool.threat_level}, Category: {tool.attack_category}")
        print()
        
        # Test response generation
        print("4. Testing fake response generation...")
        if ghost_tools:
            test_tool = ghost_tools[0]
            test_args = {}
            
            # Extract a sample argument if available
            if test_tool.parameters.get("properties"):
                first_param = list(test_tool.parameters["properties"].keys())[0]
                test_args[first_param] = "test_value"
            
            fake_response = test_tool.response_generator(test_args)
            print(f"   ✓ Generated fake response for '{test_tool.name}':")
            print(f"     {fake_response[:200]}...")
        print()
        
        print("=" * 60)
        print("✓ All tests passed successfully!")
        print("=" * 60)
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


if __name__ == "__main__":
    print()
    print("This script tests the dynamic ghost tool generation system.")
    print("Make sure you have set up your .env file with WatsonX credentials.")
    print()
    
    success = asyncio.run(test_dynamic_generation())
    sys.exit(0 if success else 1)
