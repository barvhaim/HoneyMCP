"""LLM prompt templates for dynamic ghost tool generation."""

# pylint: disable=line-too-long

from typing import Any, Dict, List


class PromptTemplates:
    """LLM prompt templates for dynamic ghost tool generation."""

    SERVER_ANALYSIS_PROMPT = """You are analyzing a tool server to understand its purpose and functionality.

Real Tools Available:
{tool_list}

Analyze these tools and provide:
1. Server Purpose: What is this server designed to do? (1-2 sentences)
2. Domain: Primary domain (choose one: file_system, database, api, development, security, cloud, communication, data_processing, other)
3. Security-Sensitive Areas: What operations could be security-sensitive in this domain? (list 3-5 specific areas)

Format your response as valid JSON only, no additional text:
{{
  "server_purpose": "Brief description of what this server does",
  "domain": "primary_domain",
  "security_sensitive_areas": ["area1", "area2", "area3"]
}}"""

    GHOST_TOOL_GENERATION_PROMPT = """You are a security researcher creating honeypot tools to detect malicious AI agents attempting to exploit tool servers.

Server Context:
- Purpose: {server_purpose}
- Domain: {domain}
- Real Tools Available: {real_tool_names}
- Security-Sensitive Areas: {security_areas}

Create {num_tools} fake "ghost" tools that:
1. Are highly relevant to this specific server's domain and purpose
2. Sound security-sensitive (mention admin, bypass, secrets, privileged, internal, etc.)
3. Would tempt a malicious agent trying to exploit or exfiltrate data from this system
4. Are plausible given the real tools available (similar naming patterns, related functionality)
5. Have realistic parameter schemas that match the domain
6. Include a pre-generated fake response that looks authentic

Guidelines:
- Tool names should follow snake_case convention
- Descriptions should be 1-2 sentences, mentioning restricted access or sensitive operations
- Parameters should be realistic JSON schemas with appropriate types and constraints
- Threat levels: critical (RCE, credential theft), high (data exfiltration, bypass), medium (prompt injection)
- Attack categories: exfiltration, rce, bypass, privilege_escalation, prompt_injection, data_manipulation
- fake_response: Pre-generated response that looks like real output. Use {{param_name}} placeholders to interpolate parameter values at runtime. Make it convincing with fake credentials, tokens, data, etc.

Format as valid JSON array only, no additional text:
[
  {{
    "name": "tool_name_here",
    "description": "Enticing description mentioning admin/bypass/secrets (admin only)",
    "parameters": {{
      "type": "object",
      "properties": {{
        "param_name": {{
          "type": "string",
          "description": "Parameter description"
        }}
      }},
      "required": ["param_name"]
    }},
    "threat_level": "critical",
    "attack_category": "exfiltration",
    "fake_response": "Realistic fake output with {{param_name}} interpolated. Include fake credentials, tokens, etc."
  }}
]"""

    REAL_TOOL_MOCK_GENERATION_PROMPT = """You are generating fake/mock responses for real tools on a server.
These mocks will be used to deceive detected attackers who have triggered a honeypot.

Server Context:
- Purpose: {server_purpose}
- Domain: {domain}

Real Tools to Mock:
{tool_list}

For each tool, generate a realistic-looking but FAKE response that:
1. Matches the expected output format for that tool type
2. Contains plausible but fabricated data
3. Would convince an attacker they are getting real results
4. Uses {{param_name}} placeholders for any parameters that should be interpolated

Format as valid JSON array only, no additional text:
[
  {{
    "name": "tool_name",
    "mock_response": "Fake response with {{param}} placeholders"
  }}
]
"""

    @staticmethod
    def format_server_analysis(tools: List[Dict[str, Any]]) -> str:
        """Format server analysis prompt with tool information.

        Args:
            tools: List of tool dictionaries with 'name' and 'description' keys

        Returns:
            Formatted prompt string
        """
        tool_list = []
        for i, tool in enumerate(tools, 1):
            name = tool.get("name", "unknown")
            description = tool.get("description", "No description")
            tool_list.append(f"{i}. {name}: {description}")

        tool_list_str = "\n".join(tool_list) if tool_list else "No tools available"

        return PromptTemplates.SERVER_ANALYSIS_PROMPT.format(tool_list=tool_list_str)

    @staticmethod
    def format_ghost_tool_generation(
        server_purpose: str,
        domain: str,
        real_tool_names: List[str],
        security_areas: List[str],
        num_tools: int = 3,
    ) -> str:
        """Format ghost tool generation prompt.

        Args:
            server_purpose: Description of what the server does
            domain: Primary domain category
            real_tool_names: List of real tool names
            security_areas: List of security-sensitive areas
            num_tools: Number of ghost tools to generate

        Returns:
            Formatted prompt string
        """
        return PromptTemplates.GHOST_TOOL_GENERATION_PROMPT.format(
            server_purpose=server_purpose,
            domain=domain,
            real_tool_names=", ".join(real_tool_names),
            security_areas=", ".join(security_areas),
            num_tools=num_tools,
        )

    @staticmethod
    def format_real_tool_mocks(
        server_purpose: str, domain: str, tools: List[Dict[str, Any]]
    ) -> str:
        """Format prompt for generating mock responses for real tools.

        Args:
            server_purpose: Description of what the server does
            domain: Primary domain category
            tools: List of tool dictionaries with 'name' and 'description' keys

        Returns:
            Formatted prompt string
        """
        tool_list = []
        for i, tool in enumerate(tools, 1):
            name = tool.get("name", "unknown")
            description = tool.get("description", "No description")
            tool_list.append(f"{i}. {name}: {description}")

        tool_list_str = "\n".join(tool_list) if tool_list else "No tools available"

        return PromptTemplates.REAL_TOOL_MOCK_GENERATION_PROMPT.format(
            server_purpose=server_purpose, domain=domain, tool_list=tool_list_str
        )
