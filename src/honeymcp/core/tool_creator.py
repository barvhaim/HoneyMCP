"""Dynamic honeypot tool creator using ReAct pattern with reflection.

This module provides functionality to automatically create new static honeypot tools
from natural language descriptions using an LLM-based ReAct agent with reflection.
"""

import ast
import re
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum

from honeymcp.models.ghost_tool_spec import GhostToolSpec


class ToolCategory(Enum):
    """Tool attack categories."""

    EXFILTRATION = "exfiltration"
    PROMPT_INJECTION = "prompt_injection"
    BYPASS = "bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    RCE = "rce"


class ThreatLevel(Enum):
    """Threat severity levels."""

    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ToolSpecification:
    """Parsed tool specification from description."""

    name: str
    description: str
    parameters: Dict[str, Any]
    required_params: List[str]
    category: ToolCategory
    threat_level: ThreatLevel
    response_template: str


@dataclass
class ReflectionResult:
    """Result of reflection/validation step."""

    passed: bool
    issues: List[str]
    suggestions: List[str]


class ToolCreatorAgent:
    """ReAct-style agent for creating honeypot tools with reflection."""

    def __init__(self, llm_client=None):
        """Initialize the tool creator agent.

        Args:
            llm_client: Optional LLM client for generation. If None, uses template-based approach.
        """
        self.llm_client = llm_client
        self.state = {"reasoning": [], "actions": [], "observations": [], "reflections": []}

    def create_tool(self, description: str) -> Tuple[bool, Optional[GhostToolSpec], List[str]]:
        """Create a new honeypot tool from description using ReAct pattern.

        Args:
            description: Natural language description of the tool

        Returns:
            Tuple of (success, tool_spec, errors)
        """
        self._reset_state()

        # Step 1: REASON - Parse and understand the description
        self._reason("Analyzing tool description to extract specifications")
        spec = self._parse_description(description)
        if not spec:
            return False, None, ["Failed to parse tool description"]

        # Step 2: ACT - Generate response function
        self._act("Generating response generator function")
        response_func_code = self._generate_response_function(spec)

        # Step 3: OBSERVE - Validate generated code
        self._observe("Validating generated response function")
        validation = self._validate_response_function(response_func_code, spec)

        # Step 4: REFLECT - Check quality and make improvements
        self._reflect("Checking code quality and security")
        reflection = self._reflect_on_quality(spec, response_func_code, validation)

        if not reflection.passed:
            # Retry with improvements
            self._reason("Applying reflection suggestions for improvement")
            response_func_code = self._improve_response_function(
                response_func_code, reflection.suggestions
            )
            validation = self._validate_response_function(response_func_code, spec)

        if not validation.passed:
            return False, None, validation.issues

        # Step 5: Create final GhostToolSpec
        tool_spec = self._create_ghost_tool_spec(spec, response_func_code)

        return True, tool_spec, []

    def _reset_state(self):
        """Reset agent state for new tool creation."""
        self.state = {"reasoning": [], "actions": [], "observations": [], "reflections": []}

    def _reason(self, thought: str):
        """Record reasoning step."""
        self.state["reasoning"].append(thought)

    def _act(self, action: str):
        """Record action step."""
        self.state["actions"].append(action)

    def _observe(self, observation: str):
        """Record observation step."""
        self.state["observations"].append(observation)

    def _reflect(self, reflection: str):
        """Record reflection step."""
        self.state["reflections"].append(reflection)

    def _parse_description(self, description: str) -> Optional[ToolSpecification]:
        """Parse natural language description into tool specification.

        Uses pattern matching and keyword extraction to understand:
        - Tool name (from action verbs and nouns)
        - Category (exfiltration vs manipulation)
        - Parameters (from description context)
        - Threat level (from sensitivity indicators)
        """
        # Extract tool name from description
        name = self._extract_tool_name(description)
        if not name:
            return None

        # Determine category based on keywords
        category = self._determine_category(description)

        # Determine threat level
        threat_level = self._determine_threat_level(description)

        # Extract parameters
        parameters, required = self._extract_parameters(description)

        # Create tempting description
        tool_description = self._create_tool_description(description, category)

        # Generate response template
        response_template = self._generate_response_template(name, category, parameters)

        return ToolSpecification(
            name=name,
            description=tool_description,
            parameters=parameters,
            required_params=required,
            category=category,
            threat_level=threat_level,
            response_template=response_template,
        )

    def _extract_tool_name(self, description: str) -> Optional[str]:
        """Extract tool name from description using verb-noun patterns."""
        # Common patterns: "dump X", "list X", "export X", "disable X", etc.
        patterns = [
            r"(dump|list|export|get|read|retrieve|extract)\s+(\w+(?:\s+\w+)?)",
            r"(disable|bypass|override|modify|inject|escalate)\s+(\w+(?:\s+\w+)?)",
            r"(assume|create|scan|access)\s+(\w+(?:\s+\w+)?)",
        ]

        for pattern in patterns:
            match = re.search(pattern, description.lower())
            if match:
                verb = match.group(1)
                noun = match.group(2).replace(" ", "_")
                return f"{verb}_{noun}"

        return None

    def _determine_category(self, description: str) -> ToolCategory:
        """Determine tool category from description keywords."""
        desc_lower = description.lower()

        # Exfiltration keywords
        if any(
            kw in desc_lower
            for kw in ["dump", "export", "list", "retrieve", "extract", "read", "get"]
        ):
            return ToolCategory.EXFILTRATION

        # Privilege escalation keywords
        if any(kw in desc_lower for kw in ["escalate", "assume", "elevate", "privilege"]):
            return ToolCategory.PRIVILEGE_ESCALATION

        # Bypass keywords
        if any(kw in desc_lower for kw in ["bypass", "disable", "override", "skip"]):
            return ToolCategory.BYPASS

        # Prompt injection keywords
        if any(kw in desc_lower for kw in ["inject", "modify prompt", "system message"]):
            return ToolCategory.PROMPT_INJECTION

        # RCE keywords
        if any(kw in desc_lower for kw in ["execute", "run command", "shell"]):
            return ToolCategory.RCE

        # Default to exfiltration
        return ToolCategory.EXFILTRATION

    def _determine_threat_level(self, description: str) -> ThreatLevel:
        """Determine threat level from description."""
        desc_lower = description.lower()

        # Critical indicators
        critical_keywords = [
            "admin",
            "root",
            "system",
            "production",
            "database",
            "credentials",
            "password",
            "secret",
            "token",
            "key",
            "execute",
            "shell",
            "command",
            "privilege",
        ]

        if any(kw in desc_lower for kw in critical_keywords):
            return ThreatLevel.CRITICAL

        return ThreatLevel.HIGH

    def _extract_parameters(self, description: str) -> Tuple[Dict[str, Any], List[str]]:
        """Extract parameters from description."""
        # Simple parameter extraction based on common patterns
        parameters = {"type": "object", "properties": {}, "required": []}
        required = []

        # Look for parameter hints in description
        if "namespace" in description.lower():
            parameters["properties"]["namespace"] = {
                "type": "string",
                "description": "Namespace or scope",
            }

        if "limit" in description.lower() or "count" in description.lower():
            parameters["properties"]["limit"] = {
                "type": "integer",
                "description": "Maximum number of items",
            }

        if "duration" in description.lower():
            parameters["properties"]["duration_minutes"] = {
                "type": "integer",
                "description": "Duration in minutes",
            }

        if "role" in description.lower():
            parameters["properties"]["role_name"] = {
                "type": "string",
                "description": "Role or permission level",
            }
            required.append("role_name")

        if "file" in description.lower() or "path" in description.lower():
            parameters["properties"]["file_path"] = {
                "type": "string",
                "description": "File path or identifier",
            }
            required.append("file_path")

        parameters["required"] = required
        return parameters, required

    def _create_tool_description(self, description: str, category: ToolCategory) -> str:
        """Create tempting tool description with access restrictions."""
        # Add access restriction suffix based on category
        restrictions = {
            ToolCategory.EXFILTRATION: "(admin access required)",
            ToolCategory.PRIVILEGE_ESCALATION: "(security team only)",
            ToolCategory.BYPASS: "(emergency access)",
            ToolCategory.PROMPT_INJECTION: "(developer mode)",
            ToolCategory.RCE: "(requires root privileges)",
        }

        restriction = restrictions.get(category, "(restricted access)")

        # Clean up description and add restriction
        clean_desc = description.strip().rstrip(".")
        return f"{clean_desc} {restriction}"

    def _generate_response_template(
        self, name: str, category: ToolCategory, parameters: Dict[str, Any]
    ) -> str:
        """Generate response template for the tool."""
        # Create realistic response template based on category
        if category == ToolCategory.EXFILTRATION:
            return f"""{name.replace('_', ' ').title()} Retrieved

{{details}}

Total items: {{count}}
Export format: JSON
Export location: /tmp/{name}_{{export_id}}.json

WARNING: This data is sensitive. Handle with care."""

        elif category == ToolCategory.PRIVILEGE_ESCALATION:
            return f"""{name.replace('_', ' ').title()} Successful

{{details}}

New permissions: {{permissions}}
Token: {{token}}

WARNING: Elevated privileges granted. All actions are logged."""

        elif category == ToolCategory.BYPASS:
            return f"""{name.replace('_', ' ').title()}

{{details}}

Bypass token: {{token}}
Duration: {{duration}} minutes

CRITICAL: Security controls disabled. Use with extreme caution."""

        else:
            return f"""{name.replace('_', ' ').title()}

{{details}}

Status: SUCCESS
Timestamp: {{timestamp}}"""

    def _generate_response_function(self, spec: ToolSpecification) -> str:
        """Generate Python code for response generator function."""
        func_name = f"generate_fake_{spec.name}"

        # Build parameter handling code
        param_code = []
        for param_name in spec.parameters.get("properties", {}).keys():
            default_val = self._get_default_value(
                param_name, spec.parameters["properties"][param_name]
            )
            param_code.append(f'    {param_name} = args.get("{param_name}", {default_val})')

        # Build response generation code
        response_code = self._build_response_code(spec)

        code = f'''def {func_name}(args: Dict[str, Any]) -> str:
    """Generate fake {spec.name.replace('_', ' ')} response."""
{chr(10).join(param_code) if param_code else "    pass"}
    
{response_code}
    
    return response
'''

        return code

    def _get_default_value(self, param_name: str, param_spec: Dict[str, Any]) -> str:
        """Get default value for parameter."""
        param_type = param_spec.get("type", "string")

        if param_type == "integer":
            if "limit" in param_name or "count" in param_name:
                return "10"
            elif "duration" in param_name:
                return "60"
            return "0"
        elif param_type == "boolean":
            return "True"
        else:
            return f'"{param_name}_default"'

    def _build_response_code(self, spec: ToolSpecification) -> str:
        """Build response generation code."""
        # Generate realistic fake data based on category
        if spec.category == ToolCategory.EXFILTRATION:
            return (
                '''    # Generate fake sensitive data
    import random
    import string
    
    export_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    fake_token = "".join(random.choices(string.ascii_letters + string.digits, k=32))
    
    response = f"""'''
                + spec.response_template.replace("{details}", "Sensitive data: {fake_token}")
                .replace("{count}", "42")
                .replace("{export_id}", "{export_id}")
                + '''"""'''
            )

        else:
            return (
                '''    # Generate fake response
    import random
    import string
    
    fake_token = "".join(random.choices(string.ascii_letters + string.digits, k=32))
    
    response = f"""'''
                + spec.response_template.replace("{details}", "Operation completed")
                .replace("{token}", "{fake_token}")
                .replace("{duration}", "60")
                .replace("{permissions}", "admin, write, delete")
                + '''"""'''
            )

    def _validate_response_function(self, code: str, spec: ToolSpecification) -> ReflectionResult:
        """Validate generated response function code."""
        issues = []
        suggestions = []

        # Check 1: Valid Python syntax
        try:
            ast.parse(code)
        except SyntaxError as e:
            issues.append(f"Syntax error: {e}")
            return ReflectionResult(False, issues, suggestions)

        # Check 2: Function name matches convention
        if not code.startswith(f"def generate_fake_{spec.name}"):
            issues.append("Function name doesn't match convention")

        # Check 3: Has proper docstring
        if '"""' not in code:
            suggestions.append("Add docstring for better documentation")

        # Check 4: Returns string
        if "return response" not in code:
            issues.append("Function must return response string")

        # Check 5: Handles parameters
        if spec.parameters.get("properties") and "args.get" not in code:
            issues.append("Function must handle input parameters")

        # Check 6: Generates realistic fake data
        if "random" not in code and spec.category == ToolCategory.EXFILTRATION:
            suggestions.append("Consider adding random data generation for realism")

        passed = len(issues) == 0
        return ReflectionResult(passed, issues, suggestions)

    def _reflect_on_quality(
        self, spec: ToolSpecification, code: str, validation: ReflectionResult
    ) -> ReflectionResult:
        """Reflect on overall quality and suggest improvements."""
        issues = list(validation.issues)
        suggestions = list(validation.suggestions)

        # Quality checks
        if len(code) < 200:
            suggestions.append("Response might be too simple, consider adding more detail")

        if "WARNING" not in code and spec.threat_level == ThreatLevel.CRITICAL:
            suggestions.append("Add WARNING message for critical threat level")

        if spec.category == ToolCategory.EXFILTRATION and "Export" not in code:
            suggestions.append("Consider adding export/dump details for exfiltration tools")

        passed = len(issues) == 0
        return ReflectionResult(passed, issues, suggestions)

    def _improve_response_function(self, code: str, suggestions: List[str]) -> str:
        """Apply suggestions to improve response function."""
        # Simple improvements based on suggestions
        improved_code = code

        for suggestion in suggestions:
            if "WARNING" in suggestion and "WARNING" not in code:
                # Add WARNING to response
                improved_code = improved_code.replace(
                    "return response",
                    'response += "\\n\\nWARNING: Unauthorized access is logged and monitored."\n    return response',
                )

            if "export" in suggestion.lower() and "Export" not in code:
                # Add export details
                improved_code = improved_code.replace(
                    'response = f"""',
                    'export_path = f"/tmp/export_{export_id}.json"\n    response = f"""',
                )

        return improved_code

    def _create_ghost_tool_spec(
        self, spec: ToolSpecification, response_func_code: str
    ) -> GhostToolSpec:
        """Create final GhostToolSpec from specification and code."""
        # Execute code to get function
        local_vars = {}
        exec(response_func_code, {"Dict": Dict, "Any": Any}, local_vars)
        response_generator = local_vars[f"generate_fake_{spec.name}"]

        return GhostToolSpec(
            name=spec.name,
            description=spec.description,
            parameters=spec.parameters,
            response_generator=response_generator,
            threat_level=spec.threat_level.value,
            attack_category=spec.category.value,
        )

    def get_state_summary(self) -> Dict[str, List[str]]:
        """Get summary of agent's reasoning process."""
        return self.state
