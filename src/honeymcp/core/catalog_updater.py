"""Catalog updater for adding new honeypot tools to ghost_tools.py and middleware.py"""

import ast
import re
from pathlib import Path
from typing import Tuple, List, Optional

from honeymcp.models.ghost_tool_spec import GhostToolSpec


class CatalogUpdater:
    """Updates ghost_tools.py and middleware.py with new honeypot tools."""

    def __init__(self, project_root: Optional[Path] = None):
        """Initialize catalog updater.
        
        Args:
            project_root: Root directory of HoneyMCP project. If None, auto-detects.
        """
        if project_root is None:
            # Auto-detect project root
            current = Path(__file__).resolve()
            while current.parent != current:
                if (current / "src" / "honeymcp").exists():
                    project_root = current
                    break
                current = current.parent
        
        self.project_root = project_root
        self.ghost_tools_path = project_root / "src" / "honeymcp" / "core" / "ghost_tools.py"
        self.middleware_path = project_root / "src" / "honeymcp" / "core" / "middleware.py"

    def add_tool_to_catalog(
        self, 
        tool_spec: GhostToolSpec,
        response_func_code: str
    ) -> Tuple[bool, List[str]]:
        """Add new tool to ghost_tools.py catalog.
        
        Args:
            tool_spec: GhostToolSpec for the new tool
            response_func_code: Python code for response generator function
            
        Returns:
            Tuple of (success, errors)
        """
        errors = []
        
        # Step 1: Validate tool doesn't already exist
        if self._tool_exists(tool_spec.name):
            errors.append(f"Tool '{tool_spec.name}' already exists in catalog")
            return False, errors
        
        # Step 2: Read current ghost_tools.py
        try:
            content = self.ghost_tools_path.read_text()
        except Exception as e:
            errors.append(f"Failed to read ghost_tools.py: {e}")
            return False, errors
        
        # Step 3: Add response generator function
        updated_content = self._add_response_generator(content, response_func_code)
        
        # Step 4: Add tool to GHOST_TOOL_CATALOG
        updated_content = self._add_to_catalog(updated_content, tool_spec)
        
        # Step 5: Validate syntax
        try:
            ast.parse(updated_content)
        except SyntaxError as e:
            errors.append(f"Generated code has syntax error: {e}")
            return False, errors
        
        # Step 6: Write updated file
        try:
            self.ghost_tools_path.write_text(updated_content)
        except Exception as e:
            errors.append(f"Failed to write ghost_tools.py: {e}")
            return False, errors
        
        return True, []

    def add_tool_to_middleware(self, tool_spec: GhostToolSpec) -> Tuple[bool, List[str]]:
        """Add new tool handler to middleware.py.
        
        Args:
            tool_spec: GhostToolSpec for the new tool
            
        Returns:
            Tuple of (success, errors)
        """
        errors = []
        
        # Step 1: Read current middleware.py
        try:
            content = self.middleware_path.read_text()
        except Exception as e:
            errors.append(f"Failed to read middleware.py: {e}")
            return False, errors
        
        # Step 2: Generate handler code
        handler_code = self._generate_handler_code(tool_spec)
        
        # Step 3: Insert handler before "else:" clause
        updated_content = self._insert_handler(content, handler_code)
        
        # Step 4: Validate syntax
        try:
            ast.parse(updated_content)
        except SyntaxError as e:
            errors.append(f"Generated middleware code has syntax error: {e}")
            return False, errors
        
        # Step 5: Write updated file
        try:
            self.middleware_path.write_text(updated_content)
        except Exception as e:
            errors.append(f"Failed to write middleware.py: {e}")
            return False, errors
        
        return True, []

    def _tool_exists(self, tool_name: str) -> bool:
        """Check if tool already exists in catalog."""
        content = self.ghost_tools_path.read_text()
        return f'"{tool_name}": GhostToolSpec(' in content

    def _add_response_generator(self, content: str, func_code: str) -> str:
        """Add response generator function to ghost_tools.py."""
        # Find the last response generator function
        last_func_pattern = r'(def generate_fake_\w+\(args: Dict\[str, Any\]\) -> str:.*?(?=\n\ndef |\n\n# Ghost tool catalog))'
        matches = list(re.finditer(last_func_pattern, content, re.DOTALL))
        
        if matches:
            last_match = matches[-1]
            insert_pos = last_match.end()
            # Add new function after last one
            return content[:insert_pos] + "\n\n" + func_code.rstrip() + "\n" + content[insert_pos:]
        else:
            # No functions found, add before catalog
            catalog_pos = content.find("# Ghost tool catalog")
            if catalog_pos > 0:
                return content[:catalog_pos] + func_code.rstrip() + "\n\n" + content[catalog_pos:]
        
        return content

    def _add_to_catalog(self, content: str, tool_spec: GhostToolSpec) -> str:
        """Add tool entry to GHOST_TOOL_CATALOG dictionary."""
        # Generate catalog entry
        catalog_entry = self._generate_catalog_entry(tool_spec)
        
        # Find the closing brace of GHOST_TOOL_CATALOG
        # Look for the last tool entry before the closing brace
        pattern = r'(    "[\w_]+": GhostToolSpec\(.*?\),)\n(\})'
        
        def replacer(match):
            last_entry = match.group(1)
            closing_brace = match.group(2)
            return f"{last_entry}\n{catalog_entry}\n{closing_brace}"
        
        updated = re.sub(pattern, replacer, content, flags=re.DOTALL)
        
        return updated

    def _generate_catalog_entry(self, tool_spec: GhostToolSpec) -> str:
        """Generate catalog entry code for tool."""
        # Format parameters as Python dict
        params_str = str(tool_spec.parameters).replace("'", '"')
        
        entry = f'''    "{tool_spec.name}": GhostToolSpec(
        name="{tool_spec.name}",
        description="{tool_spec.description}",
        parameters={params_str},
        response_generator=generate_fake_{tool_spec.name},
        threat_level="{tool_spec.threat_level}",
        attack_category="{tool_spec.attack_category}",
    ),'''
        
        return entry

    def _generate_handler_code(self, tool_spec: GhostToolSpec) -> str:
        """Generate middleware handler code for tool."""
        # Extract parameters
        properties = tool_spec.parameters.get("properties", {})
        required = tool_spec.parameters.get("required", [])
        
        # Build parameter list
        params = []
        for param_name, param_spec in properties.items():
            param_type = self._python_type_from_json_type(param_spec.get("type", "string"))
            if param_name in required:
                params.append(f"{param_name}: {param_type}")
            else:
                default = self._get_param_default(param_name, param_spec)
                params.append(f"{param_name}: {param_type} = {default}")
        
        params_str = ", ".join(params) if params else ""
        
        # Build args dict
        if params:
            args_dict_lines = [f'                {{"{p.split(":")[0].strip()}": {p.split(":")[0].strip()}}}' 
                             for p in params]
            args_dict = "{\n" + ",\n".join([f'                "{p.split(":")[0].strip()}": {p.split(":")[0].strip()}' 
                                           for p in params]) + "\n            }"
        else:
            args_dict = "{}"
        
        handler = f'''    elif ghost_spec.name == "{tool_spec.name}":

        @server.tool(name=ghost_spec.name, description=ghost_spec.description)
        async def handler({params_str}):
            """Generated handler for {tool_spec.name} (fallback only)."""
            return ghost_spec.response_generator({args_dict})
'''
        
        return handler

    def _python_type_from_json_type(self, json_type: str) -> str:
        """Convert JSON schema type to Python type hint."""
        type_map = {
            "string": "str",
            "integer": "int",
            "number": "float",
            "boolean": "bool",
            "array": "list",
            "object": "dict"
        }
        return type_map.get(json_type, "str")

    def _get_param_default(self, param_name: str, param_spec: dict) -> str:
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
        elif param_type == "string":
            return f'"{param_name}_default"'
        else:
            return "None"

    def _insert_handler(self, content: str, handler_code: str) -> str:
        """Insert handler code before the final else clause."""
        # Find the last "elif ghost_spec.name ==" before "else:"
        pattern = r'(    elif ghost_spec\.name == "[\w_]+":\n.*?return ghost_spec\.response_generator\(.*?\)\n)\n(    else:\n        raise ValueError)'
        
        def replacer(match):
            last_handler = match.group(1)
            else_clause = match.group(2)
            return f"{last_handler}\n{handler_code}\n{else_clause}"
        
        updated = re.sub(pattern, replacer, content, flags=re.DOTALL)
        
        return updated

    def add_tool_complete(
        self, 
        tool_spec: GhostToolSpec,
        response_func_code: str
    ) -> Tuple[bool, List[str]]:
        """Complete workflow: add tool to both catalog and middleware.
        
        Args:
            tool_spec: GhostToolSpec for the new tool
            response_func_code: Python code for response generator function
            
        Returns:
            Tuple of (success, errors)
        """
        all_errors = []
        
        # Step 1: Add to ghost_tools.py
        success, errors = self.add_tool_to_catalog(tool_spec, response_func_code)
        if not success:
            all_errors.extend(errors)
            return False, all_errors
        
        # Step 2: Add to middleware.py
        success, errors = self.add_tool_to_middleware(tool_spec)
        if not success:
            all_errors.extend(errors)
            # Rollback ghost_tools.py changes would go here
            return False, all_errors
        
        return True, []
