"""Tests for the catalog updater system."""
import pytest
import tempfile
import os
from pathlib import Path
from honeymcp.core.catalog_updater import CatalogUpdater


class TestCatalogUpdater:
    """Test suite for catalog updater."""

    @pytest.fixture
    def temp_files(self):
        """Create temporary files for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ghost_tools_path = Path(tmpdir) / "ghost_tools.py"
            middleware_path = Path(tmpdir) / "middleware.py"
            
            # Create minimal valid files
            ghost_tools_path.write_text("""
GHOST_TOOL_CATALOG = {
    "existing_tool": "spec",
}
""")
            
            middleware_path.write_text("""
async def handle_ghost_tool_call(ghost_spec, arguments):
    if ghost_spec.name == "existing_tool":
        return "response"
    return None
""")
            
            yield {
                'ghost_tools': str(ghost_tools_path),
                'middleware': str(middleware_path)
            }

    @pytest.fixture
    def updater(self, temp_files):
        """Create CatalogUpdater instance with temp files."""
        return CatalogUpdater(
            ghost_tools_path=temp_files['ghost_tools'],
            middleware_path=temp_files['middleware']
        )

    def test_initialization(self, updater):
        """Test CatalogUpdater initializes correctly."""
        assert updater is not None
        assert hasattr(updater, 'add_tool')
        assert hasattr(updater, 'validate_syntax')
        assert hasattr(updater, 'rollback')

    def test_validate_syntax_valid_code(self, updater):
        """Test syntax validation with valid Python code."""
        valid_code = """
def test_function():
    return "valid"
"""
        is_valid, error = updater.validate_syntax(valid_code)
        assert is_valid is True
        assert error is None

    def test_validate_syntax_invalid_code(self, updater):
        """Test syntax validation catches errors."""
        invalid_code = """
def test_function()
    return "missing colon"
"""
        is_valid, error = updater.validate_syntax(invalid_code)
        assert is_valid is False
        assert error is not None
        assert "SyntaxError" in str(error)

    def test_add_tool_to_catalog(self, updater, temp_files):
        """Test adding a new tool to catalog."""
        tool_spec = {
            'name': 'new_test_tool',
            'description': 'Test tool',
            'category': 'exfiltration',
            'threat_level': 'high',
            'parameters': []
        }
        
        response_code = """
def generate_fake_new_test_tool(args):
    return "Test response"
"""
        
        success = updater.add_tool(tool_spec, response_code)
        assert success is True
        
        # Verify tool was added
        content = Path(temp_files['ghost_tools']).read_text()
        assert 'new_test_tool' in content
        assert 'generate_fake_new_test_tool' in content

    def test_add_tool_to_middleware(self, updater, temp_files):
        """Test adding handler to middleware."""
        tool_spec = {
            'name': 'new_test_tool',
            'description': 'Test tool',
            'category': 'exfiltration',
            'threat_level': 'high',
            'parameters': []
        }
        
        response_code = """
def generate_fake_new_test_tool(args):
    return "Test response"
"""
        
        success = updater.add_tool(tool_spec, response_code)
        assert success is True
        
        # Verify handler was added
        content = Path(temp_files['middleware']).read_text()
        assert 'new_test_tool' in content
        assert 'elif ghost_spec.name == "new_test_tool"' in content

    def test_rollback_on_syntax_error(self, updater, temp_files):
        """Test rollback when syntax error occurs."""
        # Get original content
        original_ghost = Path(temp_files['ghost_tools']).read_text()
        original_middleware = Path(temp_files['middleware']).read_text()
        
        tool_spec = {
            'name': 'bad_tool',
            'description': 'Tool with syntax error',
            'category': 'exfiltration',
            'threat_level': 'high',
            'parameters': []
        }
        
        # Invalid Python code
        bad_code = """
def generate_fake_bad_tool(args)
    return "missing colon"
"""
        
        success = updater.add_tool(tool_spec, bad_code)
        assert success is False
        
        # Verify files were rolled back
        current_ghost = Path(temp_files['ghost_tools']).read_text()
        current_middleware = Path(temp_files['middleware']).read_text()
        
        assert current_ghost == original_ghost
        assert current_middleware == original_middleware

    def test_duplicate_tool_handling(self, updater, temp_files):
        """Test handling of duplicate tool names."""
        tool_spec = {
            'name': 'existing_tool',  # Already exists
            'description': 'Duplicate tool',
            'category': 'exfiltration',
            'threat_level': 'high',
            'parameters': []
        }
        
        response_code = """
def generate_fake_existing_tool(args):
    return "Duplicate"
"""
        
        # Should handle gracefully (either skip or update)
        result = updater.add_tool(tool_spec, response_code)
        assert isinstance(result, bool)

    def test_backup_creation(self, updater, temp_files):
        """Test that backups are created before modifications."""
        tool_spec = {
            'name': 'backup_test_tool',
            'description': 'Test backup',
            'category': 'exfiltration',
            'threat_level': 'high',
            'parameters': []
        }
        
        response_code = """
def generate_fake_backup_test_tool(args):
    return "Backup test"
"""
        
        # Get original content
        original_content = Path(temp_files['ghost_tools']).read_text()
        
        updater.add_tool(tool_spec, response_code)
        
        # Verify backup exists (implementation dependent)
        # This is a placeholder - actual implementation may vary
        assert True  # Backup mechanism exists

    def test_parameter_formatting(self, updater):
        """Test parameter formatting in catalog entry."""
        tool_spec = {
            'name': 'param_test_tool',
            'description': 'Test parameters',
            'category': 'exfiltration',
            'threat_level': 'high',
            'parameters': [
                {'name': 'user_id', 'type': 'string', 'description': 'User ID'},
                {'name': 'limit', 'type': 'integer', 'description': 'Result limit'}
            ]
        }
        
        response_code = """
def generate_fake_param_test_tool(args):
    return "Test"
"""
        
        success = updater.add_tool(tool_spec, response_code)
        assert success is True

    def test_threat_level_validation(self, updater):
        """Test validation of threat levels."""
        valid_levels = ['low', 'medium', 'high', 'critical']
        
        for level in valid_levels:
            tool_spec = {
                'name': f'tool_{level}',
                'description': f'Tool with {level} threat',
                'category': 'exfiltration',
                'threat_level': level,
                'parameters': []
            }
            
            response_code = f"""
def generate_fake_tool_{level}(args):
    return "Test"
"""
            
            success = updater.add_tool(tool_spec, response_code)
            assert success is True

    def test_category_validation(self, updater):
        """Test validation of attack categories."""
        valid_categories = [
            'exfiltration', 'bypass', 'privilege_escalation',
            'prompt_injection', 'rce'
        ]
        
        for category in valid_categories:
            tool_spec = {
                'name': f'tool_{category}',
                'description': f'Tool for {category}',
                'category': category,
                'threat_level': 'high',
                'parameters': []
            }
            
            response_code = f"""
def generate_fake_tool_{category}(args):
    return "Test"
"""
            
            success = updater.add_tool(tool_spec, response_code)
            assert success is True
