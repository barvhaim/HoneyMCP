"""Tests for the 7 new honeypot tools added to the catalog."""
import pytest
from honeymcp.core.ghost_tools import GHOST_TOOL_CATALOG


class TestNewHoneypotTools:
    """Test suite for newly added honeypot tools."""

    @pytest.fixture
    def new_tool_names(self):
        """List of new tool names to test."""
        return [
            'list_kubernetes_secrets',
            'dump_session_tokens',
            'list_github_tokens',
            'disable_2fa_requirement',
            'assume_iam_role',
            'export_audit_logs',
            'dump_ml_model_weights'
        ]

    def test_all_new_tools_in_catalog(self, new_tool_names):
        """Verify all 7 new tools are registered in catalog."""
        for tool_name in new_tool_names:
            assert tool_name in GHOST_TOOL_CATALOG, f"Tool {tool_name} not found in catalog"

    def test_tool_specifications(self, new_tool_names):
        """Verify each tool has correct specification structure."""
        for tool_name in new_tool_names:
            spec = GHOST_TOOL_CATALOG[tool_name]
            
            # Check required attributes
            assert spec.name == tool_name
            assert spec.description is not None and len(spec.description) > 0
            assert spec.parameters is not None
            assert spec.response_generator is not None
            assert spec.threat_level in ['high', 'critical']
            assert spec.attack_category in [
                'exfiltration', 'bypass', 'privilege_escalation', 
                'prompt_injection', 'rce'
            ]

    def test_response_generators_work(self, new_tool_names):
        """Verify response generators produce valid output."""
        for tool_name in new_tool_names:
            spec = GHOST_TOOL_CATALOG[tool_name]
            
            # Test with empty args
            response = spec.response_generator({})
            assert isinstance(response, str)
            assert len(response) > 50, f"Response too short for {tool_name}"
            
            # Check for realistic content
            assert any(keyword in response.lower() for keyword in [
                'token', 'credential', 'secret', 'key', 'access', 
                'warning', 'admin', 'permission'
            ]), f"Response lacks realistic content for {tool_name}"

    def test_kubernetes_secrets_tool(self):
        """Test list_kubernetes_secrets specifically."""
        spec = GHOST_TOOL_CATALOG['list_kubernetes_secrets']
        
        # Test with namespace parameter
        response = spec.response_generator({'namespace': 'production'})
        assert 'production' in response.lower()
        assert 'kubernetes' in response.lower()
        assert 'secret' in response.lower()

    def test_session_tokens_tool(self):
        """Test dump_session_tokens specifically."""
        spec = GHOST_TOOL_CATALOG['dump_session_tokens']
        
        # Test with limit parameter
        response = spec.response_generator({'limit': 5})
        assert 'session' in response.lower()
        assert 'token' in response.lower() or 'jwt' in response.lower()

    def test_github_tokens_tool(self):
        """Test list_github_tokens specifically."""
        spec = GHOST_TOOL_CATALOG['list_github_tokens']
        
        # Test with scope parameter
        response = spec.response_generator({'scope': 'repo'})
        assert 'github' in response.lower() or 'gitlab' in response.lower()
        assert 'token' in response.lower()

    def test_2fa_disable_tool(self):
        """Test disable_2fa_requirement specifically."""
        spec = GHOST_TOOL_CATALOG['disable_2fa_requirement']
        
        # Test with required parameters
        response = spec.response_generator({
            'user_scope': 'current_user',
            'duration_minutes': 30
        })
        assert '2fa' in response.lower() or 'two-factor' in response.lower()
        assert 'disable' in response.lower()

    def test_iam_role_tool(self):
        """Test assume_iam_role specifically."""
        spec = GHOST_TOOL_CATALOG['assume_iam_role']
        
        # Test with role_name parameter
        response = spec.response_generator({
            'role_name': 'AdminRole',
            'duration_hours': 12
        })
        assert 'iam' in response.lower() or 'role' in response.lower()
        assert 'adminrole' in response.lower()

    def test_audit_logs_tool(self):
        """Test export_audit_logs specifically."""
        spec = GHOST_TOOL_CATALOG['export_audit_logs']
        
        # Test with parameters
        response = spec.response_generator({
            'time_range': 'last_7_days',
            'include_sensitive': True
        })
        assert 'audit' in response.lower() or 'log' in response.lower()
        assert 'export' in response.lower()

    def test_ml_model_tool(self):
        """Test dump_ml_model_weights specifically."""
        spec = GHOST_TOOL_CATALOG['dump_ml_model_weights']
        
        # Test with model_name parameter
        response = spec.response_generator({
            'model_name': 'gpt-model',
            'include_training_data': False
        })
        assert 'model' in response.lower()
        assert 'weight' in response.lower() or 'export' in response.lower()

    def test_threat_levels(self, new_tool_names):
        """Verify threat levels are appropriate."""
        critical_tools = [
            'list_kubernetes_secrets', 'dump_session_tokens', 
            'list_github_tokens', 'disable_2fa_requirement',
            'assume_iam_role', 'dump_ml_model_weights'
        ]
        
        for tool_name in new_tool_names:
            spec = GHOST_TOOL_CATALOG[tool_name]
            if tool_name in critical_tools:
                assert spec.threat_level == 'critical'
            else:
                assert spec.threat_level in ['high', 'critical']

    def test_attack_categories(self, new_tool_names):
        """Verify attack categories are correct."""
        exfiltration_tools = [
            'list_kubernetes_secrets', 'dump_session_tokens',
            'list_github_tokens', 'export_audit_logs', 'dump_ml_model_weights'
        ]
        
        for tool_name in new_tool_names:
            spec = GHOST_TOOL_CATALOG[tool_name]
            if tool_name in exfiltration_tools:
                assert spec.attack_category == 'exfiltration'
            elif tool_name == 'disable_2fa_requirement':
                assert spec.attack_category == 'bypass'
            elif tool_name == 'assume_iam_role':
                assert spec.attack_category == 'privilege_escalation'

    def test_catalog_size(self):
        """Verify total catalog size after additions."""
        assert len(GHOST_TOOL_CATALOG) == 20, "Expected 20 tools in catalog"
