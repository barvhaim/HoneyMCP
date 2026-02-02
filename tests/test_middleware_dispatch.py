"""Tests for middleware and ghost tool integration."""
import pytest
from honeymcp.core.ghost_tools import GHOST_TOOL_CATALOG


class TestMiddlewareDispatch:
    """Test suite for ghost tool response generation."""

    def test_all_tools_have_response_generators(self):
        """Test that all catalog tools have response generator functions."""
        for tool_name, ghost_spec in GHOST_TOOL_CATALOG.items():
            assert ghost_spec.response_generator is not None, \
                f"Tool {tool_name} missing response generator"
            assert callable(ghost_spec.response_generator), \
                f"Tool {tool_name} response generator not callable"

    def test_response_generators_produce_output(self):
        """Test that all response generators produce valid output."""
        for tool_name, ghost_spec in GHOST_TOOL_CATALOG.items():
            result = ghost_spec.response_generator({})
            
            assert result is not None, f"Tool {tool_name} returned None"
            assert isinstance(result, str), f"Tool {tool_name} didn't return string"
            assert len(result) > 0, f"Tool {tool_name} returned empty string"

    def test_new_tools_response_quality(self):
        """Test that new tools produce quality responses."""
        new_tools = [
            'list_kubernetes_secrets',
            'dump_session_tokens',
            'list_github_tokens',
            'disable_2fa_requirement',
            'assume_iam_role',
            'export_audit_logs',
            'dump_ml_model_weights'
        ]
        
        for tool_name in new_tools:
            ghost_spec = GHOST_TOOL_CATALOG[tool_name]
            result = ghost_spec.response_generator({})
            
            assert len(result) > 50, f"Tool {tool_name} response too short"
            # Should contain warning or alert
            assert any(keyword in result for keyword in [
                "WARNING", "ALERT", "⚠️", "CRITICAL", "SECURITY", "warning"
            ]), f"Tool {tool_name} missing security warning"

    def test_response_with_parameters(self):
        """Test response generators with parameters."""
        # Test with namespace parameter
        spec = GHOST_TOOL_CATALOG['list_kubernetes_secrets']
        result = spec.response_generator({"namespace": "production"})
        assert "production" in result.lower()
        
        # Test with limit parameter
        spec = GHOST_TOOL_CATALOG['dump_session_tokens']
        result = spec.response_generator({"limit": 5})
        assert result is not None

    def test_all_tools_have_proper_specs(self):
        """Test that all tools have complete specifications."""
        for tool_name, ghost_spec in GHOST_TOOL_CATALOG.items():
            assert ghost_spec.name == tool_name
            assert ghost_spec.description is not None
            assert ghost_spec.parameters is not None
            assert ghost_spec.threat_level in ['high', 'critical']
            assert ghost_spec.attack_category in [
                'exfiltration', 'bypass', 'privilege_escalation',
                'prompt_injection', 'rce'
            ]
