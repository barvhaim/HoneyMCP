"""Tests for configuration management."""
import pytest
import tempfile
from pathlib import Path
from honeymcp.models.config import HoneyMCPConfig
from honeymcp.models.protection_mode import ProtectionMode


class TestConfiguration:
    """Test suite for configuration management."""

    @pytest.fixture
    def temp_config_file(self):
        """Create temporary config file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
protection_mode: scanner
ghost_tools:
  - list_cloud_secrets
  - execute_shell_command
use_dynamic_tools: true
num_dynamic_tools: 3
""")
            config_path = Path(f.name)
        
        yield config_path
        
        # Cleanup
        if config_path.exists():
            config_path.unlink()

    def test_default_config(self):
        """Test creating config with defaults."""
        config = HoneyMCPConfig()
        assert config is not None
        assert config.protection_mode in [ProtectionMode.SCANNER, ProtectionMode.COGNITIVE]
        assert isinstance(config.ghost_tools, list)

    def test_load_from_yaml(self, temp_config_file):
        """Test loading configuration from YAML file."""
        config = HoneyMCPConfig.from_yaml(temp_config_file)
        assert config is not None
        assert config.protection_mode == ProtectionMode.SCANNER
        assert len(config.ghost_tools) >= 2

    def test_protection_mode_setting(self):
        """Test setting protection mode."""
        config = HoneyMCPConfig(protection_mode=ProtectionMode.COGNITIVE)
        assert config.protection_mode == ProtectionMode.COGNITIVE

    def test_dynamic_tools_config(self):
        """Test dynamic tools configuration."""
        config = HoneyMCPConfig(
            use_dynamic_tools=True,
            num_dynamic_tools=5
        )
        assert config.use_dynamic_tools is True
        assert config.num_dynamic_tools == 5

    def test_event_storage_path(self):
        """Test event storage path configuration."""
        config = HoneyMCPConfig()
        assert config.event_storage_path is not None
        assert isinstance(config.event_storage_path, Path)

    def test_dashboard_config(self):
        """Test dashboard configuration."""
        config = HoneyMCPConfig(enable_dashboard=False)
        assert config.enable_dashboard is False

    def test_webhook_config(self):
        """Test webhook URL configuration."""
        webhook_url = "https://example.com/webhook"
        config = HoneyMCPConfig(webhook_url=webhook_url)
        assert config.webhook_url == webhook_url
