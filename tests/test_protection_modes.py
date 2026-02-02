"""Tests for protection mode behavior."""
import pytest
from honeymcp.models.protection_mode import ProtectionMode


class TestProtectionModes:
    """Test suite for protection mode functionality."""

    def test_protection_mode_enum_values(self):
        """Test that ProtectionMode enum has expected values."""
        assert hasattr(ProtectionMode, 'SCANNER')
        assert hasattr(ProtectionMode, 'COGNITIVE')
        
    def test_scanner_mode_value(self):
        """Test SCANNER mode has correct value."""
        assert ProtectionMode.SCANNER.value == "scanner"
        
    def test_cognitive_mode_value(self):
        """Test COGNITIVE mode has correct value."""
        assert ProtectionMode.COGNITIVE.value == "cognitive"

    def test_mode_from_string(self):
        """Test creating mode from string value."""
        scanner = ProtectionMode("scanner")
        assert scanner == ProtectionMode.SCANNER
        
        cognitive = ProtectionMode("cognitive")
        assert cognitive == ProtectionMode.COGNITIVE

    def test_mode_comparison(self):
        """Test comparing protection modes."""
        assert ProtectionMode.SCANNER != ProtectionMode.COGNITIVE
        assert ProtectionMode.SCANNER == ProtectionMode.SCANNER

    def test_mode_string_representation(self):
        """Test string representation of modes."""
        assert str(ProtectionMode.SCANNER.value) == "scanner"
        assert str(ProtectionMode.COGNITIVE.value) == "cognitive"

    def test_all_modes_defined(self):
        """Test that all expected modes are defined."""
        modes = list(ProtectionMode)
        assert len(modes) == 2
        assert ProtectionMode.SCANNER in modes
        assert ProtectionMode.COGNITIVE in modes

    def test_mode_is_enum(self):
        """Test that ProtectionMode is an Enum."""
        from enum import Enum
        assert issubclass(ProtectionMode, Enum)

    def test_invalid_mode_raises_error(self):
        """Test that invalid mode string raises error."""
        with pytest.raises(ValueError):
            ProtectionMode("invalid_mode")

    def test_mode_iteration(self):
        """Test iterating over protection modes."""
        modes = [mode for mode in ProtectionMode]
        assert len(modes) == 2
        assert all(isinstance(mode, ProtectionMode) for mode in modes)
