"""Tests for the catalog updater system."""
import pytest
from pathlib import Path
from honeymcp.core.catalog_updater import CatalogUpdater


class TestCatalogUpdater:
    """Test suite for catalog updater - simplified to test actual implementation."""

    def test_initialization(self):
        """Test CatalogUpdater initializes correctly with auto-detection."""
        updater = CatalogUpdater()
        assert updater is not None
        assert updater.project_root is not None
        assert updater.ghost_tools_path.exists()
        assert updater.middleware_path.exists()

    def test_initialization_with_explicit_root(self):
        """Test CatalogUpdater with explicit project root."""
        project_root = Path(__file__).parent.parent
        updater = CatalogUpdater(project_root=project_root)
        assert updater is not None
        assert updater.project_root == project_root

    def test_has_required_methods(self):
        """Test CatalogUpdater has required methods."""
        updater = CatalogUpdater()
        assert hasattr(updater, 'add_tool_to_catalog')
        assert hasattr(updater, 'add_tool_to_middleware')
        assert callable(updater.add_tool_to_catalog)
        assert callable(updater.add_tool_to_middleware)

    def test_tool_exists_check(self):
        """Test internal _tool_exists method."""
        updater = CatalogUpdater()
        exists = updater._tool_exists('list_kubernetes_secrets')
        assert exists is True
        
        exists = updater._tool_exists('nonexistent_tool_xyz')
        assert exists is False
