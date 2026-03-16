"""Tests for event retention auto-cleanup."""

from datetime import date, timedelta
from pathlib import Path

import pytest

from honeymcp.storage.event_store import cleanup_old_events
from honeymcp.models.config import HoneyMCPConfig


class TestCleanupOldEvents:
    """Test cleanup_old_events function."""

    def _create_date_dir(self, base: Path, d: date) -> Path:
        """Helper: create a YYYY-MM-DD directory with a dummy .json file."""
        dir_path = base / d.strftime("%Y-%m-%d")
        dir_path.mkdir(parents=True, exist_ok=True)
        (dir_path / "dummy.json").write_text("{}")
        return dir_path

    def test_deletes_old_directories(self, tmp_path):
        old_date = date.today() - timedelta(days=10)
        self._create_date_dir(tmp_path, old_date)
        deleted = cleanup_old_events(tmp_path, max_age_days=5)
        assert deleted == 1
        assert not (tmp_path / old_date.strftime("%Y-%m-%d")).exists()

    def test_keeps_recent_directories(self, tmp_path):
        recent = date.today() - timedelta(days=2)
        self._create_date_dir(tmp_path, recent)
        deleted = cleanup_old_events(tmp_path, max_age_days=5)
        assert deleted == 0
        assert (tmp_path / recent.strftime("%Y-%m-%d")).exists()

    def test_keeps_today(self, tmp_path):
        self._create_date_dir(tmp_path, date.today())
        deleted = cleanup_old_events(tmp_path, max_age_days=1)
        assert deleted == 0

    def test_empty_storage_returns_zero(self, tmp_path):
        deleted = cleanup_old_events(tmp_path, max_age_days=5)
        assert deleted == 0

    def test_nonexistent_path_returns_zero(self, tmp_path):
        deleted = cleanup_old_events(tmp_path / "nonexistent", max_age_days=5)
        assert deleted == 0

    def test_skips_non_date_directories(self, tmp_path):
        (tmp_path / "not-a-date").mkdir()
        deleted = cleanup_old_events(tmp_path, max_age_days=1)
        assert deleted == 0

    def test_mixed_old_and_new(self, tmp_path):
        old = date.today() - timedelta(days=60)
        recent = date.today() - timedelta(days=2)
        self._create_date_dir(tmp_path, old)
        self._create_date_dir(tmp_path, recent)
        deleted = cleanup_old_events(tmp_path, max_age_days=30)
        assert deleted == 1
        assert not (tmp_path / old.strftime("%Y-%m-%d")).exists()
        assert (tmp_path / recent.strftime("%Y-%m-%d")).exists()

    def test_deletes_multiple_json_files(self, tmp_path):
        old_date = date.today() - timedelta(days=10)
        dir_path = self._create_date_dir(tmp_path, old_date)
        (dir_path / "event1.json").write_text("{}")
        (dir_path / "event2.json").write_text("{}")
        deleted = cleanup_old_events(tmp_path, max_age_days=5)
        assert deleted == 1
        assert not dir_path.exists()

    def test_boundary_exact_cutoff_not_deleted(self, tmp_path):
        """A directory exactly max_age_days old is on the cutoff and should NOT be deleted."""
        boundary = date.today() - timedelta(days=5)
        self._create_date_dir(tmp_path, boundary)
        deleted = cleanup_old_events(tmp_path, max_age_days=5)
        assert deleted == 0


class TestCleanupConfig:
    """Config parsing for max_age_days."""

    def test_default_is_none(self):
        config = HoneyMCPConfig()
        assert config.max_age_days is None

    def test_custom_value(self):
        config = HoneyMCPConfig(max_age_days=30)
        assert config.max_age_days == 30

    def test_yaml_parsing(self, tmp_path):
        config_file = tmp_path / "honeymcp.yaml"
        config_file.write_text("storage:\n  max_age_days: 14\n")
        config = HoneyMCPConfig.from_yaml(config_file)
        assert config.max_age_days == 14

    def test_yaml_null_means_disabled(self, tmp_path):
        config_file = tmp_path / "honeymcp.yaml"
        config_file.write_text("storage:\n  max_age_days: null\n")
        config = HoneyMCPConfig.from_yaml(config_file)
        assert config.max_age_days is None

    def test_validation_rejects_zero(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            HoneyMCPConfig(max_age_days=0)

    def test_validation_rejects_negative(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            HoneyMCPConfig(max_age_days=-1)
