"""Attack event persistence - JSON file storage."""

import logging
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import List, Optional

import aiofiles

from honeymcp.models.config import resolve_event_storage_path
from honeymcp.models.events import AttackFingerprint

logger = logging.getLogger(__name__)


async def store_event(
    fingerprint: AttackFingerprint,
    storage_path: Optional[Path] = None,
) -> Path:
    """Save attack event to JSON file.

    Events are organized by date: ~/.honeymcp/events/2026-01-23/153422_abc12345.json

    Args:
        fingerprint: Attack fingerprint to persist
        storage_path: Base directory for event storage

    Returns:
        Path to the created JSON file
    """
    storage_path = resolve_event_storage_path(storage_path)

    date_dir = storage_path / fingerprint.timestamp.strftime("%Y-%m-%d")
    date_dir.mkdir(parents=True, exist_ok=True)

    filename = f"{fingerprint.timestamp.strftime('%H%M%S')}_" f"{fingerprint.session_id[:8]}.json"
    filepath = date_dir / filename

    async with aiofiles.open(filepath, "w") as f:
        await f.write(fingerprint.model_dump_json(indent=2))

    return filepath


async def list_events(
    storage_path: Optional[Path] = None,
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
) -> List[AttackFingerprint]:
    """Load events from storage with optional date filtering.

    Args:
        storage_path: Base directory for event storage
        start_date: Only include events on or after this date
        end_date: Only include events on or before this date

    Returns:
        List of attack fingerprints sorted by timestamp (newest first)
    """
    storage_path = resolve_event_storage_path(storage_path)
    if not storage_path.exists():
        return []

    events = []

    for date_dir in sorted(storage_path.iterdir(), reverse=True):
        if not date_dir.is_dir():
            continue

        try:
            dir_date = datetime.strptime(date_dir.name, "%Y-%m-%d").date()
            if start_date and dir_date < start_date:
                continue
            if end_date and dir_date > end_date:
                continue
        except ValueError:
            continue

        for json_file in sorted(date_dir.glob("*.json"), reverse=True):
            try:
                async with aiofiles.open(json_file, "r") as f:
                    content = await f.read()
                    event = AttackFingerprint.model_validate_json(content)
                    events.append(event)
            except Exception as e:
                print(f"Warning: Failed to load {json_file}: {e}")
                continue

    return events


async def get_event(
    event_id: str, storage_path: Optional[Path] = None
) -> Optional[AttackFingerprint]:
    """Load a specific event by ID.

    Args:
        event_id: Event identifier
        storage_path: Base directory for event storage

    Returns:
        Attack fingerprint if found, None otherwise
    """
    storage_path = resolve_event_storage_path(storage_path)
    if not storage_path.exists():
        return None

    for date_dir in storage_path.iterdir():
        if not date_dir.is_dir():
            continue

        for json_file in date_dir.glob("*.json"):
            try:
                async with aiofiles.open(json_file, "r") as f:
                    content = await f.read()
                    event = AttackFingerprint.model_validate_json(content)
                    if event.event_id == event_id:
                        return event
            except Exception:
                continue

    return None


async def update_event(
    event_id: str,
    updates: dict,
    storage_path: Optional[Path] = None,
) -> bool:
    """Update an existing event.

    Args:
        event_id: Event identifier
        updates: Dictionary of fields to update
        storage_path: Base directory for event storage

    Returns:
        True if event was found and updated, False otherwise
    """
    storage_path = resolve_event_storage_path(storage_path)
    if not storage_path.exists():
        return False

    for date_dir in storage_path.iterdir():
        if not date_dir.is_dir():
            continue

        for json_file in date_dir.glob("*.json"):
            try:
                async with aiofiles.open(json_file, "r") as f:
                    content = await f.read()
                    event = AttackFingerprint.model_validate_json(content)

                if event.event_id == event_id:
                    event_dict = event.model_dump()
                    event_dict.update(updates)
                    updated_event = AttackFingerprint(**event_dict)

                    async with aiofiles.open(json_file, "w") as f:
                        await f.write(updated_event.model_dump_json(indent=2))

                    return True

            except Exception:
                continue

    return False


async def clear_events(storage_path: Optional[Path] = None) -> int:
    """Delete all persisted attack events.

    Args:
        storage_path: Base directory for event storage

    Returns:
        Number of event JSON files deleted
    """
    storage_path = resolve_event_storage_path(storage_path)
    if not storage_path.exists():
        return 0

    deleted_count = 0

    for date_dir in storage_path.iterdir():
        if not date_dir.is_dir():
            continue

        for json_file in date_dir.glob("*.json"):
            try:
                json_file.unlink()
                deleted_count += 1
            except Exception as e:
                print(f"Warning: Failed to delete {json_file}: {e}")

        try:
            date_dir.rmdir()
        except OSError:
            # Keep directory when it still has non-event files/subdirs.
            continue

    return deleted_count


def cleanup_old_events(
    storage_path: Optional[Path] = None,
    max_age_days: int = 30,
) -> int:
    """Delete event directories older than max_age_days.

    Compares each YYYY-MM-DD directory name against today's date.
    Removes both the JSON files inside and the directory itself.

    Args:
        storage_path: Base directory for event storage
        max_age_days: Delete directories older than this many days

    Returns:
        Number of directories deleted
    """
    storage_path = resolve_event_storage_path(storage_path)
    if not storage_path.exists():
        return 0

    cutoff = date.today() - timedelta(days=max_age_days)
    deleted_dirs = 0

    for date_dir in list(storage_path.iterdir()):
        if not date_dir.is_dir():
            continue
        try:
            dir_date = datetime.strptime(date_dir.name, "%Y-%m-%d").date()
        except ValueError:
            continue

        if dir_date < cutoff:
            for json_file in date_dir.glob("*.json"):
                try:
                    json_file.unlink()
                except Exception as e:
                    logger.warning("Failed to delete %s: %s", json_file, e)
            try:
                date_dir.rmdir()
                deleted_dirs += 1
            except OSError:
                logger.warning("Could not remove directory %s (not empty?)", date_dir)

    return deleted_dirs
