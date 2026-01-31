"""Attack event persistence - JSON file storage."""

from datetime import date, datetime
from pathlib import Path
from typing import List, Optional

import aiofiles

from honeymcp.models.config import resolve_event_storage_path
from honeymcp.models.events import AttackFingerprint


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

    # Create date-based directory structure
    date_dir = storage_path / fingerprint.timestamp.strftime("%Y-%m-%d")
    date_dir.mkdir(parents=True, exist_ok=True)

    # Generate filename: HHMMSS_session_id.json
    filename = f"{fingerprint.timestamp.strftime('%H%M%S')}_" f"{fingerprint.session_id[:8]}.json"
    filepath = date_dir / filename

    # Write event to JSON file
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

    # Scan all date directories
    for date_dir in sorted(storage_path.iterdir(), reverse=True):
        if not date_dir.is_dir():
            continue

        # Check if date is in range
        try:
            dir_date = datetime.strptime(date_dir.name, "%Y-%m-%d").date()
            if start_date and dir_date < start_date:
                continue
            if end_date and dir_date > end_date:
                continue
        except ValueError:
            # Skip directories that don't match date format
            continue

        # Load all JSON files in this date directory
        for json_file in sorted(date_dir.glob("*.json"), reverse=True):
            try:
                async with aiofiles.open(json_file, "r") as f:
                    content = await f.read()
                    event = AttackFingerprint.model_validate_json(content)
                    events.append(event)
            except Exception as e:
                # Skip files that can't be parsed
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
    # Search all date directories for the event
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
    # Find the event file
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
                    # Update fields
                    event_dict = event.model_dump()
                    event_dict.update(updates)
                    updated_event = AttackFingerprint(**event_dict)

                    # Write back to file
                    async with aiofiles.open(json_file, "w") as f:
                        await f.write(updated_event.model_dump_json(indent=2))

                    return True

            except Exception:
                continue

    return False
