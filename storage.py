"""
storage.py — Append-only incident persistence layer for Agent Zero.

Stores compliance incidents in a JSON Lines file. Sensitive values are
NEVER written — only masked representations are stored.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_STORAGE_PATH = Path("incidents.jsonl")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class IncidentRecord:
    """
    A single compliance incident entry.

    All sensitive values must already be masked before constructing
    this record. This class never holds raw secrets.
    """

    incident_id: str
    timestamp: str                # ISO-8601 UTC
    user_id: str                  # Slack user ID (e.g. U01234567)
    username: str                 # Display name
    channel_id: str               # Slack channel ID
    channel_name: str             # Human-readable channel name
    message_preview: str          # First 80 chars of message (no raw secrets)
    risk_count: int
    highest_severity: str         # HIGH / MEDIUM / LOW
    risks: list[dict]             # List of Risk.to_dict() results
    resolved: bool = False
    notes: str = ""

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialisation."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "IncidentRecord":
        """Deserialise from a plain dict (e.g. read from JSONL)."""
        return cls(**data)


# ---------------------------------------------------------------------------
# Storage engine
# ---------------------------------------------------------------------------

class IncidentStore:
    """
    Thread-safe append-only storage for compliance incidents.

    Each incident is written as a single JSON line to a `.jsonl` file.
    Reads load the entire file into memory; this is acceptable for typical
    compliance workloads (thousands of incidents).

    Args:
        path: Path to the JSON Lines storage file.
    """
    _instances: dict[str, "IncidentStore"] = {}

    def __new__(cls, path: Path = _DEFAULT_STORAGE_PATH) -> "IncidentStore":
        path_str = str(Path(path).resolve())
        if path_str not in cls._instances:
            cls._instances[path_str] = super().__new__(cls)
        return cls._instances[path_str]

    def __init__(self, path: Path = _DEFAULT_STORAGE_PATH) -> None:
        """Initialise the store, creating the storage file if absent."""
        if hasattr(self, '_lock'):
            return
        self._path = Path(path)
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.touch()
        logger.info("IncidentStore initialised at %s", self._path.resolve())

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def append(self, record: IncidentRecord) -> None:
        """
        Append a single incident to the store (thread-safe).

        Args:
            record: The incident to persist.
        """
        with self._lock:
            try:
                line = json.dumps(record.to_dict(), ensure_ascii=False)
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                logger.debug("Incident %s written to storage.", record.incident_id)
            except OSError as exc:
                logger.error("Failed to write incident %s: %s", record.incident_id, exc)
                raise

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def load_all(self) -> list[IncidentRecord]:
        """
        Load and return all stored incidents from the persistent JSON Lines file.
        
        Contract:
        - Thread-safe read operation.
        - Loads the entire file into memory (acceptable for thousands of records).
        - Skips malformed or corrupt lines, ensuring partial corruption doesn't crash the application.
        - Returns a list of `IncidentRecord` objects chronologically.

        Returns:
            List of IncidentRecord objects ordered by insertion time.
        """
        records: list[IncidentRecord] = []
        with self._lock:
            try:
                with self._path.open("r", encoding="utf-8") as fh:
                    for lineno, line in enumerate(fh, start=1):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            records.append(IncidentRecord.from_dict(data))
                        except (json.JSONDecodeError, TypeError, KeyError) as exc:
                            logger.warning(
                                "Skipping malformed record at line %d: %s", lineno, exc
                            )
            except OSError as exc:
                logger.error("Failed to read storage file: %s", exc)
        return records

    def load_recent(self, limit: int = 100) -> list[IncidentRecord]:
        """
        Load the most recent `limit` incidents.

        Args:
            limit: Maximum number of incidents to return.

        Returns:
            The most recent incidents (newest last).
        """
        return self.load_all()[-limit:]

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """
        Compute summary statistics from all stored incidents.

        Returns:
            Dict with keys: total, high, medium, low, last_activity.
        """
        records = self.load_all()
        high = sum(1 for r in records if r.highest_severity == "HIGH")
        medium = sum(1 for r in records if r.highest_severity == "MEDIUM")
        low = sum(1 for r in records if r.highest_severity == "LOW")

        last_activity: Optional[str] = None
        if records:
            last_activity = records[-1].timestamp

        return {
            "total": len(records),
            "high": high,
            "medium": medium,
            "low": low,
            "last_activity": last_activity,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def make_incident_id() -> str:
        """Generate a unique incident ID based on current UTC time."""
        now = datetime.now(tz=timezone.utc)
        return f"INC-{now.strftime('%Y%m%d%H%M%S%f')}"

    @staticmethod
    def current_timestamp() -> str:
        """Return current UTC time as ISO-8601 string."""
        return datetime.now(tz=timezone.utc).isoformat()
