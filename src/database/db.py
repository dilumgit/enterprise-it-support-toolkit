"""SQLite database connection management, schema initialization, and migrations."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from src.config.settings import DEFAULT_DB_PATH


class DatabaseError(Exception):
    """Raised when a local SQLite persistence operation fails."""


class ValidationError(ValueError):
    """Raised when user or service input fails validation constraints."""


class DuplicateRecordError(ValueError):
    """Raised when attempting to insert a record with an existing unique identifier."""


class RecordNotFoundError(LookupError):
    """Raised when a requested ticket, asset, or license identifier does not exist."""


def require_non_empty(value: str, field_label: str) -> str:
    """Validate that a required string field is non-empty after stripping."""
    cleaned = (value or "").strip()
    if not cleaned:
        raise ValidationError(f"{field_label} is required.")
    return cleaned


def validate_choice(value: str, allowed: tuple[str, ...], field_label: str) -> str:
    """Validate that a field matches an allowed enumeration."""
    cleaned = (value or "").strip()
    if cleaned not in allowed:
        raise ValidationError(f"Invalid {field_label}: '{cleaned}'. Allowed: {', '.join(allowed)}.")
    return cleaned


_MIGRATIONS: list[tuple[int, str, list[str]]] = [
    (
        1,
        "Initial schema for IT Help Desk tickets, activities, IT assets, software inventory, and licenses",
        [
            """
            CREATE TABLE IF NOT EXISTS tickets (
                ticket_id TEXT PRIMARY KEY,
                ticket_type TEXT NOT NULL CHECK (ticket_type IN ('Incident', 'Service Request')),
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                requester_name TEXT NOT NULL,
                department TEXT NOT NULL,
                category TEXT NOT NULL CHECK (category IN ('Hardware', 'Software', 'Network', 'Security', 'User Access', 'Other')),
                priority TEXT NOT NULL CHECK (priority IN ('Low', 'Medium', 'High', 'Critical')),
                status TEXT NOT NULL CHECK (status IN ('Open', 'In Progress', 'Resolved', 'Closed')),
                assigned_technician TEXT NOT NULL,
                troubleshooting_notes TEXT NOT NULL DEFAULT '',
                resolution_notes TEXT NOT NULL DEFAULT '',
                is_demo INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                resolved_at TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS ticket_activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id TEXT NOT NULL REFERENCES tickets(ticket_id) ON DELETE CASCADE,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_tickets_status_priority
            ON tickets (status, priority)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_ticket_activities_ticket_id
            ON ticket_activities (ticket_id)
            """,
            """
            CREATE TABLE IF NOT EXISTS assets (
                asset_id TEXT PRIMARY KEY,
                asset_name TEXT NOT NULL,
                category TEXT NOT NULL CHECK (category IN ('Desktop', 'Laptop', 'Printer', 'Network Device', 'Server', 'Other')),
                manufacturer TEXT NOT NULL,
                model TEXT NOT NULL,
                serial_number TEXT NOT NULL DEFAULT '',
                operating_system TEXT NOT NULL DEFAULT '',
                assigned_employee TEXT NOT NULL DEFAULT '',
                department TEXT NOT NULL DEFAULT '',
                location TEXT NOT NULL DEFAULT '',
                purchase_date TEXT NOT NULL DEFAULT '',
                warranty_expiration TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL CHECK (status IN ('Available', 'Assigned', 'Under Maintenance', 'Retired')),
                hardware_summary TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                is_demo INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS asset_software_inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
                software_name TEXT NOT NULL,
                version TEXT NOT NULL DEFAULT '',
                publisher TEXT NOT NULL DEFAULT '',
                install_date TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT 'Manual',
                recorded_at TEXT NOT NULL,
                UNIQUE (asset_id, software_name, version)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS software_licenses (
                license_id TEXT PRIMARY KEY,
                software_name TEXT NOT NULL,
                vendor TEXT NOT NULL,
                license_type TEXT NOT NULL CHECK (
                    license_type IN (
                        'Subscription',
                        'Perpetual',
                        'Volume',
                        'Named User',
                        'Concurrent',
                        'Open Source / Freeware',
                        'Other'
                    )
                ),
                quantity INTEGER NOT NULL CHECK (quantity >= 1),
                assigned_count INTEGER NOT NULL DEFAULT 0 CHECK (assigned_count >= 0),
                expiration_date TEXT NOT NULL DEFAULT '',
                department TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                is_demo INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
        ],
    ),
]


def utc_now_iso() -> str:
    """Return the current local/UTC timestamp formatted cleanly as YYYY-MM-DD HH:MM:SS."""
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _resolve_db_path(db_path: Path | str | None) -> Path:
    """Resolve and ensure parent directory exists for a SQLite database file."""
    path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    return path


@contextmanager
def get_connection(db_path: Path | str | None = None) -> Iterator[sqlite3.Connection]:
    """Yield a parameterized-query-ready SQLite connection with foreign keys enabled."""
    resolved = _resolve_db_path(db_path)
    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(str(resolved), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        yield conn
        conn.commit()
    except sqlite3.Error as exc:
        if conn is not None:
            conn.rollback()
        raise DatabaseError(f"SQLite operation failed: {exc}") from exc
    finally:
        if conn is not None:
            conn.close()


def initialize_database(db_path: Path | str | None = None) -> int:
    """
    Initialize the SQLite database and apply pending schema migrations safely.

    Never overwrites existing records; returns the highest applied schema version.
    """
    with get_connection(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                description TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        rows = conn.execute("SELECT version FROM schema_migrations").fetchall()
        applied_versions = {int(row["version"]) for row in rows}

        latest_version = max(applied_versions, default=0)
        for version, description, statements in _MIGRATIONS:
            if version in applied_versions:
                continue
            for stmt in statements:
                conn.execute(stmt)
            conn.execute(
                """
                INSERT INTO schema_migrations (version, description, applied_at)
                VALUES (?, ?, ?)
                """,
                (version, description, utc_now_iso()),
            )
            latest_version = max(latest_version, version)

        return latest_version
