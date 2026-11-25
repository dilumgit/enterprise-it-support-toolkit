"""SQLite persistence layer for IT Help Desk and IT Asset Management."""

from src.database.db import (
    DatabaseError,
    DuplicateRecordError,
    RecordNotFoundError,
    ValidationError,
    get_connection,
    initialize_database,
    require_non_empty,
    utc_now_iso,
    validate_choice,
)

__all__ = [
    "DatabaseError",
    "DuplicateRecordError",
    "RecordNotFoundError",
    "ValidationError",
    "get_connection",
    "initialize_database",
    "require_non_empty",
    "utc_now_iso",
    "validate_choice",
]
