"""Unit tests for the SQLite database layer and safe schema migrations."""

from __future__ import annotations

from pathlib import Path

from src.database.db import get_connection, initialize_database


def test_initialize_database_is_idempotent_and_preserves_existing_records(tmp_path: Path) -> None:
    db_file = tmp_path / "toolkit_test.db"
    v1 = initialize_database(db_file)
    assert v1 >= 1

    with get_connection(db_file) as conn:
        conn.execute(
            """
            INSERT INTO tickets (
                ticket_id, ticket_type, title, description, requester_name, department,
                category, priority, status, assigned_technician, troubleshooting_notes,
                resolution_notes, is_demo, created_at, updated_at, resolved_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "INC-KEEP-0001",
                "Incident",
                "Existing Ticket",
                "Must survive re-initialization",
                "Analyst",
                "IT",
                "Software",
                "Low",
                "Open",
                "Support",
                "",
                "",
                0,
                "2026-11-25 07:00:00",
                "2026-11-25 07:00:00",
                None,
            ),
        )

    v2 = initialize_database(db_file)
    assert v2 == v1

    with get_connection(db_file) as conn:
        row = conn.execute("SELECT title FROM tickets WHERE ticket_id = ?", ("INC-KEEP-0001",)).fetchone()
        migrations = conn.execute("SELECT version FROM schema_migrations").fetchall()

    assert row is not None
    assert row["title"] == "Existing Ticket"
    assert len(migrations) == 1
