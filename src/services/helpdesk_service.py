"""IT Help Desk & Incident Management service backed by SQLite."""

from __future__ import annotations

import csv
import io
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from src.config.settings import DEFAULT_DB_PATH
from src.database.db import (
    DuplicateRecordError,
    RecordNotFoundError,
    ValidationError,
    get_connection,
    initialize_database,
    require_non_empty,
    utc_now_iso,
    validate_choice,
)
from src.utils.formatting import sanitize_csv_cell

TICKET_TYPES: tuple[str, ...] = ("Incident", "Service Request")
TICKET_CATEGORIES: tuple[str, ...] = (
    "Hardware",
    "Software",
    "Network",
    "Security",
    "User Access",
    "Other",
)
TICKET_PRIORITIES: tuple[str, ...] = ("Low", "Medium", "High", "Critical")
TICKET_STATUSES: tuple[str, ...] = ("Open", "In Progress", "Resolved", "Closed")

ALLOWED_STATUS_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "Open": ("Open", "In Progress", "Resolved", "Closed"),
    "In Progress": ("In Progress", "Open", "Resolved", "Closed"),
    "Resolved": ("Resolved", "In Progress", "Closed", "Open"),
    "Closed": ("Closed", "Open"),
}

_SORT_EXPRESSIONS: dict[str, str] = {
    "created_at": "created_at",
    "updated_at": "updated_at",
    "ticket_id": "ticket_id",
    "status": "status",
    "priority": "CASE priority WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END",
}


@dataclass(frozen=True)
class Ticket:
    """Represents a persisted IT Help Desk incident or service request."""

    ticket_id: str
    ticket_type: str
    title: str
    description: str
    requester_name: str
    department: str
    category: str
    priority: str
    status: str
    assigned_technician: str
    troubleshooting_notes: str
    resolution_notes: str
    is_demo: bool
    created_at: str
    updated_at: str
    resolved_at: str | None


@dataclass(frozen=True)
class TicketActivity:
    """Audit trail entry for a help desk ticket."""

    id: int
    ticket_id: str
    actor: str
    action: str
    details: str
    created_at: str


@dataclass(frozen=True)
class TicketSummary:
    """Aggregated help desk metrics for dashboards."""

    total: int
    open_count: int
    in_progress_count: int
    resolved_count: int
    closed_count: int
    critical_open_count: int
    by_category: dict[str, int]
    by_priority: dict[str, int]


def _row_to_ticket(row: sqlite3.Row) -> Ticket:
    """Convert a SQLite row into an immutable Ticket dataclass."""
    return Ticket(
        ticket_id=str(row["ticket_id"]),
        ticket_type=str(row["ticket_type"]),
        title=str(row["title"]),
        description=str(row["description"]),
        requester_name=str(row["requester_name"]),
        department=str(row["department"]),
        category=str(row["category"]),
        priority=str(row["priority"]),
        status=str(row["status"]),
        assigned_technician=str(row["assigned_technician"]),
        troubleshooting_notes=str(row["troubleshooting_notes"]),
        resolution_notes=str(row["resolution_notes"]),
        is_demo=bool(row["is_demo"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
        resolved_at=str(row["resolved_at"]) if row["resolved_at"] is not None else None,
    )


def _generate_ticket_id(conn: sqlite3.Connection, ticket_type: str) -> str:
    """Generate a unique sequential ticket ID (INC-YYYYMMDD-XXXX or REQ-YYYYMMDD-XXXX)."""
    prefix = "INC" if ticket_type == "Incident" else "REQ"
    date_part = datetime.now().strftime("%Y%m%d")
    pattern = f"{prefix}-{date_part}-%"
    rows = conn.execute(
        "SELECT ticket_id FROM tickets WHERE ticket_id LIKE ?",
        (pattern,),
    ).fetchall()

    max_seq = 0
    for row in rows:
        parts = str(row["ticket_id"]).rsplit("-", 1)
        if len(parts) == 2 and parts[1].isdigit():
            max_seq = max(max_seq, int(parts[1]))

    return f"{prefix}-{date_part}-{max_seq + 1:04d}"


def _log_activity(
    conn: sqlite3.Connection,
    ticket_id: str,
    actor: str,
    action: str,
    details: str,
    timestamp: str,
) -> None:
    """Insert an activity audit entry for a ticket."""
    conn.execute(
        """
        INSERT INTO ticket_activities (ticket_id, actor, action, details, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (ticket_id, actor, action, details, timestamp),
    )


def create_ticket(
    *,
    ticket_type: str,
    title: str,
    description: str,
    requester_name: str,
    department: str,
    category: str,
    priority: str,
    assigned_technician: str = "Unassigned",
    troubleshooting_notes: str = "",
    ticket_id: str | None = None,
    is_demo: bool = False,
    db_path: Path | str = DEFAULT_DB_PATH,
) -> Ticket:
    """Create and persist a new IT Help Desk ticket with initial activity history."""
    initialize_database(db_path)

    clean_type = validate_choice(ticket_type, TICKET_TYPES, "ticket type")
    clean_title = require_non_empty(title, "Ticket title")
    clean_desc = require_non_empty(description, "Ticket description")
    clean_req = require_non_empty(requester_name, "Requester name")
    clean_dept = require_non_empty(department, "Department")
    clean_cat = validate_choice(category, TICKET_CATEGORIES, "category")
    clean_prio = validate_choice(priority, TICKET_PRIORITIES, "priority")
    clean_tech = (assigned_technician or "").strip() or "Unassigned"
    clean_notes = (troubleshooting_notes or "").strip()

    now = utc_now_iso()

    with get_connection(db_path) as conn:
        final_id = (ticket_id or "").strip() or _generate_ticket_id(conn, clean_type)
        existing = conn.execute(
            "SELECT 1 FROM tickets WHERE ticket_id = ?",
            (final_id,),
        ).fetchone()
        if existing is not None:
            raise DuplicateRecordError(f"Ticket ID '{final_id}' already exists.")

        conn.execute(
            """
            INSERT INTO tickets (
                ticket_id, ticket_type, title, description, requester_name, department,
                category, priority, status, assigned_technician, troubleshooting_notes,
                resolution_notes, is_demo, created_at, updated_at, resolved_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                final_id,
                clean_type,
                clean_title,
                clean_desc,
                clean_req,
                clean_dept,
                clean_cat,
                clean_prio,
                "Open",
                clean_tech,
                clean_notes,
                "",
                1 if is_demo else 0,
                now,
                now,
                None,
            ),
        )
        _log_activity(
            conn,
            final_id,
            clean_req,
            "Ticket Created",
            f"{clean_type} opened under {clean_cat} ({clean_prio} priority), assigned to {clean_tech}.",
            now,
        )
        row = conn.execute("SELECT * FROM tickets WHERE ticket_id = ?", (final_id,)).fetchone()
        return _row_to_ticket(row)


def get_ticket(ticket_id: str, db_path: Path | str = DEFAULT_DB_PATH) -> Ticket:
    """Retrieve a single ticket by its unique ID."""
    initialize_database(db_path)
    clean_id = require_non_empty(ticket_id, "Ticket ID")
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM tickets WHERE ticket_id = ?", (clean_id,)).fetchone()
        if row is None:
            raise RecordNotFoundError(f"Ticket '{clean_id}' was not found.")
        return _row_to_ticket(row)


def list_tickets(
    *,
    search: str = "",
    category: str = "All",
    priority: str = "All",
    status: str = "All",
    ticket_type: str = "All",
    sort_by: str = "created_at",
    sort_desc: bool = True,
    db_path: Path | str = DEFAULT_DB_PATH,
) -> list[Ticket]:
    """Query persisted tickets using safe parameterized filters and allowlisted sorting."""
    initialize_database(db_path)
    clauses: list[str] = []
    params: list[str] = []

    cleaned_search = (search or "").strip()
    if cleaned_search:
        like_term = f"%{cleaned_search}%"
        clauses.append(
            "(ticket_id LIKE ? OR title LIKE ? OR description LIKE ? "
            "OR requester_name LIKE ? OR department LIKE ? OR assigned_technician LIKE ?)"
        )
        params.extend([like_term] * 6)

    for column, value in (
        ("category", category),
        ("priority", priority),
        ("status", status),
        ("ticket_type", ticket_type),
    ):
        if value and value != "All":
            clauses.append(f"{column} = ?")
            params.append(value)

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sort_expr = _SORT_EXPRESSIONS.get(sort_by, "created_at")
    direction = "DESC" if sort_desc else "ASC"
    sql = f"SELECT * FROM tickets {where_sql} ORDER BY {sort_expr} {direction}, ticket_id DESC"

    with get_connection(db_path) as conn:
        rows = conn.execute(sql, tuple(params)).fetchall()
        return [_row_to_ticket(row) for row in rows]


def update_ticket(
    ticket_id: str,
    *,
    status: str | None = None,
    priority: str | None = None,
    assigned_technician: str | None = None,
    troubleshooting_notes: str | None = None,
    resolution_notes: str | None = None,
    actor: str = "IT Support Analyst",
    db_path: Path | str = DEFAULT_DB_PATH,
) -> Ticket:
    """Update ticket fields, enforce valid status transitions, and append activity history."""
    initialize_database(db_path)
    clean_id = require_non_empty(ticket_id, "Ticket ID")
    clean_actor = (actor or "").strip() or "IT Support Analyst"

    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM tickets WHERE ticket_id = ?", (clean_id,)).fetchone()
        if row is None:
            raise RecordNotFoundError(f"Ticket '{clean_id}' was not found.")
        current = _row_to_ticket(row)

        new_status = current.status
        if status is not None:
            new_status = validate_choice(status, TICKET_STATUSES, "status")
            allowed_next = ALLOWED_STATUS_TRANSITIONS[current.status]
            if new_status not in allowed_next:
                raise ValidationError(
                    f"Cannot transition ticket from '{current.status}' to '{new_status}'. "
                    f"Allowed next statuses: {', '.join(allowed_next)}."
                )

        new_priority = (
            validate_choice(priority, TICKET_PRIORITIES, "priority")
            if priority is not None
            else current.priority
        )
        new_tech = (
            (assigned_technician.strip() or "Unassigned")
            if assigned_technician is not None
            else current.assigned_technician
        )
        new_trouble = (
            troubleshooting_notes.strip()
            if troubleshooting_notes is not None
            else current.troubleshooting_notes
        )
        new_resolution = (
            resolution_notes.strip()
            if resolution_notes is not None
            else current.resolution_notes
        )

        if new_status == "Resolved" and not new_resolution:
            raise ValidationError("Resolution notes are required when resolving a ticket.")

        now = utc_now_iso()
        new_resolved_at = current.resolved_at
        if new_status in {"Resolved", "Closed"} and current.resolved_at is None:
            new_resolved_at = now
        elif new_status in {"Open", "In Progress"}:
            new_resolved_at = None

        changes: list[str] = []
        if new_status != current.status:
            changes.append(f"Status: {current.status} -> {new_status}")
        if new_priority != current.priority:
            changes.append(f"Priority: {current.priority} -> {new_priority}")
        if new_tech != current.assigned_technician:
            changes.append(f"Assigned: {current.assigned_technician} -> {new_tech}")
        if new_trouble != current.troubleshooting_notes:
            changes.append("Troubleshooting notes updated")
        if new_resolution != current.resolution_notes:
            changes.append("Resolution notes updated")

        if not changes:
            return current

        conn.execute(
            """
            UPDATE tickets
            SET status = ?,
                priority = ?,
                assigned_technician = ?,
                troubleshooting_notes = ?,
                resolution_notes = ?,
                updated_at = ?,
                resolved_at = ?
            WHERE ticket_id = ?
            """,
            (
                new_status,
                new_priority,
                new_tech,
                new_trouble,
                new_resolution,
                now,
                new_resolved_at,
                clean_id,
            ),
        )
        _log_activity(conn, clean_id, clean_actor, "Ticket Updated", "; ".join(changes), now)
        updated = conn.execute("SELECT * FROM tickets WHERE ticket_id = ?", (clean_id,)).fetchone()
        return _row_to_ticket(updated)


def add_ticket_comment(
    ticket_id: str,
    *,
    actor: str,
    note: str,
    db_path: Path | str = DEFAULT_DB_PATH,
) -> TicketActivity:
    """Append a standalone work note to a ticket's activity timeline."""
    initialize_database(db_path)
    clean_id = require_non_empty(ticket_id, "Ticket ID")
    clean_note = require_non_empty(note, "Activity note")
    clean_actor = (actor or "").strip() or "IT Support Analyst"
    now = utc_now_iso()

    with get_connection(db_path) as conn:
        existing = conn.execute("SELECT 1 FROM tickets WHERE ticket_id = ?", (clean_id,)).fetchone()
        if existing is None:
            raise RecordNotFoundError(f"Ticket '{clean_id}' was not found.")
        cursor = conn.execute(
            """
            INSERT INTO ticket_activities (ticket_id, actor, action, details, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (clean_id, clean_actor, "Work Note", clean_note, now),
        )
        conn.execute("UPDATE tickets SET updated_at = ? WHERE ticket_id = ?", (now, clean_id))
        return TicketActivity(
            id=int(cursor.lastrowid),
            ticket_id=clean_id,
            actor=clean_actor,
            action="Work Note",
            details=clean_note,
            created_at=now,
        )


def get_ticket_activities(
    ticket_id: str,
    db_path: Path | str = DEFAULT_DB_PATH,
) -> list[TicketActivity]:
    """Retrieve chronological activity history for a ticket."""
    initialize_database(db_path)
    clean_id = require_non_empty(ticket_id, "Ticket ID")
    with get_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT id, ticket_id, actor, action, details, created_at
            FROM ticket_activities
            WHERE ticket_id = ?
            ORDER BY id DESC
            """,
            (clean_id,),
        ).fetchall()
        return [
            TicketActivity(
                id=int(r["id"]),
                ticket_id=str(r["ticket_id"]),
                actor=str(r["actor"]),
                action=str(r["action"]),
                details=str(r["details"]),
                created_at=str(r["created_at"]),
            )
            for r in rows
        ]


def delete_ticket(ticket_id: str, db_path: Path | str = DEFAULT_DB_PATH) -> None:
    """Permanently delete a ticket and its cascading activity rows."""
    initialize_database(db_path)
    clean_id = require_non_empty(ticket_id, "Ticket ID")
    with get_connection(db_path) as conn:
        cursor = conn.execute("DELETE FROM tickets WHERE ticket_id = ?", (clean_id,))
        if cursor.rowcount == 0:
            raise RecordNotFoundError(f"Ticket '{clean_id}' was not found.")


def get_ticket_summary(db_path: Path | str = DEFAULT_DB_PATH) -> TicketSummary:
    """Compute Help Desk KPI counts for dashboard summaries."""
    tickets = list_tickets(db_path=db_path)
    by_category: dict[str, int] = {cat: 0 for cat in TICKET_CATEGORIES}
    by_priority: dict[str, int] = {prio: 0 for prio in TICKET_PRIORITIES}

    open_count = in_progress = resolved = closed = critical_open = 0
    for t in tickets:
        by_category[t.category] = by_category.get(t.category, 0) + 1
        by_priority[t.priority] = by_priority.get(t.priority, 0) + 1
        if t.status == "Open":
            open_count += 1
        elif t.status == "In Progress":
            in_progress += 1
        elif t.status == "Resolved":
            resolved += 1
        elif t.status == "Closed":
            closed += 1
        if t.priority == "Critical" and t.status in {"Open", "In Progress"}:
            critical_open += 1

    return TicketSummary(
        total=len(tickets),
        open_count=open_count,
        in_progress_count=in_progress,
        resolved_count=resolved,
        closed_count=closed,
        critical_open_count=critical_open,
        by_category=by_category,
        by_priority=by_priority,
    )


def export_tickets_csv(tickets: list[Ticket]) -> str:
    """Serialize tickets into a clean UTF-8 CSV string."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "Ticket ID",
            "Type",
            "Title",
            "Description",
            "Requester",
            "Department",
            "Category",
            "Priority",
            "Status",
            "Assigned Technician",
            "Troubleshooting Notes",
            "Resolution Notes",
            "Demo Record",
            "Created At",
            "Updated At",
            "Resolved At",
        ]
    )
    for t in tickets:
        writer.writerow(
            [
                sanitize_csv_cell(field_val)
                for field_val in (
                    t.ticket_id,
                    t.ticket_type,
                    t.title,
                    t.description,
                    t.requester_name,
                    t.department,
                    t.category,
                    t.priority,
                    t.status,
                    t.assigned_technician,
                    t.troubleshooting_notes,
                    t.resolution_notes,
                    "Yes" if t.is_demo else "No",
                    t.created_at,
                    t.updated_at,
                    t.resolved_at or "",
                )
            ]
        )
    return buffer.getvalue()


def load_demo_tickets(db_path: Path | str = DEFAULT_DB_PATH) -> int:
    """
    Insert clearly labeled fictional financial-services demo tickets if absent.

    Never overwrites existing records; returns count of newly inserted demo tickets.
    """
    initialize_database(db_path)
    demo_specs = [
        {
            "ticket_id": "INC-DEMO-0001",
            "ticket_type": "Incident",
            "title": "[DEMO] Trading Floor VPN DNS Lookup Timeout",
            "description": "Fictional sample: Workstation resolves internal gateway but external FQDN lookups time out over split-tunnel VPN.",
            "requester_name": "Jordan Blake (Demo)",
            "department": "Equities Desk (Demo)",
            "category": "Network",
            "priority": "High",
            "status": "In Progress",
            "assigned_technician": "Tier 2 NetOps (Demo)",
            "troubleshooting_notes": "Confirmed adapter IPv4 lease and gateway ping; investigating corporate DNS forwarder.",
            "resolution_notes": "",
        },
        {
            "ticket_id": "REQ-DEMO-0002",
            "ticket_type": "Service Request",
            "title": "[DEMO] Read-Only Bloomberg Terminal Access Onboarding",
            "description": "Fictional sample: Provision standard analyst workstation software profile and access group.",
            "requester_name": "Priya Nair (Demo)",
            "department": "Risk & Compliance (Demo)",
            "category": "User Access",
            "priority": "Medium",
            "status": "Open",
            "assigned_technician": "IAM Desk (Demo)",
            "troubleshooting_notes": "Awaiting manager sign-off reference.",
            "resolution_notes": "",
        },
        {
            "ticket_id": "INC-DEMO-0003",
            "ticket_type": "Incident",
            "title": "[DEMO] Endpoint RAM Saturation During Risk Batch",
            "description": "Fictional sample: Laptop reaches 94% memory utilization while running spreadsheet macros.",
            "requester_name": "Marcus Chen (Demo)",
            "department": "Treasury Operations (Demo)",
            "category": "Hardware",
            "priority": "Medium",
            "status": "Resolved",
            "assigned_technician": "Desktop Support (Demo)",
            "troubleshooting_notes": "Verified 16 GB dual-channel DIMMs healthy; identified duplicate background browser tabs.",
            "resolution_notes": "Cleared orphaned background processes and scheduled 32 GB RAM upgrade request.",
        },
    ]

    inserted = 0
    for spec in demo_specs:
        try:
            created = create_ticket(
                ticket_id=spec["ticket_id"],
                ticket_type=spec["ticket_type"],
                title=spec["title"],
                description=spec["description"],
                requester_name=spec["requester_name"],
                department=spec["department"],
                category=spec["category"],
                priority=spec["priority"],
                assigned_technician=spec["assigned_technician"],
                troubleshooting_notes=spec["troubleshooting_notes"],
                is_demo=True,
                db_path=db_path,
            )
            if spec["status"] == "In Progress":
                update_ticket(created.ticket_id, status="In Progress", actor="Demo Seed", db_path=db_path)
            elif spec["status"] == "Resolved":
                update_ticket(
                    created.ticket_id,
                    status="Resolved",
                    resolution_notes=spec["resolution_notes"],
                    actor="Demo Seed",
                    db_path=db_path,
                )
            inserted += 1
        except DuplicateRecordError:
            continue
    return inserted


def clear_demo_tickets(db_path: Path | str = DEFAULT_DB_PATH) -> int:
    """Remove only records explicitly flagged as fictional demo tickets."""
    initialize_database(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.execute("DELETE FROM tickets WHERE is_demo = 1")
        return int(cursor.rowcount)
