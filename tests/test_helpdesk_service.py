"""Unit tests for IT Help Desk & Incident Management service."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.database.db import DuplicateRecordError, RecordNotFoundError, ValidationError
from src.services.helpdesk_service import (
    add_ticket_comment,
    clear_demo_tickets,
    create_ticket,
    delete_ticket,
    export_tickets_csv,
    get_ticket,
    get_ticket_activities,
    get_ticket_summary,
    list_tickets,
    load_demo_tickets,
    update_ticket,
)


def test_create_ticket_generates_unique_ids_and_persists(tmp_path: Path) -> None:
    db = tmp_path / "helpdesk.db"
    t1 = create_ticket(
        ticket_type="Incident",
        title="VPN drops every 10 minutes",
        description="Disconnects on corporate Wi-Fi",
        requester_name="Jane Doe",
        department="Treasury",
        category="Network",
        priority="High",
        db_path=db,
    )
    t2 = create_ticket(
        ticket_type="Incident",
        title="Monitor flickering",
        description="Secondary DisplayPort flickering",
        requester_name="John Smith",
        department="Compliance",
        category="Hardware",
        priority="Low",
        db_path=db,
    )
    t3 = create_ticket(
        ticket_type="Service Request",
        title="Shared mailbox access",
        description="Read-only mailbox request",
        requester_name="Jane Doe",
        department="Treasury",
        category="User Access",
        priority="Medium",
        db_path=db,
    )

    assert t1.ticket_id.startswith("INC-")
    assert t2.ticket_id.startswith("INC-")
    assert t1.ticket_id != t2.ticket_id
    assert t3.ticket_id.startswith("REQ-")

    reloaded = get_ticket(t1.ticket_id, db_path=db)
    assert reloaded.title == "VPN drops every 10 minutes"
    assert reloaded.status == "Open"

    activities = get_ticket_activities(t1.ticket_id, db_path=db)
    assert len(activities) == 1
    assert activities[0].action == "Ticket Created"


def test_ticket_validation_and_duplicate_id_rejected(tmp_path: Path) -> None:
    db = tmp_path / "helpdesk_val.db"
    with pytest.raises(ValidationError):
        create_ticket(
            ticket_type="Incident",
            title="   ",
            description="Desc",
            requester_name="User",
            department="IT",
            category="Network",
            priority="Low",
            db_path=db,
        )

    with pytest.raises(ValidationError):
        create_ticket(
            ticket_type="Incident",
            title="Test",
            description="Desc",
            requester_name="User",
            department="IT",
            category="InvalidCat",
            priority="Low",
            db_path=db,
        )

    create_ticket(
        ticket_id="INC-CUSTOM-1",
        ticket_type="Incident",
        title="First",
        description="Desc",
        requester_name="User",
        department="IT",
        category="Other",
        priority="Low",
        db_path=db,
    )
    with pytest.raises(DuplicateRecordError):
        create_ticket(
            ticket_id="INC-CUSTOM-1",
            ticket_type="Incident",
            title="Duplicate",
            description="Desc",
            requester_name="User",
            department="IT",
            category="Other",
            priority="Low",
            db_path=db,
        )


def test_ticket_status_transitions_and_activity_history(tmp_path: Path) -> None:
    db = tmp_path / "helpdesk_flow.db"
    t = create_ticket(
        ticket_type="Incident",
        title="Cannot resolve internal DNS",
        description="nslookup times out",
        requester_name="Analyst",
        department="Operations",
        category="Network",
        priority="Critical",
        db_path=db,
    )

    # Resolving without resolution notes must fail
    with pytest.raises(ValidationError):
        update_ticket(t.ticket_id, status="Resolved", resolution_notes="  ", db_path=db)

    in_prog = update_ticket(
        t.ticket_id,
        status="In Progress",
        assigned_technician="NetOps",
        troubleshooting_notes="Checked gateway",
        db_path=db,
    )
    assert in_prog.status == "In Progress"
    assert in_prog.resolved_at is None

    resolved = update_ticket(
        t.ticket_id,
        status="Resolved",
        resolution_notes="Updated DHCP DNS server option.",
        db_path=db,
    )
    assert resolved.status == "Resolved"
    assert resolved.resolved_at is not None

    closed = update_ticket(t.ticket_id, status="Closed", db_path=db)
    assert closed.status == "Closed"

    # Closed -> Resolved directly is blocked without reopening to Open
    with pytest.raises(ValidationError):
        update_ticket(t.ticket_id, status="Resolved", db_path=db)

    reopened = update_ticket(t.ticket_id, status="Open", db_path=db)
    assert reopened.status == "Open"
    assert reopened.resolved_at is None

    add_ticket_comment(t.ticket_id, actor="NetOps", note="Monitoring user connection.", db_path=db)
    activities = get_ticket_activities(t.ticket_id, db_path=db)
    assert len(activities) == 6


def test_ticket_filtering_summary_csv_delete_and_demo(tmp_path: Path) -> None:
    db = tmp_path / "helpdesk_filter.db"
    added = load_demo_tickets(db_path=db)
    assert added == 3
    # Re-running does not duplicate or overwrite
    assert load_demo_tickets(db_path=db) == 0

    network_tickets = list_tickets(category="Network", db_path=db)
    assert len(network_tickets) == 1
    assert network_tickets[0].is_demo is True

    search_hits = list_tickets(search="Risk Batch", db_path=db)
    assert len(search_hits) == 1

    summary = get_ticket_summary(db_path=db)
    assert summary.total == 3
    assert summary.open_count == 1
    assert summary.in_progress_count == 1
    assert summary.resolved_count == 1

    csv_text = export_tickets_csv(network_tickets)
    assert "Ticket ID" in csv_text
    assert "INC-DEMO-0001" in csv_text

    removed = clear_demo_tickets(db_path=db)
    assert removed == 3
    assert list_tickets(db_path=db) == []

    with pytest.raises(RecordNotFoundError):
        delete_ticket("INC-DOES-NOT-EXIST", db_path=db)
