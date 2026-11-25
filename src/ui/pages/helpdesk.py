"""IT Help Desk & Incident Management dedicated page."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from src.database.db import DatabaseError, DuplicateRecordError, RecordNotFoundError, ValidationError
from src.services.helpdesk_service import (
    ALLOWED_STATUS_TRANSITIONS,
    TICKET_CATEGORIES,
    TICKET_PRIORITIES,
    TICKET_STATUSES,
    TICKET_TYPES,
    add_ticket_comment,
    clear_demo_tickets,
    create_ticket,
    delete_ticket,
    export_tickets_csv,
    get_ticket_activities,
    get_ticket_summary,
    list_tickets,
    load_demo_tickets,
    update_ticket,
)
from src.ui.components import (
    PLOTLY_CONFIG,
    build_count_bar_chart,
    render_kpi_card,
    render_page_header,
    render_section_title,
)


def render() -> None:
    """Render the IT Help Desk & Incident Management page."""
    render_page_header(
        title="IT Help Desk & Incident Management",
        subtitle="Persistent SQLite incident and service request tracking with activity history and CSV export.",
        badge_text="Implemented",
    )

    try:
        summary = get_ticket_summary()
    except DatabaseError as exc:
        st.error(f"Database error loading Help Desk summary: {exc}")
        return

    # KPI Row
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        render_kpi_card("Total Tickets", str(summary.total), "All persisted records")
    with k2:
        render_kpi_card(
            "Open / In Progress",
            f"{summary.open_count} / {summary.in_progress_count}",
            "Active service queue",
            status="Open" if summary.open_count > 0 else "Healthy",
        )
    with k3:
        render_kpi_card(
            "Critical Active",
            str(summary.critical_open_count),
            "Critical Open or In Progress",
            status="Critical" if summary.critical_open_count > 0 else "Healthy",
        )
    with k4:
        render_kpi_card(
            "Resolved / Closed",
            f"{summary.resolved_count} / {summary.closed_count}",
            "Completed tickets",
            status="Resolved",
        )

    st.write("")

    tab_queue, tab_create, tab_manage, tab_summary = st.tabs(
        ["Ticket Queue & Search", "Create New Ticket", "Update & Activity History", "Summary & Demo Controls"]
    )

    with tab_queue:
        f1, f2, f3, f4, f5 = st.columns([2.2, 1, 1, 1, 1.2])
        with f1:
            search = st.text_input(
                "Search tickets",
                placeholder="ID, title, requester, department, technician",
                key="hd_search",
            )
        with f2:
            cat_filter = st.selectbox("Category", ["All", *TICKET_CATEGORIES], key="hd_cat_filter")
        with f3:
            prio_filter = st.selectbox("Priority", ["All", *TICKET_PRIORITIES], key="hd_prio_filter")
        with f4:
            stat_filter = st.selectbox("Status", ["All", *TICKET_STATUSES], key="hd_stat_filter")
        with f5:
            sort_by = st.selectbox(
                "Sort by",
                ["created_at", "updated_at", "priority", "status", "ticket_id"],
                key="hd_sort_by",
            )

        c_type, c_order, c_export = st.columns([1.2, 1, 1.2])
        with c_type:
            type_filter = st.selectbox("Type", ["All", *TICKET_TYPES], key="hd_type_filter")
        with c_order:
            sort_desc = st.checkbox("Descending order", value=True, key="hd_sort_desc")

        tickets = list_tickets(
            search=search,
            category=cat_filter,
            priority=prio_filter,
            status=stat_filter,
            ticket_type=type_filter,
            sort_by=sort_by,
            sort_desc=sort_desc,
        )

        with c_export:
            st.write("")
            st.download_button(
                label=f"Export Filtered CSV ({len(tickets)})",
                data=export_tickets_csv(tickets),
                file_name="helpdesk_tickets.csv",
                mime="text/csv",
                width="stretch",
                disabled=not tickets,
            )

        if tickets:
            rows = [
                {
                    "Ticket ID": t.ticket_id,
                    "Type": t.ticket_type,
                    "Title": t.title,
                    "Category": t.category,
                    "Priority": t.priority,
                    "Status": t.status,
                    "Requester": t.requester_name,
                    "Department": t.department,
                    "Assigned": t.assigned_technician,
                    "Demo": "Yes" if t.is_demo else "No",
                    "Updated": t.updated_at,
                }
                for t in tickets
            ]
            st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
        else:
            st.info("No tickets found matching the current filters. Create a ticket or load fictional demo data.")

    with tab_create:
        render_section_title("Submit Incident or Service Request")
        with st.form("create_ticket_form", clear_on_submit=True):
            c1, c2, c3 = st.columns(3)
            with c1:
                ticket_type = st.selectbox("Ticket Type *", TICKET_TYPES)
            with c2:
                category = st.selectbox("Category *", TICKET_CATEGORIES)
            with c3:
                priority = st.selectbox("Priority *", TICKET_PRIORITIES, index=1)

            title = st.text_input("Title *", placeholder="Concise summary of the issue or request")
            description = st.text_area("Detailed Description *", placeholder="Symptoms, impact, steps to reproduce...")

            r1, r2, r3 = st.columns(3)
            with r1:
                requester_name = st.text_input("Requester Name *", placeholder="e.g., Alex Morgan")
            with r2:
                department = st.text_input("Department *", placeholder="e.g., Trading Operations")
            with r3:
                assigned_tech = st.text_input("Assigned Technician", value="Tier 1 Support")

            trouble_notes = st.text_area("Initial Troubleshooting Notes (Optional)")
            submitted = st.form_submit_button("Create Ticket", type="primary")

            if submitted:
                try:
                    created = create_ticket(
                        ticket_type=ticket_type,
                        title=title,
                        description=description,
                        requester_name=requester_name,
                        department=department,
                        category=category,
                        priority=priority,
                        assigned_technician=assigned_tech,
                        troubleshooting_notes=trouble_notes,
                    )
                    st.success(f"Ticket `{created.ticket_id}` created and persisted.")
                    st.rerun()
                except (ValidationError, DuplicateRecordError, DatabaseError) as exc:
                    st.error(str(exc))

    with tab_manage:
        all_tickets = list_tickets()
        if not all_tickets:
            st.info("No tickets available to inspect or update.")
        else:
            options = {f"{t.ticket_id} — {t.title} [{t.status}]": t.ticket_id for t in all_tickets}
            selected_label = st.selectbox("Select Ticket", list(options.keys()), key="hd_manage_select")
            selected_id = options[selected_label]
            ticket = next(t for t in all_tickets if t.ticket_id == selected_id)

            st.caption(
                f"**Type:** {ticket.ticket_type} | **Requester:** {ticket.requester_name} ({ticket.department}) | "
                f"**Created:** {ticket.created_at} | **Updated:** {ticket.updated_at}"
                + (f" | **Resolved:** {ticket.resolved_at}" if ticket.resolved_at else "")
            )
            st.markdown(f"**Description:** {ticket.description}")

            allowed_statuses = ALLOWED_STATUS_TRANSITIONS[ticket.status]
            with st.form("update_ticket_form"):
                u1, u2, u3 = st.columns(3)
                with u1:
                    new_status = st.selectbox(
                        "Status",
                        allowed_statuses,
                        index=allowed_statuses.index(ticket.status),
                    )
                with u2:
                    new_priority = st.selectbox(
                        "Priority",
                        TICKET_PRIORITIES,
                        index=TICKET_PRIORITIES.index(ticket.priority),
                    )
                with u3:
                    new_tech = st.text_input("Assigned Technician", value=ticket.assigned_technician)

                actor_name = st.text_input("Updated By (Analyst)", value="IT Support Analyst")
                new_trouble = st.text_area("Troubleshooting Notes", value=ticket.troubleshooting_notes)
                new_resolution = st.text_area(
                    "Resolution Notes (Required when setting status to Resolved)",
                    value=ticket.resolution_notes,
                )
                save_btn = st.form_submit_button("Save Ticket Changes", type="primary")

                if save_btn:
                    try:
                        update_ticket(
                            ticket.ticket_id,
                            status=new_status,
                            priority=new_priority,
                            assigned_technician=new_tech,
                            troubleshooting_notes=new_trouble,
                            resolution_notes=new_resolution,
                            actor=actor_name,
                        )
                        st.success(f"Ticket `{ticket.ticket_id}` updated.")
                        st.rerun()
                    except (ValidationError, RecordNotFoundError, DatabaseError) as exc:
                        st.error(str(exc))

            col_note, col_del = st.columns([1.4, 1])
            with col_note:
                render_section_title("Add Work Note")
                with st.form("add_note_form", clear_on_submit=True):
                    note_actor = st.text_input("Author", value="IT Support Analyst", key="hd_note_actor")
                    note_text = st.text_input("Work Note", placeholder="Document diagnostic step or user follow-up")
                    if st.form_submit_button("Append Work Note"):
                        try:
                            add_ticket_comment(ticket.ticket_id, actor=note_actor, note=note_text)
                            st.success("Activity note recorded.")
                            st.rerun()
                        except (ValidationError, RecordNotFoundError, DatabaseError) as exc:
                            st.error(str(exc))

            with col_del:
                render_section_title("Delete Ticket")
                confirm_del = st.checkbox(
                    f"Confirm permanent deletion of {ticket.ticket_id}",
                    key="hd_confirm_delete_ticket",
                )
                if st.button("Delete Selected Ticket", disabled=not confirm_del):
                    try:
                        delete_ticket(ticket.ticket_id)
                        st.success(f"Deleted `{ticket.ticket_id}`.")
                        st.rerun()
                    except (RecordNotFoundError, DatabaseError) as exc:
                        st.error(str(exc))

            render_section_title("Ticket Activity History")
            activities = get_ticket_activities(ticket.ticket_id)
            if activities:
                act_rows = [
                    {
                        "Timestamp": a.created_at,
                        "Actor": a.actor,
                        "Action": a.action,
                        "Details": a.details,
                    }
                    for a in activities
                ]
                st.dataframe(pd.DataFrame(act_rows), width="stretch", hide_index=True)

    with tab_summary:
        if summary.total > 0:
            st.plotly_chart(
                build_count_bar_chart("Tickets by Category", summary.by_category, color="#3B82F6"),
                width="stretch",
                config=PLOTLY_CONFIG,
            )
        else:
            st.info("No ticket records yet to chart.")

        render_section_title("Fictional Demonstration Data (Optional)")
        st.caption(
            "Demonstration tickets use clearly labeled fictional financial-services names and `[DEMO]` prefixes. "
            "Loading demo data never overwrites existing records."
        )
        d1, d2 = st.columns(2)
        with d1:
            if st.button("Load Fictional Demo Tickets", width="stretch"):
                added = load_demo_tickets()
                st.success(f"Inserted {added} fictional demo ticket(s).")
                st.rerun()
        with d2:
            confirm_clear_demo = st.checkbox("Confirm clearing [DEMO] tickets only", key="hd_confirm_clear_demo")
            if st.button("Clear Demo Tickets", disabled=not confirm_clear_demo, width="stretch"):
                removed = clear_demo_tickets()
                st.success(f"Removed {removed} demo ticket(s).")
                st.rerun()
