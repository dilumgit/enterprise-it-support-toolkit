"""Intelligent Rule-Based Troubleshooting Assistant page."""

from __future__ import annotations

import html

import streamlit as st

from src.database.db import DatabaseError, DuplicateRecordError, ValidationError
from src.services.network_diagnostics import collect_network_snapshot, run_connectivity_check
from src.services.troubleshooting_engine import (
    ASSESSMENT_CATEGORIES,
    SEVERITY_LEVELS,
    TroubleshootingAssessment,
    create_ticket_from_finding,
    run_troubleshooting_assessment,
)
from src.ui.components import render_kpi_card, render_page_header, render_section_title
from src.ui.styles import status_badge_html


def render() -> None:
    """Render the Intelligent Rule-Based Troubleshooting Assistant page."""
    render_page_header(
        title="Troubleshooting Assistant",
        subtitle="Cross-module, read-only rule engine correlating Hardware, System, Network, and Security telemetry.",
        badge_text="Implemented",
    )

    st.caption(
        "Read-Only Guarantee: This assistant evaluates live observations and separates confirmed evidence from "
        "suspected root causes. It never modifies system settings or automatically repairs issues."
    )

    c_mode, c_cat, c_probe, c_btn = st.columns([1.4, 1.5, 1.8, 1.1])
    with c_mode:
        scope_mode = st.radio(
            "Assessment Scope",
            options=["Full Endpoint Assessment", "Single Category"],
            horizontal=True,
            key="trb_scope_mode",
        )
    with c_cat:
        selected_cat = st.selectbox(
            "Category",
            options=ASSESSMENT_CATEGORIES,
            disabled=(scope_mode == "Full Endpoint Assessment"),
            key="trb_single_cat",
        )
    with c_probe:
        st.write("")
        include_active_probe = st.checkbox(
            "Run active Internet Connectivity Check (opt-in)",
            value=False,
            key="trb_active_probe",
        )
    with c_btn:
        st.write("")
        run_clicked = st.button("Run Assessment", type="primary", width="stretch")

    if run_clicked:
        cats = ASSESSMENT_CATEGORIES if scope_mode == "Full Endpoint Assessment" else (selected_cat,)
        ping_res = st.session_state.get("network_ping_result")
        dns_res = st.session_state.get("network_dns_result")
        conn_res = st.session_state.get("network_connectivity_result")

        with st.spinner("Evaluating diagnostic rules across selected modules..."):
            if include_active_probe and ("Network" in cats):
                net_snap = collect_network_snapshot()
                conn_res = run_connectivity_check(
                    adapters=net_snap.adapters,
                    default_gateways=net_snap.default_gateways,
                )
                st.session_state["network_connectivity_result"] = conn_res

            assessment = run_troubleshooting_assessment(
                categories=cats,
                ping_result=ping_res,
                dns_result=dns_res,
                connectivity_result=conn_res,
            )
            st.session_state["trb_assessment"] = assessment

    assessment: TroubleshootingAssessment | None = st.session_state.get("trb_assessment")
    if assessment is None:
        st.info("Click **Run Assessment** to evaluate current endpoint telemetry without altering system settings.")
        return

    st.caption(
        f"Assessed At: `{assessment.assessed_at}` | Categories: `{', '.join(assessment.categories_evaluated)}` "
        f"| Total Findings: **{len(assessment.findings)}**"
    )

    # Severity summary cards
    cols = st.columns(5)
    for idx, sev in enumerate(SEVERITY_LEVELS):
        with cols[idx]:
            count = assessment.severity_counts.get(sev, 0)
            render_kpi_card(
                label=sev,
                value=str(count),
                detail="Findings",
                status=sev if count > 0 else "Healthy",
            )

    if assessment.limitations:
        with st.expander(f"Evidence Scope & Limitations ({len(assessment.limitations)})", expanded=False):
            for lim in assessment.limitations:
                st.caption(f"- {lim}")

    st.write("")

    # Filters
    f1, f2 = st.columns(2)
    available_cats = sorted({f.category for f in assessment.findings})
    with f1:
        cat_filter = st.multiselect("Filter by Category", options=available_cats, default=available_cats)
    with f2:
        sev_filter = st.multiselect("Filter by Severity", options=list(SEVERITY_LEVELS), default=list(SEVERITY_LEVELS))

    filtered = [
        f
        for f in assessment.findings
        if f.category in cat_filter and f.severity in sev_filter
    ]

    render_section_title(f"Diagnostic Findings ({len(filtered)})")
    if not filtered:
        st.info("No findings match the selected category and severity filters.")
    else:
        for finding in filtered:
            with st.expander(f"[{finding.severity}] [{finding.finding_id}] {finding.title}", expanded=(finding.severity in {"Critical", "High"})):
                st.html(
                    f'<div style="margin-bottom:0.5rem;font-size:0.86rem;color:#CBD5E1;overflow-wrap:anywhere;">'
                    f"{status_badge_html(finding.severity)} &nbsp; "
                    f"<strong>Category:</strong> {html.escape(finding.category)} &nbsp;|&nbsp; "
                    f"<strong>Confidence / Limitations:</strong> {html.escape(finding.confidence_and_limitations)}"
                    f"</div>"
                )
                col_ev, col_rc = st.columns(2)
                with col_ev:
                    st.markdown("**Confirmed Diagnostic Evidence**")
                    for item in finding.confirmed_evidence:
                        st.markdown(f"- {item}")
                with col_rc:
                    st.markdown("**Suspected Root Causes**")
                    for item in finding.suspected_root_causes:
                        st.markdown(f"- {item}")

                col_rec, col_ver = st.columns(2)
                with col_rec:
                    st.markdown("**Recommended Troubleshooting Steps**")
                    for idx_step, step in enumerate(finding.recommended_steps, start=1):
                        st.markdown(f"{idx_step}. {step}")
                with col_ver:
                    st.markdown("**Post-Action Verification Steps**")
                    for step in finding.verification_steps:
                        st.markdown(f"- {step}")

                st.caption(f"**Escalation Guidance:** {finding.escalation_guidance}")

        st.divider()
        render_section_title("Create IT Help Desk Incident from Finding")
        finding_options = {f"{f.finding_id} — {f.title} [{f.severity}]": f for f in filtered}
        chosen_lbl = st.selectbox("Select Finding to Escalate", options=list(finding_options.keys()), key="trb_ticket_select")
        chosen = finding_options[chosen_lbl]

        with st.expander("Preview Incident Details Before Creation", expanded=True):
            st.write(
                {
                    "Proposed Title": f"[{chosen.finding_id}] {chosen.title}",
                    "Ticket Type": "Incident",
                    "Category": chosen.helpdesk_category,
                    "Priority": chosen.helpdesk_priority,
                    "Confirmed Evidence": chosen.confirmed_evidence,
                }
            )

        with st.form("trb_create_ticket_form"):
            t1, t2, t3 = st.columns(3)
            with t1:
                req_name = st.text_input("Requester Name *", placeholder="e.g., Alex Morgan")
            with t2:
                dept = st.text_input("Department *", placeholder="e.g., Treasury Operations")
            with t3:
                tech = st.text_input("Assigned Technician", value="Tier 1 Support")
            extra_notes = st.text_area("Additional Analyst Context (Optional)")
            confirm_ticket = st.checkbox("I confirm creating a persisted Help Desk incident from this diagnostic finding.")
            if st.form_submit_button("Confirm & Create Incident", type="primary"):
                if not confirm_ticket:
                    st.warning("Please check the confirmation box before creating an incident.")
                else:
                    try:
                        created = create_ticket_from_finding(
                            chosen,
                            requester_name=req_name,
                            department=dept,
                            assigned_technician=tech,
                            additional_notes=extra_notes,
                        )
                        st.success(f"Incident `{created.ticket_id}` created in IT Help Desk.")
                    except (ValidationError, DuplicateRecordError, DatabaseError) as exc:
                        st.error(str(exc))
