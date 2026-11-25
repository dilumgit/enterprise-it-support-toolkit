"""Technical Reporting page for CSV and self-contained HTML exports."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from src.services.network_diagnostics import collect_network_snapshot, run_connectivity_check
from src.services.reporting_service import REPORT_TYPES, TechnicalReport, generate_report
from src.services.troubleshooting_engine import SEVERITY_LEVELS
from src.ui.components import render_kpi_card, render_page_header, render_section_title


def render() -> None:
    """Render the Technical Reporting page."""
    render_page_header(
        title="Technical Reporting",
        subtitle="Generate audit-ready CSV and self-contained HTML reports with optional privacy redaction.",
        badge_text="Implemented",
    )

    label_to_key = {label: key for key, label in REPORT_TYPES}
    c_type, c_priv, c_probe, c_btn = st.columns([2, 1.4, 1.4, 1.1])
    with c_type:
        selected_label = st.selectbox("Select Report Type", options=list(label_to_key.keys()), key="rpt_type_select")
        report_key = label_to_key[selected_label]
    with c_priv:
        st.write("")
        privacy_redacted = st.checkbox(
            "Privacy-Safe Redaction",
            value=True,
            help="Redacts usernames, hostnames, IP/MAC addresses, serial numbers, and employee names.",
            key="rpt_privacy_toggle",
        )
    with c_probe:
        st.write("")
        include_probe = st.checkbox(
            "Run active Connectivity Check",
            value=False,
            disabled=(report_key not in {"network", "comprehensive"}),
            key="rpt_active_probe",
        )
    with c_btn:
        st.write("")
        gen_clicked = st.button("Generate Report", type="primary", width="stretch")

    if gen_clicked:
        conn_res = st.session_state.get("network_connectivity_result")
        with st.spinner(f"Compiling {selected_label}..."):
            if include_probe and report_key in {"network", "comprehensive"}:
                net_snap = collect_network_snapshot()
                conn_res = run_connectivity_check(
                    adapters=net_snap.adapters,
                    default_gateways=net_snap.default_gateways,
                )
                st.session_state["network_connectivity_result"] = conn_res

            report = generate_report(
                report_key,
                privacy_redacted=privacy_redacted,
                connectivity_result=conn_res,
            )
            st.session_state["generated_report"] = report

    report: TechnicalReport | None = st.session_state.get("generated_report")
    if report is None:
        st.info("Select a report type and click **Generate Report** to preview and download CSV or HTML outputs.")
        return

    st.caption(
        f"Report ID: `{report.report_id}` | Generated: `{report.generated_at}` | "
        f"Privacy Mode: `{'Redacted' if report.privacy_redacted else 'Standard'}`"
    )
    st.markdown(f"**Executive Summary:** {report.executive_summary}")

    dl1, dl2 = st.columns(2)
    with dl1:
        st.download_button(
            label="Download CSV Report",
            data=report.csv_content,
            file_name=f"{report.report_key}_{report.report_id}.csv",
            mime="text/csv",
            width="stretch",
        )
    with dl2:
        st.download_button(
            label="Download Self-Contained HTML Report",
            data=report.html_content,
            file_name=f"{report.report_key}_{report.report_id}.html",
            mime="text/html",
            width="stretch",
        )

    if report.findings:
        st.write("")
        cols = st.columns(5)
        for idx, sev in enumerate(SEVERITY_LEVELS):
            with cols[idx]:
                count = report.severity_breakdown.get(sev, 0)
                render_kpi_card(sev, str(count), "Findings", status=sev if count > 0 else "Healthy")

        with st.expander(f"Diagnostic Findings ({len(report.findings)})", expanded=False):
            finding_rows = [
                {
                    "Finding ID": f.finding_id,
                    "Category": f.category,
                    "Severity": f.severity,
                    "Title": f.title,
                    "Confirmed Evidence": " | ".join(f.confirmed_evidence),
                }
                for f in report.findings
            ]
            st.dataframe(pd.DataFrame(finding_rows), width="stretch", hide_index=True)

    for sec in report.sections:
        render_section_title(sec.title)
        if sec.rows:
            st.dataframe(pd.DataFrame(sec.rows), width="stretch", hide_index=True)
        else:
            st.info("No records available for this section.")

    if report.recommended_actions:
        render_section_title("Recommended Actions")
        for idx, act in enumerate(report.recommended_actions, start=1):
            st.markdown(f"{idx}. {act}")

    if report.limitations:
        render_section_title("Limitations & Unavailable Checks")
        for lim in report.limitations:
            st.caption(f"- {lim}")
