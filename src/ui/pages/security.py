"""Information Security dedicated page (read-only baseline assessment)."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from src.config.settings import UNAVAILABLE_VALUE, UNKNOWN_VALUE
from src.services.security_posture import collect_security_snapshot
from src.ui.components import (
    render_kpi_card,
    render_page_header,
    render_recommendation_card,
    render_section_title,
    render_warnings_banner,
)


def render() -> None:
    """Render the read-only Information Security assessment page."""
    render_page_header(
        title="Information Security",
        subtitle="Read-only Windows Firewall, Antivirus/Defender, Update/HotFix, UAC, and BitLocker baseline checks.",
        badge_text="Implemented",
    )

    col_meta, col_btn = st.columns([4, 1])
    with col_btn:
        if st.button("Re-run Security Checks", width="stretch"):
            st.rerun()

    snapshot = collect_security_snapshot(include_hotfixes=True)
    with col_meta:
        st.caption(f"Assessment Timestamp: `{snapshot.collected_at}` | Mode: Read-Only Standard User")

    st.info(snapshot.disclaimer)
    render_warnings_banner(snapshot.warnings)

    # Top KPI cards
    enabled_fw = sum(1 for p in snapshot.firewall_profiles if p.enabled is True)
    total_fw = len(snapshot.firewall_profiles)
    if total_fw == 0:
        fw_value, fw_status = UNKNOWN_VALUE, "Warning"
    elif enabled_fw == total_fw:
        fw_value, fw_status = f"{enabled_fw} / {total_fw} On", "Healthy"
    elif enabled_fw == 0:
        fw_value, fw_status = f"0 / {total_fw} On", "Critical"
    else:
        fw_value, fw_status = f"{enabled_fw} / {total_fw} On", "Warning"

    any_reg_av_on = any(av.enabled_state == "Enabled" for av in snapshot.registered_antivirus)
    if snapshot.defender.real_time_protection_enabled is True or any_reg_av_on:
        av_value = "Active"
        av_status = "Healthy"
    elif snapshot.defender.available and snapshot.defender.real_time_protection_enabled is False:
        av_value = "Disabled"
        av_status = "Critical"
    else:
        av_value = UNKNOWN_VALUE
        av_status = "Warning"

    av_detail = (
        f"Defender Sig: {snapshot.defender.signature_version}"
        if snapshot.defender.available
        else f"Registered AVs: {len(snapshot.registered_antivirus)}"
    )

    bl_value = f"{len(snapshot.bitlocker_volumes)} Vol(s)" if snapshot.bitlocker_volumes else UNAVAILABLE_VALUE
    bl_status = "Healthy" if snapshot.bitlocker_volumes and all(
        v.protection_status.lower() == "on" for v in snapshot.bitlocker_volumes
    ) else ("Critical" if any(v.protection_status.lower() == "off" for v in snapshot.bitlocker_volumes) else UNAVAILABLE_VALUE)

    k1, k2, k3, k4 = st.columns(4)
    with k1:
        render_kpi_card("Windows Firewall", fw_value, "Domain, Private & Public profiles", status=fw_status)
    with k2:
        render_kpi_card("Real-Time AV", av_value, av_detail, status=av_status)
    with k3:
        uac_val = "Enabled" if snapshot.uac.enable_lua == 1 else ("Disabled" if snapshot.uac.enable_lua == 0 else UNAVAILABLE_VALUE)
        render_kpi_card("UAC Policy", uac_val, snapshot.uac.policy_summary, status=snapshot.uac.status)
    with k4:
        render_kpi_card("BitLocker Status", bl_value, snapshot.bitlocker_status_note, status=bl_status)

    st.write("")

    tab_findings, tab_fw_av, tab_updates, tab_uac_bl = st.tabs(
        [
            "Findings & Recommendations",
            "Firewall & Antivirus",
            "Windows Updates / HotFixes",
            "UAC & BitLocker",
        ]
    )

    with tab_findings:
        render_section_title("Rule-Based Security Observations")
        for finding in snapshot.findings:
            render_recommendation_card(
                severity=finding.severity,
                category=finding.category,
                title=finding.title,
                explanation=finding.explanation,
                steps=finding.recommendations,
            )

    with tab_fw_av:
        render_section_title("Windows Firewall Profiles")
        if snapshot.firewall_profiles:
            fw_rows = [
                {
                    "Profile": p.profile_name,
                    "Status": p.status_display,
                    "Default Inbound": p.default_inbound,
                    "Default Outbound": p.default_outbound,
                }
                for p in snapshot.firewall_profiles
            ]
            st.dataframe(pd.DataFrame(fw_rows), width="stretch", hide_index=True)
        else:
            st.info("Windows Firewall profile telemetry is unavailable.")

        col_def, col_sc = st.columns(2)
        with col_def:
            render_section_title("Microsoft Defender Status")
            d = snapshot.defender
            if d.available:
                def_rows = [
                    {"Check": "AM Service Enabled", "Value": str(d.am_service_enabled) if d.am_service_enabled is not None else UNKNOWN_VALUE},
                    {"Check": "Antivirus Enabled", "Value": str(d.antivirus_enabled) if d.antivirus_enabled is not None else UNKNOWN_VALUE},
                    {"Check": "Real-Time Protection", "Value": str(d.real_time_protection_enabled) if d.real_time_protection_enabled is not None else UNKNOWN_VALUE},
                    {"Check": "Antispyware Enabled", "Value": str(d.antispyware_enabled) if d.antispyware_enabled is not None else UNKNOWN_VALUE},
                    {"Check": "Signature Version", "Value": d.signature_version},
                    {"Check": "Signatures Updated", "Value": d.signature_last_updated},
                    {"Check": "Last Quick Scan", "Value": d.quick_scan_end_time},
                ]
                st.dataframe(pd.DataFrame(def_rows), width="stretch", hide_index=True)
            else:
                st.info("Microsoft Defender status is unavailable.")

        with col_sc:
            render_section_title("Registered Antivirus (SecurityCenter2)")
            if snapshot.registered_antivirus:
                av_rows = [
                    {
                        "Product": av.display_name,
                        "State": av.enabled_state,
                        "Signatures": av.signature_state,
                        "Raw State": av.raw_state_hex,
                        "Timestamp": av.timestamp,
                    }
                    for av in snapshot.registered_antivirus
                ]
                st.dataframe(pd.DataFrame(av_rows), width="stretch", hide_index=True)
            else:
                st.info("No registered antivirus entries returned by SecurityCenter2.")

    with tab_updates:
        render_section_title("Installed Windows HotFixes")
        hf_search = st.text_input("Filter hotfixes by KB ID or description", placeholder="e.g., KB50, Security")
        filtered_hf = [
            hf
            for hf in snapshot.hotfixes
            if not hf_search
            or hf_search.lower() in hf.hotfix_id.lower()
            or hf_search.lower() in hf.description.lower()
        ]
        st.caption(f"Showing **{len(filtered_hf)}** of **{len(snapshot.hotfixes)}** retrieved hotfix records.")
        if filtered_hf:
            hf_rows = [
                {
                    "HotFix ID": hf.hotfix_id,
                    "Description": hf.description,
                    "Installed On": hf.installed_on,
                    "Installed By": hf.installed_by,
                }
                for hf in filtered_hf
            ]
            st.dataframe(pd.DataFrame(hf_rows), width="stretch", hide_index=True)
        else:
            st.info("No matching Windows Update/HotFix records available.")

    with tab_uac_bl:
        col_uac, col_bl = st.columns(2)
        with col_uac:
            render_section_title("User Account Control (UAC)")
            uac = snapshot.uac
            if uac.available:
                uac_rows = [
                    {"Policy Key": "EnableLUA", "Value": str(uac.enable_lua) if uac.enable_lua is not None else UNKNOWN_VALUE},
                    {"Policy Key": "ConsentPromptBehaviorAdmin", "Value": str(uac.consent_prompt_admin) if uac.consent_prompt_admin is not None else UNKNOWN_VALUE},
                    {"Policy Key": "PromptOnSecureDesktop", "Value": str(uac.prompt_on_secure_desktop) if uac.prompt_on_secure_desktop is not None else UNKNOWN_VALUE},
                    {"Policy Key": "Assessment", "Value": uac.policy_summary},
                ]
                st.dataframe(pd.DataFrame(uac_rows), width="stretch", hide_index=True)
            else:
                st.info("UAC policy keys are unavailable.")

        with col_bl:
            render_section_title("BitLocker Drive Encryption")
            if snapshot.bitlocker_volumes:
                bl_rows = [
                    {
                        "Volume": v.mount_point,
                        "Protection Status": v.protection_status,
                        "Volume Status": v.volume_status,
                        "Encrypted": v.encryption_percentage,
                    }
                    for v in snapshot.bitlocker_volumes
                ]
                st.dataframe(pd.DataFrame(bl_rows), width="stretch", hide_index=True)
            else:
                st.info(snapshot.bitlocker_status_note)
