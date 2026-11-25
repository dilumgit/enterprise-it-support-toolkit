"""System Administration & OS Information dedicated page."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from src.services.system_info import (
    SoftwareItem,
    get_installed_software,
    get_os_info,
    get_running_processes,
    get_windows_services,
    summarize_services,
)
from src.ui.components import (
    PLOTLY_CONFIG,
    build_top_memory_chart,
    render_kpi_card,
    render_page_header,
    render_section_title,
    render_warnings_banner,
)


@st.cache_data(ttl=120, show_spinner=False)
def _cached_software_inventory() -> tuple[list[SoftwareItem], list[str]]:
    """Cache registry software inventory briefly to keep filtering instantaneous."""
    warnings: list[str] = []
    items = get_installed_software(warnings=warnings)
    return items, warnings


def render() -> None:
    """Render the System Administration page."""
    render_page_header(
        title="System Administration",
        subtitle="Read-only OS telemetry, uptime, active processes, Windows services, and software inventory.",
        badge_text="Implemented",
    )

    col_caption, col_refresh = st.columns([4, 1])
    with col_refresh:
        if st.button("Refresh System Data", width="stretch"):
            _cached_software_inventory.clear()
            st.rerun()

    warnings: list[str] = []
    os_info = get_os_info(warnings=warnings)

    with col_caption:
        st.caption(
            f"Host: `{os_info.hostname}` | Context: `{os_info.user_domain}\\{os_info.current_user}` "
            "| Privilege Mode: Standard User Read-Only"
        )

    tab_os, tab_proc, tab_svc, tab_sw = st.tabs(
        ["OS & Uptime", "Running Processes", "Windows Services", "Installed Software"]
    )

    with tab_os:
        o1, o2, o3 = st.columns(3)
        with o1:
            render_kpi_card("Operating System", os_info.os_name, f"Version {os_info.os_version} (Build {os_info.os_build})")
        with o2:
            render_kpi_card("System Uptime", os_info.uptime_display, f"Last Boot: {os_info.boot_time_display}", status="Healthy")
        with o3:
            render_kpi_card("Active User", os_info.current_user, f"Domain / Host: {os_info.user_domain}")

        render_section_title("Operating System Metadata")
        os_rows = [
            {"Field": "OS Edition", "Value": os_info.os_name},
            {"Field": "Version", "Value": os_info.os_version},
            {"Field": "Build Number", "Value": os_info.os_build},
            {"Field": "OS Architecture", "Value": os_info.architecture},
            {"Field": "Hostname", "Value": os_info.hostname},
            {"Field": "FQDN", "Value": os_info.fqdn},
            {"Field": "OS Install Date", "Value": os_info.install_date},
            {"Field": "Registered Organization", "Value": os_info.registered_organization},
        ]
        st.dataframe(pd.DataFrame(os_rows), width="stretch", hide_index=True)

    with tab_proc:
        f1, f2, f3 = st.columns([2, 1, 1])
        with f1:
            proc_search = st.text_input("Filter processes by name or user", placeholder="e.g., python, chrome, svchost")
        with f2:
            sort_by = st.selectbox("Sort by", options=["memory_mb", "cpu_percent", "name", "pid"], index=0)
        with f3:
            proc_limit = st.selectbox("Max rows", options=[25, 40, 75, 150], index=1)

        total_procs, proc_list = get_running_processes(limit=250, sort_by=sort_by, warnings=warnings)
        filtered_procs = [
            p
            for p in proc_list
            if not proc_search
            or proc_search.lower() in p.name.lower()
            or proc_search.lower() in p.username.lower()
        ][:proc_limit]

        st.caption(f"Total active processes visible: **{total_procs}** | Showing: **{len(filtered_procs)}**")

        if filtered_procs:
            st.plotly_chart(
                build_top_memory_chart(filtered_procs, top_n=10),
                width="stretch",
                config=PLOTLY_CONFIG,
            )
            proc_rows = [
                {
                    "PID": p.pid,
                    "Process Name": p.name,
                    "User": p.username,
                    "Status": p.status,
                    "CPU %": p.cpu_percent,
                    "Memory (MB)": p.memory_mb,
                    "Memory %": p.memory_percent,
                }
                for p in filtered_procs
            ]
            st.dataframe(pd.DataFrame(proc_rows), width="stretch", hide_index=True)
        else:
            st.info("No processes matched the current filter.")

    with tab_svc:
        services = get_windows_services(warnings=warnings)
        summary = summarize_services(services)

        s1, s2, s3, s4 = st.columns(4)
        with s1:
            render_kpi_card("Total Services", str(summary["total"]), "Registered Windows services")
        with s2:
            render_kpi_card("Running", str(summary["running"]), "Active background services", status="Running")
        with s3:
            render_kpi_card("Stopped", str(summary["stopped"]), "Inactive services", status="Stopped")
        with s4:
            render_kpi_card("Automatic Start", str(summary["automatic"]), "Configured for boot start")

        st.write("")
        sf1, sf2 = st.columns([2, 1])
        with sf1:
            svc_search = st.text_input("Search Windows services", placeholder="e.g., WinDefend, Dhcp, Spooler")
        with sf2:
            svc_state = st.selectbox("Status filter", options=["All", "Running", "Stopped"], index=0)

        filtered_svcs = [
            svc
            for svc in services
            if (svc_state == "All" or svc.status.lower() == svc_state.lower())
            and (
                not svc_search
                or svc_search.lower() in svc.name.lower()
                or svc_search.lower() in svc.display_name.lower()
            )
        ]

        if filtered_svcs:
            svc_rows = [
                {
                    "Service Name": svc.name,
                    "Display Name": svc.display_name,
                    "Status": svc.status,
                    "Start Type": svc.start_type,
                    "Binary Path": svc.binpath,
                }
                for svc in filtered_svcs
            ]
            st.dataframe(pd.DataFrame(svc_rows), width="stretch", hide_index=True)
        else:
            st.info("No Windows services available or matched the filter.")

    with tab_sw:
        st.caption(
            "Software inventory is collected via read-only Windows Uninstall registry keys "
            "(avoiding Win32_Product MSI consistency triggers)."
        )
        sw_search = st.text_input("Search installed software or publisher", placeholder="e.g., Microsoft, Python, Git")
        software_items, sw_warnings = _cached_software_inventory()
        warnings.extend(sw_warnings)

        filtered_sw = [
            item
            for item in software_items
            if not sw_search
            or sw_search.lower() in item.name.lower()
            or sw_search.lower() in item.publisher.lower()
        ]
        st.caption(f"Total unique applications discovered: **{len(software_items)}** | Matching: **{len(filtered_sw)}**")

        if filtered_sw:
            sw_rows = [
                {
                    "Application": item.name,
                    "Version": item.version,
                    "Publisher": item.publisher,
                    "Install Date": item.install_date,
                    "Registry Hive": item.source,
                }
                for item in filtered_sw
            ]
            st.dataframe(pd.DataFrame(sw_rows), width="stretch", hide_index=True)
        else:
            st.info("No installed applications matched the filter or registry query was unavailable.")

    render_warnings_banner(warnings)
