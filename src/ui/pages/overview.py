"""Overview Dashboard page showing live endpoint metrics and module status."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from src.config.settings import (
    CPU_CRITICAL_THRESHOLD,
    CPU_WARNING_THRESHOLD,
    NAVIGATION_ITEMS,
    RAM_CRITICAL_THRESHOLD,
    RAM_WARNING_THRESHOLD,
    UNKNOWN_VALUE,
)
from src.services.asset_service import get_asset_summary
from src.services.hardware_diagnostics import collect_hardware_snapshot
from src.services.helpdesk_service import get_ticket_summary
from src.services.network_diagnostics import collect_network_snapshot
from src.services.security_posture import collect_security_snapshot
from src.services.system_info import get_os_info
from src.ui.components import (
    PLOTLY_CONFIG,
    build_disk_usage_chart,
    build_utilization_gauge,
    render_kpi_card,
    render_page_header,
    render_section_title,
    render_warnings_banner,
)
from src.utils.formatting import format_bytes


def render() -> None:
    """Render the Overview Dashboard using live local telemetry."""
    render_page_header(
        title="Enterprise Endpoint Overview",
        subtitle="Real-time, read-only local workstation diagnostics and infrastructure readiness.",
        badge_text="Implemented",
    )

    col_meta, col_btn = st.columns([4, 1])
    with col_btn:
        if st.button("Refresh Telemetry", width="stretch"):
            st.rerun()

    hw = collect_hardware_snapshot()
    os_warnings: list[str] = []
    os_info = get_os_info(warnings=os_warnings)
    net = collect_network_snapshot()
    sec = collect_security_snapshot(include_hotfixes=False)
    all_warnings = hw.warnings + os_warnings + net.warnings + sec.warnings

    with col_meta:
        st.caption(
            f"Host: `{os_info.hostname}` | User: `{os_info.user_domain}\\{os_info.current_user}` "
            f"| Snapshot: `{hw.collected_at}` | Mode: Read-Only"
        )

    render_warnings_banner(all_warnings)

    # Top KPI cards
    primary_disk = hw.logical_disks[0] if hw.logical_disks else None
    cpu_val = f"{hw.cpu.usage_percent:.1f}%" if hw.cpu.usage_percent is not None else UNKNOWN_VALUE
    ram_val = f"{hw.memory.percent_used:.1f}%" if hw.memory.percent_used is not None else UNKNOWN_VALUE
    disk_val = (
        f"{primary_disk.percent_used:.1f}%"
        if primary_disk and primary_disk.percent_used is not None
        else UNKNOWN_VALUE
    )
    disk_detail = (
        f"{primary_disk.mountpoint} {format_bytes(primary_disk.free_bytes)} free of "
        f"{format_bytes(primary_disk.total_bytes)}"
        if primary_disk
        else "No accessible disk volumes"
    )

    k1, k2, k3, k4 = st.columns(4)
    with k1:
        render_kpi_card(
            label="CPU Utilization",
            value=cpu_val,
            detail=f"{hw.cpu.logical_cores or UNKNOWN_VALUE} logical cores | {hw.cpu.architecture}",
            status=hw.cpu.status,
        )
    with k2:
        render_kpi_card(
            label="Memory Utilization",
            value=ram_val,
            detail=f"{format_bytes(hw.memory.used_bytes)} / {format_bytes(hw.memory.total_bytes)}",
            status=hw.memory.status,
        )
    with k3:
        render_kpi_card(
            label="Primary Storage",
            value=disk_val,
            detail=disk_detail,
            status=primary_disk.status if primary_disk else UNKNOWN_VALUE,
        )
    with k4:
        render_kpi_card(
            label="System Uptime",
            value=os_info.uptime_display,
            detail=f"Last boot: {os_info.boot_time_display}",
            status="Healthy" if os_info.uptime_seconds is not None else UNKNOWN_VALUE,
        )

    st.write("")

    # Charts Row
    c_left, c_mid, c_right = st.columns([1, 1, 1.4])
    with c_left:
        st.plotly_chart(
            build_utilization_gauge(
                "CPU Load",
                hw.cpu.usage_percent,
                CPU_WARNING_THRESHOLD,
                CPU_CRITICAL_THRESHOLD,
            ),
            width="stretch",
            config=PLOTLY_CONFIG,
        )
    with c_mid:
        st.plotly_chart(
            build_utilization_gauge(
                "RAM Usage",
                hw.memory.percent_used,
                RAM_WARNING_THRESHOLD,
                RAM_CRITICAL_THRESHOLD,
            ),
            width="stretch",
            config=PLOTLY_CONFIG,
        )
    with c_right:
        if hw.logical_disks:
            st.plotly_chart(
                build_disk_usage_chart(hw.logical_disks),
                width="stretch",
                config=PLOTLY_CONFIG,
            )
        else:
            st.info("No accessible logical disk volumes detected.")

    # Network & Security Posture Row (passive read-only summary)
    render_section_title("Network & Security Baseline Summary")
    up_adapters = [a for a in net.adapters if "loopback" not in a.name.lower() and a.status == "Up"]
    fw_enabled = sum(1 for p in sec.firewall_profiles if p.enabled is True)
    fw_total = len(sec.firewall_profiles)
    av_active = sec.defender.real_time_protection_enabled is True or any(
        av.enabled_state == "Enabled" for av in sec.registered_antivirus
    )

    ns1, ns2, ns3, ns4 = st.columns(4)
    with ns1:
        render_kpi_card(
            label="Network Adapters",
            value=f"{len(up_adapters)} Up",
            detail=f"Gateway: {net.default_gateways[0] if net.default_gateways else 'Unavailable'}",
            status="Healthy" if up_adapters else "Critical",
        )
    with ns2:
        wifi_val = (
            f"{net.wifi.signal_percent}%"
            if net.wifi.available and net.wifi.signal_percent is not None
            else (net.wifi.state if net.wifi.available else "Unavailable")
        )
        render_kpi_card(
            label="Wi-Fi Link",
            value=wifi_val,
            detail=net.wifi.ssid if net.wifi.available else "No wireless adapter",
            status=net.wifi.status,
        )
    with ns3:
        fw_val = f"{fw_enabled} / {fw_total} On" if fw_total else UNKNOWN_VALUE
        fw_status = "Healthy" if fw_total and fw_enabled == fw_total else ("Critical" if fw_total and fw_enabled == 0 else "Warning")
        render_kpi_card(
            label="Windows Firewall",
            value=fw_val,
            detail="Domain / Private / Public",
            status=fw_status,
        )
    with ns4:
        render_kpi_card(
            label="Antivirus Protection",
            value="Active" if av_active else ("Disabled" if sec.defender.available else UNKNOWN_VALUE),
            detail=f"UAC: {'Enabled' if sec.uac.enable_lua == 1 else ('Disabled' if sec.uac.enable_lua == 0 else UNKNOWN_VALUE)}",
            status="Healthy" if av_active else ("Critical" if sec.defender.available else "Warning"),
        )

    st.write("")

    # Service Desk & Asset Management Row (SQLite Persistence)
    render_section_title("Help Desk & Asset Management Summary")
    try:
        ticket_summary = get_ticket_summary()
        asset_summary = get_asset_summary()
        sd1, sd2, sd3, sd4 = st.columns(4)
        with sd1:
            render_kpi_card(
                label="Open Help Desk Tickets",
                value=str(ticket_summary.open_count + ticket_summary.in_progress_count),
                detail=f"Total: {ticket_summary.total} | Critical Active: {ticket_summary.critical_open_count}",
                status="Critical" if ticket_summary.critical_open_count > 0 else (
                    "Open" if ticket_summary.open_count > 0 else "Healthy"
                ),
            )
        with sd2:
            render_kpi_card(
                label="Resolved / Closed Tickets",
                value=f"{ticket_summary.resolved_count + ticket_summary.closed_count}",
                detail=f"Resolved: {ticket_summary.resolved_count} | Closed: {ticket_summary.closed_count}",
                status="Resolved",
            )
        with sd3:
            render_kpi_card(
                label="Managed IT Assets",
                value=str(asset_summary.total_assets),
                detail=f"Assigned: {asset_summary.assigned_count} | Available: {asset_summary.available_count}",
                status="Healthy" if asset_summary.maintenance_count == 0 else "Under Maintenance",
            )
        with sd4:
            render_kpi_card(
                label="Software Licenses",
                value=str(asset_summary.total_licenses),
                detail=f"Seats: {asset_summary.total_license_seats} | Software Links: {asset_summary.total_software_records}",
            )
    except Exception as exc:
        st.warning(f"Help Desk / Asset summary unavailable: {exc}")

    st.write("")

    # Troubleshooting & Technical Reporting Capabilities Summary
    render_section_title("Troubleshooting & Reporting Readiness")
    tr1, tr2, tr3 = st.columns(3)
    with tr1:
        render_kpi_card(
            label="Troubleshooting Engine",
            value="15 Scenarios",
            detail="Hardware, System, Network, Security & Cross-Module rules",
            status="Implemented",
        )
    with tr2:
        render_kpi_card(
            label="Technical Reporting",
            value="8 Report Types",
            detail="Self-contained HTML & CSV with privacy-safe redaction",
            status="Implemented",
        )
    with tr3:
        render_kpi_card(
            label="Toolkit Modules Active",
            value=f"{sum(1 for i in NAVIGATION_ITEMS if i.implemented)} / {len(NAVIGATION_ITEMS)}",
            detail="All core modules operational in read-only safe mode",
            status="Healthy",
        )

    st.write("")

    # System & Module Readiness Summary
    col_sys, col_mod = st.columns([1, 1.2])
    with col_sys:
        render_section_title("Endpoint Identity & Hardware Summary")
        summary_rows = [
            {"Property": "Hostname / FQDN", "Value": f"{os_info.hostname} ({os_info.fqdn})"},
            {"Property": "Operating System", "Value": f"{os_info.os_name} (Build {os_info.os_build})"},
            {"Property": "Manufacturer / Model", "Value": f"{hw.system_specs.manufacturer} {hw.system_specs.model}"},
            {"Property": "Processor", "Value": hw.cpu.processor_name},
            {"Property": "BIOS Version", "Value": f"{hw.system_specs.bios_vendor} {hw.system_specs.bios_version}"},
            {
                "Property": "Battery",
                "Value": (
                    f"{hw.battery.percent:.0f}% ({hw.battery.time_left_display})"
                    if hw.battery.present and hw.battery.percent is not None
                    else hw.battery.time_left_display
                ),
            },
        ]
        st.dataframe(pd.DataFrame(summary_rows), width="stretch", hide_index=True)

    with col_mod:
        render_section_title("Toolkit Module Delivery Status")
        module_rows = [
            {
                "Module": item.label,
                "Phase": item.phase,
                "Status": "Implemented" if item.implemented else "Planned",
                "Scope": item.summary,
            }
            for item in NAVIGATION_ITEMS
        ]
        st.dataframe(pd.DataFrame(module_rows), width="stretch", hide_index=True)
