"""Hardware Diagnostics dedicated page."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from src.config.settings import UNKNOWN_VALUE
from src.services.hardware_diagnostics import collect_hardware_snapshot
from src.ui.components import (
    PLOTLY_CONFIG,
    build_disk_usage_chart,
    build_per_core_chart,
    render_kpi_card,
    render_page_header,
    render_section_title,
    render_warnings_banner,
)
from src.utils.formatting import format_bytes


def render() -> None:
    """Render the Hardware Diagnostics page."""
    render_page_header(
        title="Hardware Diagnostics",
        subtitle="Processor, memory DIMMs, logical/physical storage, battery, and BIOS telemetry.",
        badge_text="Implemented",
    )

    col_info, col_refresh = st.columns([4, 1])
    with col_refresh:
        if st.button("Refresh Hardware", width="stretch"):
            st.rerun()

    snapshot = collect_hardware_snapshot()
    with col_info:
        st.caption(f"Host: `{snapshot.system_specs.hostname}` | Collected: `{snapshot.collected_at}`")

    render_warnings_banner(snapshot.warnings)

    tab_cpu, tab_mem, tab_disk, tab_power = st.tabs(
        ["CPU & Processor", "Memory (RAM)", "Storage & Disks", "Battery & System Specs"]
    )

    with tab_cpu:
        cpu = snapshot.cpu
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            render_kpi_card(
                "Overall CPU Usage",
                f"{cpu.usage_percent:.1f}%" if cpu.usage_percent is not None else UNKNOWN_VALUE,
                "Live sampled utilization",
                status=cpu.status,
            )
        with c2:
            render_kpi_card(
                "Cores / Threads",
                f"{cpu.physical_cores or UNKNOWN_VALUE}C / {cpu.logical_cores or UNKNOWN_VALUE}T",
                f"Architecture: {cpu.architecture}",
            )
        with c3:
            render_kpi_card(
                "Current Clock",
                f"{cpu.current_freq_mhz:.0f} MHz" if cpu.current_freq_mhz else UNKNOWN_VALUE,
                f"Max: {cpu.max_freq_mhz:.0f} MHz" if cpu.max_freq_mhz else "Max clock unknown",
            )
        with c4:
            l3 = f"{cpu.l3_cache_kb} KB" if cpu.l3_cache_kb is not None else UNKNOWN_VALUE
            render_kpi_card("L3 Cache", l3, f"Socket: {cpu.socket_designation}")

        st.write("")
        if cpu.per_core_percent:
            st.plotly_chart(
                build_per_core_chart(cpu.per_core_percent),
                width="stretch",
                config=PLOTLY_CONFIG,
            )
        else:
            st.info("Per-core utilization telemetry is unavailable.")

        render_section_title("Processor Specifications")
        cpu_specs = [
            {"Attribute": "Processor Name", "Value": cpu.processor_name},
            {"Attribute": "Manufacturer", "Value": cpu.manufacturer},
            {"Attribute": "Architecture", "Value": cpu.architecture},
            {"Attribute": "L2 Cache", "Value": f"{cpu.l2_cache_kb} KB" if cpu.l2_cache_kb is not None else UNKNOWN_VALUE},
            {"Attribute": "L3 Cache", "Value": f"{cpu.l3_cache_kb} KB" if cpu.l3_cache_kb is not None else UNKNOWN_VALUE},
            {"Attribute": "Socket", "Value": cpu.socket_designation},
        ]
        st.dataframe(pd.DataFrame(cpu_specs), width="stretch", hide_index=True)

    with tab_mem:
        mem = snapshot.memory
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            render_kpi_card(
                "RAM Utilization",
                f"{mem.percent_used:.1f}%" if mem.percent_used is not None else UNKNOWN_VALUE,
                "Virtual memory load",
                status=mem.status,
            )
        with m2:
            render_kpi_card("Total RAM", format_bytes(mem.total_bytes), "Installed capacity")
        with m3:
            render_kpi_card("Available RAM", format_bytes(mem.available_bytes), f"Used: {format_bytes(mem.used_bytes)}")
        with m4:
            swap_val = f"{mem.swap_percent:.1f}%" if mem.swap_percent is not None else UNKNOWN_VALUE
            render_kpi_card(
                "Pagefile / Swap",
                swap_val,
                f"{format_bytes(mem.swap_used_bytes)} / {format_bytes(mem.swap_total_bytes)}",
            )

        render_section_title("Physical Memory Modules (CIM)")
        if mem.modules:
            mod_rows = [
                {
                    "Slot": mod.slot,
                    "Capacity": mod.capacity_display,
                    "Type": mod.memory_type,
                    "Speed (MHz)": str(mod.speed_mhz) if mod.speed_mhz is not None else UNKNOWN_VALUE,
                    "Manufacturer": mod.manufacturer,
                    "Part Number": mod.part_number,
                }
                for mod in mem.modules
            ]
            st.dataframe(pd.DataFrame(mod_rows), width="stretch", hide_index=True)
        else:
            st.info("Physical DIMM slot details are unavailable on this host or virtualization layer.")

    with tab_disk:
        render_section_title("Logical Volumes")
        if snapshot.logical_disks:
            st.plotly_chart(
                build_disk_usage_chart(snapshot.logical_disks),
                width="stretch",
                config=PLOTLY_CONFIG,
            )
            disk_rows = [
                {
                    "Device": d.device,
                    "Mount": d.mountpoint,
                    "Filesystem": d.fstype,
                    "Total": format_bytes(d.total_bytes),
                    "Used": format_bytes(d.used_bytes),
                    "Free": format_bytes(d.free_bytes),
                    "Used %": f"{d.percent_used:.1f}%" if d.percent_used is not None else UNKNOWN_VALUE,
                    "Status": d.status,
                }
                for d in snapshot.logical_disks
            ]
            st.dataframe(pd.DataFrame(disk_rows), width="stretch", hide_index=True)
        else:
            st.info("No accessible logical partitions found.")

        render_section_title("Physical Storage Drives (CIM)")
        if snapshot.physical_disks:
            phys_rows = [
                {
                    "Model": p.model,
                    "Interface": p.interface_type,
                    "Media Type": p.media_type,
                    "Capacity": p.size_display,
                    "Serial Number": p.serial_number,
                    "Status": p.status,
                }
                for p in snapshot.physical_disks
            ]
            st.dataframe(pd.DataFrame(phys_rows), width="stretch", hide_index=True)
        else:
            st.info("Physical drive CIM inventory is unavailable.")

    with tab_power:
        bat = snapshot.battery
        b1, b2, b3 = st.columns(3)
        with b1:
            render_kpi_card(
                "Battery Charge",
                f"{bat.percent:.0f}%" if bat.present and bat.percent is not None else "Unavailable",
                "Workstation battery sensor" if bat.present else "No battery detected (desktop/VM)",
                status=bat.status,
            )
        with b2:
            plugged_str = (
                "AC Connected"
                if bat.power_plugged is True
                else ("On Battery" if bat.power_plugged is False else "Unavailable")
            )
            render_kpi_card("Power Source", plugged_str, "Charging / power state")
        with b3:
            render_kpi_card("Remaining Runtime", bat.time_left_display, "Estimated battery time")

        render_section_title("System, BIOS & Motherboard Specifications")
        specs = snapshot.system_specs
        spec_rows = [
            {"Component": "Hostname", "Detail": specs.hostname},
            {"Component": "System Manufacturer", "Detail": specs.manufacturer},
            {"Component": "System Model", "Detail": specs.model},
            {"Component": "System Type", "Detail": specs.system_type},
            {"Component": "Serial Number", "Detail": specs.serial_number},
            {"Component": "BIOS Vendor", "Detail": specs.bios_vendor},
            {"Component": "BIOS Version", "Detail": specs.bios_version},
            {"Component": "BIOS Release Date", "Detail": specs.bios_release_date},
            {"Component": "Baseboard Manufacturer", "Detail": specs.baseboard_manufacturer},
            {"Component": "Baseboard Product", "Detail": specs.baseboard_product},
        ]
        st.dataframe(pd.DataFrame(spec_rows), width="stretch", hide_index=True)
