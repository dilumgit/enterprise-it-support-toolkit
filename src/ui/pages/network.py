"""Network Diagnostics dedicated page."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from src.config.settings import UNAVAILABLE_VALUE, UNKNOWN_VALUE
from src.services.network_diagnostics import (
    collect_network_snapshot,
    generate_network_recommendations,
    resolve_dns,
    run_connectivity_check,
    run_ping,
    run_traceroute,
)
from src.ui.components import (
    PLOTLY_CONFIG,
    build_adapter_traffic_chart,
    render_kpi_card,
    render_page_header,
    render_recommendation_card,
    render_section_title,
    render_warnings_banner,
)
from src.utils.formatting import format_bytes


def render() -> None:
    """Render the Network Diagnostics page with passive config and user-triggered tests."""
    render_page_header(
        title="Network Diagnostics",
        subtitle="Interface configuration, routing, Wi-Fi telemetry, and user-triggered connectivity probes.",
        badge_text="Implemented",
    )

    col_meta, col_btn = st.columns([4, 1])
    with col_btn:
        if st.button("Refresh Interfaces", width="stretch"):
            st.rerun()

    snapshot = collect_network_snapshot()
    with col_meta:
        st.caption(
            f"Collected: `{snapshot.collected_at}` | Passive local telemetry "
            "(active probes run only when triggered below)"
        )

    render_warnings_banner(snapshot.warnings)

    non_loopback = [a for a in snapshot.adapters if "loopback" not in a.name.lower()]
    up_adapters = [a for a in non_loopback if a.status == "Up"]
    primary_adapter = up_adapters[0].name if up_adapters else "None Active"

    n1, n2, n3, n4 = st.columns(4)
    with n1:
        render_kpi_card(
            label="Active Adapters",
            value=f"{len(up_adapters)} / {len(non_loopback)}",
            detail=f"Primary: {primary_adapter}",
            status="Healthy" if up_adapters else "Critical",
        )
    with n2:
        gw_val = snapshot.default_gateways[0] if snapshot.default_gateways else UNAVAILABLE_VALUE
        dns_count = len(snapshot.dns_servers)
        render_kpi_card(
            label="Default Gateway",
            value=gw_val,
            detail=f"Configured DNS servers: {dns_count}",
            status="Healthy" if snapshot.default_gateways else "Warning",
        )
    with n3:
        wifi = snapshot.wifi
        wifi_val = (
            f"{wifi.signal_percent}%"
            if wifi.available and wifi.signal_percent is not None
            else (wifi.state if wifi.available else UNAVAILABLE_VALUE)
        )
        wifi_detail = (
            f"{wifi.ssid} ({wifi.band})" if wifi.available and wifi.state.lower() == "connected" else "No active Wi-Fi link"
        )
        render_kpi_card(
            label="Wi-Fi Signal",
            value=wifi_val,
            detail=wifi_detail,
            status=wifi.status,
        )
    with n4:
        render_kpi_card(
            label="Cumulative Traffic",
            value=format_bytes(snapshot.total_bytes_recv),
            detail=f"Sent: {format_bytes(snapshot.total_bytes_sent)}",
        )

    st.write("")

    tab_cfg, tab_wifi, tab_tools, tab_recs = st.tabs(
        [
            "Adapters & Routing",
            "Wi-Fi Details",
            "Connectivity & Probe Tools",
            "Troubleshooting Recommendations",
        ]
    )

    with tab_cfg:
        render_section_title("Network Adapters")
        if snapshot.adapters:
            adapter_rows = [
                {
                    "Adapter": a.name,
                    "Description": a.description,
                    "Status": a.status,
                    "Speed (Mbps)": str(a.speed_mbps) if a.speed_mbps is not None else UNKNOWN_VALUE,
                    "MAC Address": a.mac_address,
                    "IPv4 / Subnet": ", ".join(a.ipv4_addresses) if a.ipv4_addresses else UNAVAILABLE_VALUE,
                    "IPv6": ", ".join(a.ipv6_addresses) if a.ipv6_addresses else UNAVAILABLE_VALUE,
                    "Gateway": ", ".join(a.default_gateways) if a.default_gateways else UNAVAILABLE_VALUE,
                    "DNS Servers": ", ".join(a.dns_servers) if a.dns_servers else UNAVAILABLE_VALUE,
                    "Recv": format_bytes(a.bytes_recv),
                    "Sent": format_bytes(a.bytes_sent),
                    "Errors (In/Out)": f"{a.errin or 0} / {a.errout or 0}",
                }
                for a in snapshot.adapters
            ]
            st.dataframe(pd.DataFrame(adapter_rows), width="stretch", hide_index=True)

            if any((a.bytes_sent or 0) > 0 or (a.bytes_recv or 0) > 0 for a in snapshot.adapters):
                st.plotly_chart(
                    build_adapter_traffic_chart(snapshot.adapters),
                    width="stretch",
                    config=PLOTLY_CONFIG,
                )
        else:
            st.info("No network adapters detected.")

        render_section_title("System Routing & DNS Summary")
        c_gw, c_dns = st.columns(2)
        with c_gw:
            st.markdown("**Default Gateways**")
            st.write(", ".join(snapshot.default_gateways) if snapshot.default_gateways else UNAVAILABLE_VALUE)
        with c_dns:
            st.markdown("**Configured DNS Servers**")
            st.write(", ".join(snapshot.dns_servers) if snapshot.dns_servers else UNAVAILABLE_VALUE)

    with tab_wifi:
        render_section_title("Wireless Interface Telemetry")
        if wifi.available:
            wifi_rows = [
                {"Property": "Interface", "Value": wifi.interface_name},
                {"Property": "State", "Value": wifi.state},
                {"Property": "SSID", "Value": wifi.ssid},
                {"Property": "BSSID", "Value": wifi.bssid},
                {"Property": "Signal Strength", "Value": f"{wifi.signal_percent}%" if wifi.signal_percent is not None else UNKNOWN_VALUE},
                {"Property": "Band / Channel", "Value": f"{wifi.band} / Ch {wifi.channel}"},
                {"Property": "Radio Type", "Value": wifi.radio_type},
                {"Property": "Authentication / Cipher", "Value": f"{wifi.authentication} / {wifi.cipher}"},
                {"Property": "Receive / Transmit Rate", "Value": f"{wifi.receive_rate_mbps} / {wifi.transmit_rate_mbps} Mbps"},
            ]
            st.dataframe(pd.DataFrame(wifi_rows), width="stretch", hide_index=True)
        else:
            st.info("Wi-Fi interface telemetry is Unavailable (no wireless adapter detected or host is wired/VM).")

    with tab_tools:
        render_section_title("Gateway & Internet Connectivity Check")
        st.caption(
            "Tests active adapters, default gateway ICMP (if configured), DNS resolution, and outbound TCP/443 "
            "so blocked ICMP is distinguished from a true internet outage."
        )
        if st.button("Run Connectivity Check", key="btn_conn_check"):
            with st.spinner("Running multi-layer connectivity check..."):
                st.session_state["network_connectivity_result"] = run_connectivity_check(
                    adapters=snapshot.adapters,
                    default_gateways=snapshot.default_gateways,
                )

        conn_res = st.session_state.get("network_connectivity_result")
        if conn_res is not None:
            c_status = (
                "Healthy"
                if conn_res.classification.startswith("Connected")
                else ("Warning" if conn_res.classification == "DNS Resolution Failure" else "Critical")
            )
            render_kpi_card(
                label=f"Connectivity Status ({conn_res.executed_at})",
                value=conn_res.classification,
                detail=f"{conn_res.summary} | DNS: {conn_res.dns_detail}",
                status=c_status,
            )
            st.write("")
            if conn_res.gateway_ping is not None:
                gw_p = conn_res.gateway_ping
                st.caption(
                    f"Gateway Ping (`{gw_p.target}`): "
                    f"{gw_p.packets_received}/{gw_p.packets_sent} replies "
                    f"({gw_p.failure_reason or f'avg {gw_p.avg_ms} ms'})"
                )
            if conn_res.tcp_checks:
                st.dataframe(pd.DataFrame(conn_res.tcp_checks), width="stretch", hide_index=True)

        st.divider()
        col_ping, col_dns = st.columns(2)

        with col_ping:
            render_section_title("Ping Test (ICMP Echo)")
            ping_target = st.text_input("Destination IP or Hostname", value="1.1.1.1", key="ping_target_input")
            ping_count = st.slider("Packet Count", min_value=1, max_value=6, value=4, key="ping_count_input")
            if st.button("Run Ping Test", key="btn_run_ping"):
                with st.spinner("Running bounded ping..."):
                    st.session_state["network_ping_result"] = run_ping(ping_target, count=ping_count)

            ping_res = st.session_state.get("network_ping_result")
            if ping_res is not None:
                p_status = "Healthy" if ping_res.success and (ping_res.packet_loss_percent or 0) == 0 else (
                    "Warning" if ping_res.success else "Critical"
                )
                latency_txt = f"Avg: {ping_res.avg_ms} ms (Min {ping_res.min_ms} / Max {ping_res.max_ms})" if ping_res.avg_ms is not None else (ping_res.failure_reason or "No reply")
                render_kpi_card(
                    label=f"Ping Result ({ping_res.executed_at})",
                    value="Reachable" if ping_res.success else (ping_res.failure_reason or "Failed"),
                    detail=(
                        f"Target: {ping_res.target} ({ping_res.resolved_ip}) | "
                        f"Loss: {ping_res.packet_loss_percent if ping_res.packet_loss_percent is not None else UNKNOWN_VALUE}% | "
                        f"{latency_txt}"
                    ),
                    status=p_status,
                )
                with st.expander("Raw Ping Output"):
                    st.code(ping_res.raw_output or "No output", language="text")

        with col_dns:
            render_section_title("DNS Resolution Test")
            dns_host = st.text_input("Hostname to Resolve", value="www.microsoft.com", key="dns_host_input")
            if st.button("Resolve Hostname", key="btn_run_dns"):
                st.session_state["network_dns_result"] = resolve_dns(dns_host)

            dns_res = st.session_state.get("network_dns_result")
            if dns_res is not None:
                render_kpi_card(
                    label=f"DNS Lookup ({dns_res.executed_at})",
                    value="Resolved" if dns_res.success else "Failed",
                    detail=(
                        f"Latency: {dns_res.latency_ms} ms | IPv4: {', '.join(dns_res.ipv4_addresses) or 'None'}"
                        if dns_res.success
                        else (dns_res.error or "Lookup failed")
                    ),
                    status="Healthy" if dns_res.success else "Critical",
                )
                if dns_res.success:
                    st.write(
                        {
                            "hostname": dns_res.hostname,
                            "ipv4_addresses": dns_res.ipv4_addresses,
                            "ipv6_addresses": dns_res.ipv6_addresses,
                            "latency_ms": dns_res.latency_ms,
                        }
                    )

        st.divider()
        render_section_title("Traceroute (Bounded Execution)")
        tr_col1, tr_col2 = st.columns([3, 1])
        with tr_col1:
            trace_target = st.text_input("Traceroute Target", value="1.1.1.1", key="trace_target_input")
        with tr_col2:
            max_hops = st.slider("Max Hops", min_value=5, max_value=20, value=12, key="trace_hops_input")

        if st.button("Run Traceroute", key="btn_run_trace"):
            with st.spinner("Running bounded traceroute (max 15s)..."):
                st.session_state["network_trace_result"] = run_traceroute(trace_target, max_hops=max_hops)

        trace_res = st.session_state.get("network_trace_result")
        if trace_res is not None:
            st.caption(f"Executed: `{trace_res.executed_at}` | Target: `{trace_res.target}`")
            if trace_res.error:
                st.warning(trace_res.error)
            if trace_res.hops:
                hop_rows = [
                    {
                        "Hop": h.hop,
                        "RTT 1": h.rtt_1,
                        "RTT 2": h.rtt_2,
                        "RTT 3": h.rtt_3,
                        "Address": h.address,
                    }
                    for h in trace_res.hops
                ]
                st.dataframe(pd.DataFrame(hop_rows), width="stretch", hide_index=True)
            with st.expander("Raw Traceroute Output"):
                st.code(trace_res.raw_output or "No output", language="text")

    with tab_recs:
        render_section_title("Rule-Based Network Recommendations")
        recs = generate_network_recommendations(
            adapters=snapshot.adapters,
            default_gateways=snapshot.default_gateways,
            dns_servers=snapshot.dns_servers,
            wifi=snapshot.wifi,
            ping_result=st.session_state.get("network_ping_result"),
            connectivity=st.session_state.get("network_connectivity_result"),
        )
        for rec in recs:
            render_recommendation_card(
                severity=rec.severity,
                title=rec.title,
                explanation=rec.explanation,
                steps=rec.steps,
            )
