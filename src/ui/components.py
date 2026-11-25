"""Reusable Streamlit UI cards, banners, and Plotly dark-mode charts."""

from __future__ import annotations

import html
from typing import TYPE_CHECKING, Any

import plotly.graph_objects as go
import streamlit as st

from src.config.settings import UNAVAILABLE_VALUE
from src.ui.styles import status_badge_html

if TYPE_CHECKING:
    from src.services.hardware_diagnostics import LogicalDiskInfo
    from src.services.network_diagnostics import NetworkAdapterInfo
    from src.services.system_info import ProcessInfo

PLOTLY_CONFIG: dict[str, bool] = {"displayModeBar": False}


def _escape_text(value: Any, fallback: str = "") -> str:
    """Safely convert any dynamic value to an HTML-escaped string."""
    if value is None:
        return html.escape(fallback, quote=True)
    return html.escape(str(value), quote=True)


def build_page_header_html(title: str, subtitle: str, badge_text: str | None = None) -> str:
    """Build compact, balanced HTML for the page header banner."""
    badge = status_badge_html(badge_text) if badge_text and badge_text.strip() else ""
    return (
        '<div class="eit-header">'
        '<div class="eit-header-top">'
        f'<div class="eit-header-title">{_escape_text(title)}</div>'
        f"{badge}"
        "</div>"
        f'<div class="eit-header-sub">{_escape_text(subtitle)}</div>'
        "</div>"
    )


def render_page_header(title: str, subtitle: str, badge_text: str | None = None) -> None:
    """Render a consistent enterprise header banner at the top of a page."""
    st.html(build_page_header_html(title=title, subtitle=subtitle, badge_text=badge_text))


def build_section_title_html(title: str) -> str:
    """Build compact HTML for a bordered section heading."""
    return f'<div class="eit-section-title">{_escape_text(title)}</div>'


def render_section_title(title: str) -> None:
    """Render a subtle bordered section heading."""
    st.html(build_section_title_html(title))


def build_kpi_card_html(
    label: Any,
    value: Any,
    detail: Any = "",
    status: str | None = None,
) -> str:
    """Build compact, escaped HTML for a KPI metric card with an optional status pill."""
    badge = status_badge_html(status) if status and str(status).strip() else ""
    safe_label = _escape_text(label)
    safe_value = _escape_text(value, fallback=UNAVAILABLE_VALUE)
    safe_detail = _escape_text(detail)
    return (
        '<div class="eit-card">'
        '<div class="eit-card-label">'
        f'<span class="eit-card-label-text">{safe_label}</span>'
        f"{badge}"
        "</div>"
        f'<div class="eit-card-value">{safe_value}</div>'
        f'<div class="eit-card-detail">{safe_detail}</div>'
        "</div>"
    )


def render_kpi_card(
    label: Any,
    value: Any,
    detail: Any = "",
    status: str | None = None,
) -> None:
    """Render a dark KPI metric card with an optional semantic status pill."""
    st.html(build_kpi_card_html(label=label, value=value, detail=detail, status=status))


def render_warnings_banner(warnings: list[str]) -> None:
    """Display non-fatal telemetry warnings in a collapsible expander."""
    if not warnings:
        return
    with st.expander(f"Telemetry Notices ({len(warnings)})", expanded=False):
        for item in warnings:
            st.caption(f"- {item}")


def _apply_dark_layout(fig: go.Figure, height: int = 260) -> go.Figure:
    """Apply uniform enterprise dark styling with animations disabled."""
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="#111827",
        plot_bgcolor="#111827",
        font={"color": "#E2E8F0", "size": 12},
        margin={"l": 16, "r": 16, "t": 38, "b": 16},
        height=height,
        transition={"duration": 0},
    )
    return fig


def build_utilization_gauge(
    title: str,
    value: float | None,
    warn_threshold: float,
    crit_threshold: float,
) -> go.Figure:
    """Build a static enterprise gauge chart for CPU/RAM percentage utilization."""
    display_val = float(value) if value is not None else 0.0
    if value is None:
        bar_color = "#475569"
    elif display_val >= crit_threshold:
        bar_color = "#EF4444"
    elif display_val >= warn_threshold:
        bar_color = "#F59E0B"
    else:
        bar_color = "#3B82F6"

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=display_val,
            number={"suffix": "%" if value is not None else "", "font": {"size": 26, "color": "#F8FAFC"}},
            title={"text": title, "font": {"size": 14, "color": "#CBD5E1"}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "#64748B", "tickwidth": 1},
                "bar": {"color": bar_color},
                "bgcolor": "#0B1120",
                "borderwidth": 1,
                "bordercolor": "#1E293B",
                "steps": [
                    {"range": [0, warn_threshold], "color": "#0F172A"},
                    {"range": [warn_threshold, crit_threshold], "color": "#1F2937"},
                    {"range": [crit_threshold, 100], "color": "#2A181B"},
                ],
            },
        )
    )
    return _apply_dark_layout(fig, height=230)


def build_per_core_chart(per_core: list[float]) -> go.Figure:
    """Build a bar chart showing per-logical-core CPU utilization."""
    labels = [f"Core {idx}" for idx in range(len(per_core))]
    colors = [
        "#EF4444" if val >= 90.0 else ("#F59E0B" if val >= 75.0 else "#3B82F6")
        for val in per_core
    ]
    fig = go.Figure(
        go.Bar(
            x=labels,
            y=per_core,
            marker_color=colors,
            text=[f"{val:.0f}%" for val in per_core],
            textposition="outside",
        )
    )
    fig.update_layout(
        title="Logical Core Utilization (%)",
        yaxis={"range": [0, 110], "gridcolor": "#1E293B", "title": "Usage (%)"},
        xaxis={"gridcolor": "#1E293B"},
    )
    return _apply_dark_layout(fig, height=280)


def build_disk_usage_chart(disks: list[LogicalDiskInfo]) -> go.Figure:
    """Build a horizontal stacked bar chart for used vs. free storage per partition."""
    labels = [d.mountpoint for d in disks]
    used_gb = [round((d.used_bytes or 0) / (1024**3), 2) for d in disks]
    free_gb = [round((d.free_bytes or 0) / (1024**3), 2) for d in disks]

    fig = go.Figure()
    fig.add_trace(
        go.Bar(
            y=labels,
            x=used_gb,
            name="Used (GB)",
            orientation="h",
            marker_color="#3B82F6",
        )
    )
    fig.add_trace(
        go.Bar(
            y=labels,
            x=free_gb,
            name="Free (GB)",
            orientation="h",
            marker_color="#1E293B",
        )
    )
    fig.update_layout(
        title="Logical Volume Capacity (GiB)",
        barmode="stack",
        xaxis={"gridcolor": "#1E293B", "title": "GiB"},
        yaxis={"gridcolor": "#1E293B", "autorange": "reversed"},
        legend={"orientation": "h", "y": 1.12, "x": 0},
    )
    return _apply_dark_layout(fig, height=max(220, 70 * max(1, len(disks)) + 90))


def build_top_memory_chart(processes: list[ProcessInfo], top_n: int = 10) -> go.Figure:
    """Build a horizontal bar chart of the highest-memory active processes."""
    top = sorted(processes, key=lambda p: p.memory_mb, reverse=True)[:top_n]
    top = list(reversed(top))
    labels = [f"{p.name} ({p.pid})" for p in top]
    values = [p.memory_mb for p in top]

    fig = go.Figure(
        go.Bar(
            y=labels,
            x=values,
            orientation="h",
            marker_color="#38BDF8",
            text=[f"{v:.1f} MB" for v in values],
            textposition="outside",
        )
    )
    fig.update_layout(
        title=f"Top {len(top)} Processes by Memory (MiB)",
        xaxis={"gridcolor": "#1E293B", "title": "Working Set (MiB)"},
        yaxis={"gridcolor": "#1E293B"},
    )
    return _apply_dark_layout(fig, height=340)


def build_recommendation_card_html(
    severity: str,
    title: str,
    explanation: str,
    steps: list[str],
    category: str | None = None,
) -> str:
    """Build compact, escaped HTML for a rule-based advisory card."""
    badge = status_badge_html(severity)
    cat_html = (
        f'<span style="color:#64748B;font-size:0.78rem;margin-right:0.5rem;">'
        f"[{_escape_text(category)}]</span>"
        if category and category.strip()
        else ""
    )
    steps_html = "".join(f"<li>{_escape_text(step)}</li>" for step in steps)
    steps_block = (
        f'<ul style="margin:0;padding-left:1.2rem;color:#94A3B8;font-size:0.84rem;line-height:1.5;">{steps_html}</ul>'
        if steps_html
        else ""
    )
    return (
        '<div class="eit-card" style="min-height:auto;margin-bottom:0.75rem;">'
        '<div class="eit-card-label">'
        f'<span class="eit-card-label-text">{cat_html}{_escape_text(title)}</span>'
        f"{badge}"
        "</div>"
        f'<div class="eit-card-detail" style="color:#CBD5E1;margin-bottom:0.5rem;">{_escape_text(explanation)}</div>'
        f"{steps_block}"
        "</div>"
    )


def render_recommendation_card(
    severity: str,
    title: str,
    explanation: str,
    steps: list[str],
    category: str | None = None,
) -> None:
    """Render a clean, static advisory card for rule-based network or security findings."""
    st.html(
        build_recommendation_card_html(
            severity=severity,
            title=title,
            explanation=explanation,
            steps=steps,
            category=category,
        )
    )


def build_adapter_traffic_chart(adapters: list[NetworkAdapterInfo]) -> go.Figure:
    """Build a grouped bar chart of cumulative adapter TX/RX traffic in MiB."""
    active = [
        a for a in adapters if (a.bytes_sent or 0) > 0 or (a.bytes_recv or 0) > 0
    ][:8]
    names = [a.name for a in active]
    sent_mb = [round((a.bytes_sent or 0) / (1024**2), 2) for a in active]
    recv_mb = [round((a.bytes_recv or 0) / (1024**2), 2) for a in active]

    fig = go.Figure()
    fig.add_trace(go.Bar(x=names, y=recv_mb, name="Received (MiB)", marker_color="#3B82F6"))
    fig.add_trace(go.Bar(x=names, y=sent_mb, name="Sent (MiB)", marker_color="#38BDF8"))
    fig.update_layout(
        title="Cumulative Interface Traffic (MiB)",
        barmode="group",
        xaxis={"gridcolor": "#1E293B"},
        yaxis={"gridcolor": "#1E293B", "title": "MiB"},
        legend={"orientation": "h", "y": 1.12, "x": 0},
    )
    return _apply_dark_layout(fig, height=280)


def build_count_bar_chart(
    title: str,
    counts: dict[str, int],
    *,
    color: str = "#3B82F6",
    y_title: str = "Count",
) -> go.Figure:
    """Build a standard enterprise dark bar chart for category count breakdowns."""
    fig = go.Figure(
        go.Bar(
            x=list(counts.keys()),
            y=list(counts.values()),
            marker_color=color,
            text=list(counts.values()),
            textposition="outside",
        )
    )
    fig.update_layout(
        title=title,
        xaxis={"gridcolor": "#1E293B"},
        yaxis={"gridcolor": "#1E293B", "title": y_title},
    )
    return _apply_dark_layout(fig, height=270)
