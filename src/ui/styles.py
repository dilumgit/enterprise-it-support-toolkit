"""Minimal enterprise dark-mode styles and semantic status badge helpers."""

from __future__ import annotations

import html

import streamlit as st

_STATUS_STYLE_MAP: dict[str, tuple[str, str, str]] = {
    "healthy": ("#064E3B", "#34D399", "#065F46"),
    "running": ("#064E3B", "#34D399", "#065F46"),
    "enabled": ("#064E3B", "#34D399", "#065F46"),
    "connected": ("#064E3B", "#34D399", "#065F46"),
    "up": ("#064E3B", "#34D399", "#065F46"),
    "resolved": ("#064E3B", "#34D399", "#065F46"),
    "available": ("#064E3B", "#34D399", "#065F46"),
    "implemented": ("#1E3A8A", "#93C5FD", "#1D4ED8"),
    "info": ("#1E3A8A", "#93C5FD", "#1D4ED8"),
    "in progress": ("#1E3A8A", "#93C5FD", "#1D4ED8"),
    "assigned": ("#1E3A8A", "#93C5FD", "#1D4ED8"),
    "open": ("#78350F", "#FBBF24", "#92400E"),
    "warning": ("#78350F", "#FBBF24", "#92400E"),
    "medium": ("#78350F", "#FBBF24", "#92400E"),
    "high": ("#9A3412", "#FDBA74", "#C2410C"),
    "low": ("#1E3A8A", "#93C5FD", "#1D4ED8"),
    "informational": ("#1E293B", "#94A3B8", "#334155"),
    "limited": ("#78350F", "#FBBF24", "#92400E"),
    "under maintenance": ("#78350F", "#FBBF24", "#92400E"),
    "critical": ("#7F1D1D", "#F87171", "#991B1B"),
    "stopped": ("#7F1D1D", "#F87171", "#991B1B"),
    "disabled": ("#7F1D1D", "#F87171", "#991B1B"),
    "down": ("#7F1D1D", "#F87171", "#991B1B"),
    "disconnected": ("#7F1D1D", "#F87171", "#991B1B"),
    "closed": ("#1E293B", "#94A3B8", "#334155"),
    "retired": ("#1E293B", "#94A3B8", "#334155"),
    "planned": ("#1E293B", "#94A3B8", "#334155"),
    "unknown": ("#1E293B", "#94A3B8", "#334155"),
    "unavailable": ("#1E293B", "#94A3B8", "#334155"),
}


def apply_enterprise_styles() -> None:
    """Inject clean, static enterprise CSS with zero unnecessary animations."""
    css = "\n".join(
        [
            "<style>",
            ".block-container { padding-top: 1.5rem; padding-bottom: 2rem; max-width: 1380px; }",
            '[data-testid="stSidebar"] { background-color: #0F172A; border-right: 1px solid #1E293B; }',
            ".eit-header { box-sizing: border-box; width: 100%; background: #111827; border: 1px solid #1E293B; border-left: 4px solid #3B82F6; border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1.25rem; overflow-wrap: anywhere; }",
            ".eit-header-top { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; flex-wrap: wrap; }",
            ".eit-header-title { font-size: 1.4rem; font-weight: 600; color: #F8FAFC; margin: 0; overflow-wrap: anywhere; }",
            ".eit-header-sub { color: #94A3B8; font-size: 0.9rem; margin-top: 0.3rem; overflow-wrap: anywhere; }",
            ".eit-card { box-sizing: border-box; width: 100%; min-width: 0; min-height: 118px; background: #111827; border: 1px solid #1E293B; border-radius: 8px; padding: 1rem 1.1rem; display: flex; flex-direction: column; justify-content: space-between; overflow: hidden; }",
            ".eit-card-label { color: #94A3B8; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.45rem; display: flex; align-items: flex-start; justify-content: space-between; gap: 0.5rem; flex-wrap: wrap; min-width: 0; }",
            ".eit-card-label-text { overflow-wrap: anywhere; word-break: break-word; min-width: 0; }",
            ".eit-card-value { color: #F8FAFC; font-size: clamp(1.15rem, 1.5vw, 1.5rem); font-weight: 600; line-height: 1.25; margin-bottom: 0.35rem; overflow-wrap: anywhere; word-break: break-word; }",
            ".eit-card-detail { color: #94A3B8; font-size: 0.82rem; line-height: 1.35; overflow-wrap: anywhere; word-break: break-word; }",
            ".eit-badge { display: inline-block; padding: 0.15rem 0.55rem; border-radius: 9999px; font-size: 0.72rem; font-weight: 600; letter-spacing: 0.02em; border: 1px solid transparent; white-space: nowrap; flex-shrink: 0; }",
            ".eit-section-title { color: #E2E8F0; font-size: 1.05rem; font-weight: 600; margin: 0.75rem 0 0.6rem 0; padding-bottom: 0.35rem; border-bottom: 1px solid #1E293B; }",
            ".eit-sidebar-brand { box-sizing: border-box; padding: 0.25rem 0 0.75rem 0; border-bottom: 1px solid #1E293B; margin-bottom: 0.75rem; }",
            ".eit-sidebar-title { color: #F8FAFC; font-size: 1.05rem; font-weight: 600; margin: 0; }",
            ".eit-sidebar-sub { color: #64748B; font-size: 0.78rem; margin-top: 0.2rem; }",
            ".eit-sidebar-footer { box-sizing: border-box; margin-top: 1.25rem; padding-top: 0.75rem; border-top: 1px solid #1E293B; color: #94A3B8; font-size: 0.78rem; line-height: 1.45; }",
            "</style>",
        ]
    )
    st.markdown(css, unsafe_allow_html=True)


def status_badge_html(status: str) -> str:
    """Return an HTML pill badge for a semantic status string."""
    normalized = (status or "Unknown").strip()
    bg, fg, border = _STATUS_STYLE_MAP.get(
        normalized.lower(),
        ("#1E293B", "#CBD5E1", "#334155"),
    )
    escaped = html.escape(normalized)
    return (
        f'<span class="eit-badge" '
        f'style="background:{bg};color:{fg};border-color:{border};">{escaped}</span>'
    )
