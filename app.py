"""Streamlit entry point for the Enterprise IT Support & Network Diagnostics Toolkit."""

from __future__ import annotations

import html

import streamlit as st

from src.config.settings import (
    APP_NAME,
    APP_PHASE,
    APP_SHORT_NAME,
    APP_VERSION,
    NAVIGATION_ITEMS,
    ORGANIZATION_CONTEXT,
)
from src.ui.pages import (
    assets,
    hardware,
    helpdesk,
    network,
    overview,
    reports,
    security,
    system_admin,
    troubleshooter,
)
from src.ui.styles import apply_enterprise_styles

st.set_page_config(
    page_title=APP_NAME,
    layout="wide",
    initial_sidebar_state="expanded",
)


def main() -> None:
    """Initialize enterprise theme, render sidebar navigation, and route active page."""
    apply_enterprise_styles()

    with st.sidebar:
        st.html(
            '<div class="eit-sidebar-brand">'
            f'<div class="eit-sidebar-title">{html.escape(APP_SHORT_NAME)}</div>'
            f'<div class="eit-sidebar-sub">v{html.escape(APP_VERSION)} • {html.escape(APP_PHASE)}</div>'
            "</div>"
        )

        labels = [item.label for item in NAVIGATION_ITEMS]
        selected_label = st.radio(
            "Navigation",
            options=labels,
            index=0,
            label_visibility="collapsed",
            key="nav_page_selector",
        )
        selected_index = labels.index(selected_label)
        active_item = NAVIGATION_ITEMS[selected_index]

        st.html(
            '<div class="eit-sidebar-footer">'
            f"<strong>Profile:</strong> {html.escape(ORGANIZATION_CONTEXT)}<br/>"
            "<strong>Execution:</strong> Read-Only Diagnostics<br/>"
            "<strong>Elevation:</strong> Standard User Safe"
            "</div>"
        )

    page_dispatch = {
        "overview": overview.render,
        "hardware": hardware.render,
        "system_admin": system_admin.render,
        "network": network.render,
        "security": security.render,
        "helpdesk": helpdesk.render,
        "assets": assets.render,
        "troubleshooter": troubleshooter.render,
        "reports": reports.render,
    }

    renderer = page_dispatch[active_item.key]
    renderer()


if __name__ == "__main__":
    main()
