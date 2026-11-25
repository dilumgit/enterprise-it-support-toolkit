"""Regression tests for shared UI HTML builders and KPI card rendering."""

from __future__ import annotations

from html.parser import HTMLParser

from src.config.settings import UNAVAILABLE_VALUE
from src.ui.components import (
    build_kpi_card_html,
    build_page_header_html,
    build_recommendation_card_html,
    build_section_title_html,
)


class _TagBalanceParser(HTMLParser):
    """Verify that generated HTML fragments have strictly balanced tags."""

    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in {"br", "hr", "img", "input"}:
            self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        assert self.stack, f"Unexpected closing tag </{tag}>"
        top = self.stack.pop()
        assert top == tag, f"Mismatched closing tag </{tag}> for <{top}>"


def _assert_valid_compact_html(snippet: str) -> None:
    assert "\n\n" not in snippet
    for line in snippet.splitlines():
        assert not line.startswith("    "), f"Unexpected markdown code-block indent in line: {line!r}"
    parser = _TagBalanceParser()
    parser.feed(snippet)
    parser.close()
    assert parser.stack == [], f"Unclosed tags remaining: {parser.stack}"


def test_kpi_card_with_and_without_status_badge() -> None:
    with_badge = build_kpi_card_html("CPU Utilization", "32.5%", "16 logical cores", status="Healthy")
    without_badge = build_kpi_card_html("L3 Cache", "16384 KB", "Socket: LGA", status=None)
    empty_badge = build_kpi_card_html("Total Tickets", "0", "All persisted records", status="   ")

    for snippet in (with_badge, without_badge, empty_badge):
        _assert_valid_compact_html(snippet)
        assert '<div class="eit-card">' in snippet
        assert '<div class="eit-card-value">' in snippet
        assert '<div class="eit-card-detail">' in snippet

    assert "eit-badge" in with_badge
    assert "eit-badge" not in without_badge
    assert "eit-badge" not in empty_badge


def test_kpi_card_handles_numeric_zero_unavailable_long_and_xss_values() -> None:
    zero_card = build_kpi_card_html("Critical Active", 0, 0)
    _assert_valid_compact_html(zero_card)
    assert '<div class="eit-card-value">0</div>' in zero_card

    unavail_card = build_kpi_card_html("Battery Charge", None, UNAVAILABLE_VALUE, status=UNAVAILABLE_VALUE)
    _assert_valid_compact_html(unavail_card)
    assert UNAVAILABLE_VALUE in unavail_card

    long_val = "Microsoft Windows 11 Pro for Workstations Enterprise Edition 24H2 " * 3
    long_card = build_kpi_card_html("Operating System & Very Long Label", long_val, "Detail " * 20)
    _assert_valid_compact_html(long_card)
    assert "eit-card-label-text" in long_card

    xss_card = build_kpi_card_html(
        "<script>alert(1)</script>",
        '<b>"unsafe"&</b>',
        "<img src=x onerror=alert(2)>",
        status="<svg onload=alert(3)>",
    )
    _assert_valid_compact_html(xss_card)
    assert "<script>" not in xss_card
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in xss_card
    assert "&lt;b&gt;&quot;unsafe&quot;&amp;&lt;/b&gt;" in xss_card
    assert "<svg" not in xss_card


def test_page_header_section_and_recommendation_cards_compact_and_escaped() -> None:
    hdr_no_badge = build_page_header_html("Hardware", "Subtitle <test>", badge_text=None)
    hdr_badge = build_page_header_html("Hardware", "Subtitle", badge_text="Implemented")
    sec = build_section_title_html("Section & <Title>")
    rec_empty_steps = build_recommendation_card_html("Warning", "Alert", "Explanation", steps=[], category=None)
    rec_with_steps = build_recommendation_card_html(
        "Critical",
        "Firewall Off",
        "Disabled profile",
        steps=["Check GPO", "Escalate to <SOC>"],
        category="Security",
    )

    for snippet in (hdr_no_badge, hdr_badge, sec, rec_empty_steps, rec_with_steps):
        _assert_valid_compact_html(snippet)

    assert "eit-badge" not in hdr_no_badge
    assert "eit-badge" in hdr_badge
    assert "&lt;Title&gt;" in sec
    assert "<ul" not in rec_empty_steps
    assert "&lt;SOC&gt;" in rec_with_steps
