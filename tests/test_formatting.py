"""Unit tests for formatting and status classification utilities."""

from src.config.settings import UNAVAILABLE_VALUE, UNKNOWN_VALUE
from src.utils.formatting import (
    bytes_to_gb,
    bytes_to_mb,
    classify_utilization,
    format_bytes,
    format_cim_date,
    format_timestamp,
    format_uptime,
    safe_str,
    sanitize_csv_cell,
)


def test_safe_str_handles_empty_and_whitespace() -> None:
    assert safe_str("  Intel Core  ") == "Intel Core"
    assert safe_str("") == UNKNOWN_VALUE
    assert safe_str("   ") == UNKNOWN_VALUE
    assert safe_str(None, fallback=UNAVAILABLE_VALUE) == UNAVAILABLE_VALUE


def test_byte_conversions_and_formatting() -> None:
    assert bytes_to_gb(1024**3) == 1.0
    assert bytes_to_gb(None) is None
    assert bytes_to_gb(-5) is None
    assert bytes_to_mb(5 * 1024**2) == 5.0
    assert format_bytes(512) == "512 B"
    assert format_bytes(2 * 1024**3) == "2.00 GB"
    assert format_bytes(None) == UNAVAILABLE_VALUE


def test_format_uptime() -> None:
    assert format_uptime(None) == UNKNOWN_VALUE
    assert format_uptime(-1) == UNKNOWN_VALUE
    assert format_uptime(3661) == "01h 01m 01s"
    assert format_uptime(90061) == "1d 01h 01m 01s"


def test_format_timestamp_and_cim_date() -> None:
    assert format_timestamp(None) == UNKNOWN_VALUE
    assert format_timestamp(0) == UNKNOWN_VALUE
    formatted = format_timestamp(1_700_000_000)
    assert len(formatted) == 19
    assert format_cim_date("20250214") == "2025-02-14"
    assert format_cim_date("2025-02-14T10:20:30Z") == "2025-02-14"
    assert format_cim_date("/Date(1700000000000)/").startswith("2023-")
    assert format_cim_date(None) == UNKNOWN_VALUE


def test_classify_utilization() -> None:
    assert classify_utilization(None, 75.0, 90.0) == UNKNOWN_VALUE
    assert classify_utilization(45.0, 75.0, 90.0) == "Healthy"
    assert classify_utilization(75.0, 75.0, 90.0) == "Warning"
    assert classify_utilization(92.5, 75.0, 90.0) == "Critical"


def test_sanitize_csv_cell_neutralizes_formula_prefixes() -> None:
    assert sanitize_csv_cell("=CMD|' /C calc'!A0") == "'=CMD|' /C calc'!A0"
    assert sanitize_csv_cell("+1+1") == "'+1+1"
    assert sanitize_csv_cell("-2+3") == "'-2+3"
    assert sanitize_csv_cell("@SUM(1,2)") == "'@SUM(1,2)"
    assert sanitize_csv_cell("  =HYPERLINK(\"x\")") == "'  =HYPERLINK(\"x\")"
    assert sanitize_csv_cell("\tcmd") == "'\tcmd"
    assert sanitize_csv_cell(42) == "42"
    assert sanitize_csv_cell("Normal Title") == "Normal Title"
