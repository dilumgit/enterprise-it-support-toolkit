"""Pure formatting, sanitization, and status classification helpers."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from src.config.settings import UNAVAILABLE_VALUE, UNKNOWN_VALUE


def safe_str(value: Any, fallback: str = UNKNOWN_VALUE) -> str:
    """Convert any value to a stripped string, returning fallback when empty or None."""
    if value is None:
        return fallback
    text = str(value).strip()
    return text if text else fallback


def bytes_to_gb(num_bytes: int | float | None) -> float | None:
    """Convert bytes to gibibytes (GiB), or return None if input is missing/negative."""
    if num_bytes is None or num_bytes < 0:
        return None
    return round(float(num_bytes) / (1024**3), 2)


def bytes_to_mb(num_bytes: int | float | None) -> float | None:
    """Convert bytes to mebibytes (MiB), or return None if input is missing/negative."""
    if num_bytes is None or num_bytes < 0:
        return None
    return round(float(num_bytes) / (1024**2), 2)


def format_bytes(num_bytes: int | float | None, fallback: str = UNAVAILABLE_VALUE) -> str:
    """Format a byte count into human-readable binary units (B, KB, MB, GB, TB)."""
    if num_bytes is None or num_bytes < 0:
        return fallback

    value = float(num_bytes)
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    for unit in units[:-1]:
        if value < 1024.0:
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{value:.2f} {units[-1]}"


def format_uptime(seconds: float | int | None, fallback: str = UNKNOWN_VALUE) -> str:
    """Format an elapsed duration in seconds into 'Xd HHh MMm SSs'."""
    if seconds is None or seconds < 0:
        return fallback

    total = int(seconds)
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)

    if days > 0:
        return f"{days}d {hours:02d}h {minutes:02d}m {secs:02d}s"
    return f"{hours:02d}h {minutes:02d}m {secs:02d}s"


def format_timestamp(epoch_seconds: float | int | None, fallback: str = UNKNOWN_VALUE) -> str:
    """Format a POSIX timestamp in local time as 'YYYY-MM-DD HH:MM:SS'."""
    if epoch_seconds is None or epoch_seconds <= 0:
        return fallback
    try:
        return datetime.fromtimestamp(float(epoch_seconds)).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return fallback


def format_cim_date(raw_value: Any, fallback: str = UNKNOWN_VALUE) -> str:
    """Parse common CIM/registry date strings into 'YYYY-MM-DD' when possible."""
    text = safe_str(raw_value, fallback="")
    if not text:
        return fallback

    # Handle YYYYMMDD registry InstallDate
    if len(text) == 8 and text.isdigit():
        try:
            return datetime.strptime(text, "%Y%m%d").strftime("%Y-%m-%d")
        except ValueError:
            return text

    # Handle ISO strings returned by PowerShell ConvertTo-Json (e.g., 2024-01-15T00:00:00...)
    if "T" in text and len(text) >= 10:
        candidate = text[:10]
        try:
            datetime.strptime(candidate, "%Y-%m-%d")
            return candidate
        except ValueError:
            pass

    # Handle /Date(1700000000000)/ JSON serialization from older PowerShell serializers
    if text.startswith("/Date(") and text.endswith(")/"):
        inner = text[6:-2].split("+")[0].split("-")[0]
        if inner.isdigit():
            return format_timestamp(int(inner) / 1000.0, fallback=fallback)[:10]

    return text


def classify_utilization(
    percent: float | None,
    warn_threshold: float,
    crit_threshold: float,
) -> str:
    """Classify a percentage utilization metric as Healthy, Warning, Critical, or Unknown."""
    if percent is None:
        return UNKNOWN_VALUE
    if percent >= crit_threshold:
        return "Critical"
    if percent >= warn_threshold:
        return "Warning"
    return "Healthy"


def sanitize_csv_cell(value: Any) -> str:
    """
    Neutralize spreadsheet formula injection (CSV injection) on user-controlled cells.

    Numeric types pass through untouched; strings starting with '=', '+', '-', '@',
    tab, or carriage return (after optional leading whitespace) are prefixed with "'".
    """
    if value is None:
        return ""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)

    text = str(value)
    stripped = text.lstrip(" ")
    if text and (text[0] in ("=", "+", "-", "@", "\t", "\r") or (stripped and stripped[0] in ("=", "+", "-", "@"))):
        return f"'{text}"
    return text
