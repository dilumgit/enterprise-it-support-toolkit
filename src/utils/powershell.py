"""Safe, timeout-bounded, read-only PowerShell and Windows CIM query runner."""

from __future__ import annotations

import json
import platform
import re
import subprocess
from dataclasses import dataclass
from typing import Any

from src.config.settings import POWERSHELL_TIMEOUT_SECONDS

_VALID_CIM_IDENT = re.compile(r"^[A-Za-z0-9_]+$")
_VALID_NAMESPACE = re.compile(r"^[A-Za-z0-9_/\\]+$")


@dataclass(frozen=True)
class PowerShellResult:
    """Structured result returned by read-only PowerShell commands."""

    success: bool
    data: Any
    raw_output: str
    error: str | None = None


def is_windows() -> bool:
    """Return True when executing on a Windows host."""
    return platform.system().lower() == "windows"


def _normalize_json_list(data: Any) -> list[dict[str, Any]]:
    """Ensure parsed JSON output is consistently represented as a list of dicts."""
    if data is None:
        return []
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    return []


def run_powershell_json(
    script: str,
    timeout: int = POWERSHELL_TIMEOUT_SECONDS,
) -> PowerShellResult:
    """
    Execute a read-only PowerShell snippet and parse its JSON stdout.

    Uses -NoProfile and -NonInteractive with a strict timeout so the UI never
    blocks indefinitely on slow or unavailable WMI/CIM providers.
    """
    if not is_windows():
        return PowerShellResult(
            success=False,
            data=None,
            raw_output="",
            error="PowerShell/CIM diagnostics are only available on Windows hosts.",
        )

    wrapped_script = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        "$OutputEncoding = [System.Text.Encoding]::UTF8; "
        "$ProgressPreference = 'SilentlyContinue'; "
        f"{script}"
    )

    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                wrapped_script,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return PowerShellResult(
            success=False,
            data=None,
            raw_output="",
            error=f"PowerShell command timed out after {timeout}s.",
        )
    except FileNotFoundError:
        return PowerShellResult(
            success=False,
            data=None,
            raw_output="",
            error="powershell.exe was not found on the system PATH.",
        )
    except OSError as exc:
        return PowerShellResult(
            success=False,
            data=None,
            raw_output="",
            error=f"OS error invoking PowerShell: {exc}",
        )

    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()

    if completed.returncode != 0:
        return PowerShellResult(
            success=False,
            data=None,
            raw_output=stdout,
            error=stderr or f"PowerShell exited with code {completed.returncode}.",
        )

    if not stdout:
        return PowerShellResult(success=True, data=[], raw_output="", error=None)

    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as exc:
        return PowerShellResult(
            success=False,
            data=None,
            raw_output=stdout,
            error=f"Failed to parse PowerShell JSON output: {exc}",
        )

    return PowerShellResult(success=True, data=parsed, raw_output=stdout, error=None)


def query_cim_result(
    class_name: str,
    properties: list[str] | None = None,
    namespace: str = "root/cimv2",
    timeout: int = POWERSHELL_TIMEOUT_SECONDS,
) -> PowerShellResult:
    """
    Query a Windows CIM class safely via Get-CimInstance and return a PowerShellResult.

    All class names, namespaces, and property names are strictly validated against
    alphanumeric identifier patterns before constructing the read-only command.
    """
    if not _VALID_CIM_IDENT.match(class_name):
        return PowerShellResult(
            success=False,
            data=[],
            raw_output="",
            error=f"Invalid CIM class name: {class_name}",
        )

    if not _VALID_NAMESPACE.match(namespace):
        return PowerShellResult(
            success=False,
            data=[],
            raw_output="",
            error=f"Invalid CIM namespace: {namespace}",
        )

    select_clause = ""
    if properties:
        for prop in properties:
            if not _VALID_CIM_IDENT.match(prop):
                return PowerShellResult(
                    success=False,
                    data=[],
                    raw_output="",
                    error=f"Invalid CIM property name: {prop}",
                )
        select_clause = f" | Select-Object {', '.join(properties)}"

    script = (
        f"$items = @(Get-CimInstance -Namespace '{namespace}' -ClassName '{class_name}' "
        f"-ErrorAction Stop{select_clause}); "
        "$items | ConvertTo-Json -Depth 3 -Compress"
    )
    result = run_powershell_json(script, timeout=timeout)
    if not result.success:
        return PowerShellResult(
            success=False,
            data=[],
            raw_output=result.raw_output,
            error=result.error,
        )

    return PowerShellResult(
        success=True,
        data=_normalize_json_list(result.data),
        raw_output=result.raw_output,
        error=None,
    )


def query_cim(
    class_name: str,
    properties: list[str] | None = None,
    namespace: str = "root/cimv2",
    timeout: int = POWERSHELL_TIMEOUT_SECONDS,
) -> list[dict[str, Any]]:
    """Convenience wrapper returning normalized CIM rows or an empty list on error."""
    result = query_cim_result(
        class_name=class_name,
        properties=properties,
        namespace=namespace,
        timeout=timeout,
    )
    return result.data if result.success and isinstance(result.data, list) else []
