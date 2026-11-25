"""Read-only system administration & OS telemetry collector."""

from __future__ import annotations

import getpass
import os
import platform
import socket
import time
from dataclasses import dataclass, field

import psutil

from src.config.settings import (
    DEFAULT_PROCESS_LIMIT,
    SOFTWARE_QUERY_TIMEOUT_SECONDS,
    UNKNOWN_VALUE,
)
from src.utils.formatting import (
    bytes_to_mb,
    format_cim_date,
    format_timestamp,
    format_uptime,
    safe_str,
)
from src.utils.powershell import is_windows, query_cim_result, run_powershell_json


@dataclass(frozen=True)
class OsInfo:
    """Operating system, identity, boot time, and uptime metadata."""

    os_name: str
    os_version: str
    os_build: str
    architecture: str
    hostname: str
    fqdn: str
    current_user: str
    user_domain: str
    boot_time_epoch: float | None
    boot_time_display: str
    uptime_seconds: float | None
    uptime_display: str
    install_date: str
    registered_organization: str


@dataclass(frozen=True)
class ProcessInfo:
    """Read-only snapshot of an active OS process."""

    pid: int
    name: str
    username: str
    status: str
    cpu_percent: float
    memory_mb: float
    memory_percent: float


@dataclass(frozen=True)
class ServiceInfo:
    """Read-only snapshot of a Windows service."""

    name: str
    display_name: str
    status: str
    start_type: str
    binpath: str


@dataclass(frozen=True)
class SoftwareItem:
    """Installed software entry read from Windows Uninstall registry keys."""

    name: str
    version: str
    publisher: str
    install_date: str
    source: str


@dataclass(frozen=True)
class SystemInfoSnapshot:
    """Complete read-only system administration snapshot."""

    collected_at: str
    os_info: OsInfo
    total_processes: int
    top_processes: list[ProcessInfo]
    services: list[ServiceInfo]
    service_summary: dict[str, int]
    installed_software: list[SoftwareItem]
    warnings: list[str] = field(default_factory=list)


def get_os_info(warnings: list[str] | None = None) -> OsInfo:
    """Collect OS version, build, uptime, hostname, and user context."""
    hostname = safe_str(socket.gethostname())
    try:
        fqdn = safe_str(socket.getfqdn())
    except OSError:
        fqdn = hostname

    try:
        current_user = safe_str(os.environ.get("USERNAME") or getpass.getuser())
    except Exception:
        current_user = UNKNOWN_VALUE

    user_domain = safe_str(os.environ.get("USERDOMAIN"))

    boot_epoch: float | None = None
    uptime_secs: float | None = None
    try:
        boot_epoch = float(psutil.boot_time())
        uptime_secs = max(0.0, time.time() - boot_epoch)
    except Exception as exc:
        if warnings is not None:
            warnings.append(f"Unable to read system boot time: {exc}")

    cim_res = query_cim_result(
        "Win32_OperatingSystem",
        properties=[
            "Caption",
            "Version",
            "BuildNumber",
            "OSArchitecture",
            "InstallDate",
            "Organization",
        ],
    )
    if not cim_res.success and warnings is not None and cim_res.error:
        warnings.append(f"OS CIM metadata unavailable: {cim_res.error}")

    row = cim_res.data[0] if isinstance(cim_res.data, list) and cim_res.data else {}

    os_name = safe_str(row.get("Caption") or f"{platform.system()} {platform.release()}")
    os_version = safe_str(row.get("Version") or platform.version())
    os_build = safe_str(row.get("BuildNumber"))
    architecture = safe_str(row.get("OSArchitecture") or platform.machine())

    return OsInfo(
        os_name=os_name,
        os_version=os_version,
        os_build=os_build,
        architecture=architecture,
        hostname=hostname,
        fqdn=fqdn,
        current_user=current_user,
        user_domain=user_domain,
        boot_time_epoch=boot_epoch,
        boot_time_display=format_timestamp(boot_epoch),
        uptime_seconds=uptime_secs,
        uptime_display=format_uptime(uptime_secs),
        install_date=format_cim_date(row.get("InstallDate")),
        registered_organization=safe_str(row.get("Organization")),
    )


def get_running_processes(
    limit: int = DEFAULT_PROCESS_LIMIT,
    sort_by: str = "memory_mb",
    warnings: list[str] | None = None,
) -> tuple[int, list[ProcessInfo]]:
    """
    Collect running processes safely, handling AccessDenied and transient exits.

    Returns (total_process_count, top_processes_sorted).
    """
    procs: list[psutil.Process] = []
    try:
        for proc in psutil.process_iter(["pid", "name", "username", "status", "memory_info", "memory_percent"]):
            procs.append(proc)
            # Prime per-process CPU% baseline before brief sampling window.
            try:
                proc.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    except Exception as exc:
        if warnings is not None:
            warnings.append(f"Process enumeration failed: {exc}")
        return 0, []

    if procs:
        time.sleep(0.15)

    items: list[ProcessInfo] = []
    for proc in procs:
        try:
            info = proc.info
            mem_info = info.get("memory_info")
            mem_mb = bytes_to_mb(mem_info.rss) if mem_info is not None else 0.0
            mem_pct = info.get("memory_percent")
            cpu_pct = proc.cpu_percent(interval=None)
            items.append(
                ProcessInfo(
                    pid=int(info.get("pid", 0)),
                    name=safe_str(info.get("name")),
                    username=safe_str(info.get("username")),
                    status=safe_str(info.get("status")),
                    cpu_percent=round(float(cpu_pct or 0.0), 1),
                    memory_mb=round(float(mem_mb or 0.0), 1),
                    memory_percent=round(float(mem_pct or 0.0), 2),
                )
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    sort_key = sort_by if sort_by in {"memory_mb", "cpu_percent", "pid", "name"} else "memory_mb"
    reverse = sort_key in {"memory_mb", "cpu_percent"}
    items.sort(key=lambda item: getattr(item, sort_key), reverse=reverse)

    total_count = len(items)
    return total_count, items[: max(1, limit)]


def get_windows_services(warnings: list[str] | None = None) -> list[ServiceInfo]:
    """Enumerate Windows services in read-only mode via psutil with CIM fallback."""
    if not is_windows():
        if warnings is not None:
            warnings.append("Windows services are unavailable on non-Windows hosts.")
        return []

    services: list[ServiceInfo] = []
    try:
        for svc in psutil.win_service_iter():
            try:
                details = svc.as_dict()
                services.append(
                    ServiceInfo(
                        name=safe_str(details.get("name")),
                        display_name=safe_str(details.get("display_name")),
                        status=safe_str(details.get("status")).title(),
                        start_type=safe_str(details.get("start_type")).title(),
                        binpath=safe_str(details.get("binpath")),
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as exc:
        if warnings is not None:
            warnings.append(f"psutil service enumeration failed ({exc}); falling back to CIM.")
        cim_res = query_cim_result(
            "Win32_Service",
            properties=["Name", "DisplayName", "State", "StartMode", "PathName"],
        )
        for row in cim_res.data or []:
            services.append(
                ServiceInfo(
                    name=safe_str(row.get("Name")),
                    display_name=safe_str(row.get("DisplayName")),
                    status=safe_str(row.get("State")),
                    start_type=safe_str(row.get("StartMode")),
                    binpath=safe_str(row.get("PathName")),
                )
            )

    services.sort(key=lambda item: (item.status != "Running", item.display_name.lower()))
    return services


def summarize_services(services: list[ServiceInfo]) -> dict[str, int]:
    """Compute counts of total, running, stopped, and automatic services."""
    running = sum(1 for svc in services if svc.status.lower() == "running")
    stopped = sum(1 for svc in services if svc.status.lower() == "stopped")
    automatic = sum(1 for svc in services if svc.start_type.lower().startswith("auto"))
    return {
        "total": len(services),
        "running": running,
        "stopped": stopped,
        "automatic": automatic,
    }


def get_installed_software(warnings: list[str] | None = None) -> list[SoftwareItem]:
    """
    Retrieve installed software from Windows Uninstall registry keys (read-only).

    Deliberately queries the Uninstall registry hives instead of Win32_Product
    to avoid triggering MSI self-repair consistency checks.
    """
    if not is_windows():
        if warnings is not None:
            warnings.append("Installed software registry inventory is only available on Windows.")
        return []

    script = r"""
$paths = @(
    @{ Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'; Source = 'HKLM (64-bit)' },
    @{ Path = 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Source = 'HKLM (32-bit)' },
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'; Source = 'HKCU (User)' }
)
$items = foreach ($entry in $paths) {
    if (Test-Path $entry.Path) {
        Get-ItemProperty -Path $entry.Path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and $_.DisplayName.Trim().Length -gt 0 } |
            ForEach-Object {
                [PSCustomObject]@{
                    Name        = $_.DisplayName.Trim()
                    Version     = $_.DisplayVersion
                    Publisher   = $_.Publisher
                    InstallDate = $_.InstallDate
                    Source      = $entry.Source
                }
            }
    }
}
@($items) | ConvertTo-Json -Depth 2 -Compress
"""
    res = run_powershell_json(script, timeout=SOFTWARE_QUERY_TIMEOUT_SECONDS)
    if not res.success:
        if warnings is not None and res.error:
            warnings.append(f"Installed software inventory unavailable: {res.error}")
        return []

    rows = res.data if isinstance(res.data, list) else ([res.data] if isinstance(res.data, dict) else [])
    seen: set[tuple[str, str]] = set()
    software: list[SoftwareItem] = []

    for row in rows:
        if not isinstance(row, dict):
            continue
        name = safe_str(row.get("Name"), fallback="")
        if not name:
            continue
        version = safe_str(row.get("Version"))
        dedup_key = (name.lower(), version.lower())
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        software.append(
            SoftwareItem(
                name=name,
                version=version,
                publisher=safe_str(row.get("Publisher")),
                install_date=format_cim_date(row.get("InstallDate")),
                source=safe_str(row.get("Source")),
            )
        )

    software.sort(key=lambda item: item.name.lower())
    return software


def collect_system_info_snapshot(
    process_limit: int = DEFAULT_PROCESS_LIMIT,
    sort_processes_by: str = "memory_mb",
    include_software: bool = True,
) -> SystemInfoSnapshot:
    """Gather OS details, uptime, running processes, services, and optional software inventory."""
    warnings: list[str] = []
    os_info = get_os_info(warnings=warnings)
    total_processes, top_processes = get_running_processes(
        limit=process_limit,
        sort_by=sort_processes_by,
        warnings=warnings,
    )
    services = get_windows_services(warnings=warnings)
    service_summary = summarize_services(services)
    installed_software = get_installed_software(warnings=warnings) if include_software else []

    return SystemInfoSnapshot(
        collected_at=format_timestamp(time.time()),
        os_info=os_info,
        total_processes=total_processes,
        top_processes=top_processes,
        services=services,
        service_summary=service_summary,
        installed_software=installed_software,
        warnings=warnings,
    )
