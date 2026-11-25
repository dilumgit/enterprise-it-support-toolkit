"""Unit tests for system administration and OS telemetry collectors."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import psutil

from src.config.settings import UNKNOWN_VALUE
from src.services.system_info import (
    ServiceInfo,
    get_installed_software,
    get_os_info,
    get_running_processes,
    get_windows_services,
    summarize_services,
)
from src.utils.powershell import PowerShellResult


def test_get_os_info_with_mocked_cim() -> None:
    cim_mock = PowerShellResult(
        success=True,
        data=[
            {
                "Caption": "Microsoft Windows 11 Enterprise",
                "Version": "10.0.22621",
                "BuildNumber": "22621",
                "OSArchitecture": "64-bit",
                "InstallDate": "2024-03-10T00:00:00Z",
                "Organization": "FinCorp Global",
            }
        ],
        raw_output="",
    )
    with (
        patch("src.services.system_info.query_cim_result", return_value=cim_mock),
        patch("src.services.system_info.psutil.boot_time", return_value=1_700_000_000.0),
        patch("src.services.system_info.time.time", return_value=1_700_003_600.0),
    ):
        os_info = get_os_info()

    assert os_info.os_name == "Microsoft Windows 11 Enterprise"
    assert os_info.os_build == "22621"
    assert os_info.uptime_display == "01h 00m 00s"
    assert os_info.install_date == "2024-03-10"
    assert os_info.registered_organization == "FinCorp Global"


def test_get_running_processes_handles_access_denied() -> None:
    proc_ok = MagicMock()
    proc_ok.info = {
        "pid": 100,
        "name": "python.exe",
        "username": "CORP\\analyst",
        "status": "running",
        "memory_info": SimpleNamespace(rss=128 * 1024**2),
        "memory_percent": 1.25,
    }
    proc_ok.cpu_percent.return_value = 3.5

    proc_denied = MagicMock()
    proc_denied.info = {"pid": 4, "name": "System"}
    proc_denied.cpu_percent.side_effect = psutil.AccessDenied(pid=4)

    with (
        patch("src.services.system_info.psutil.process_iter", return_value=[proc_ok, proc_denied]),
        patch("src.services.system_info.time.sleep", return_value=None),
    ):
        total, items = get_running_processes(limit=10)

    assert total == 1
    assert len(items) == 1
    assert items[0].name == "python.exe"
    assert items[0].memory_mb == 128.0
    assert items[0].cpu_percent == 3.5


def test_summarize_services_counts() -> None:
    services = [
        ServiceInfo("WinDefend", "Microsoft Defender", "Running", "Automatic", "C:\\ProgramData\\..."),
        ServiceInfo("Spooler", "Print Spooler", "Stopped", "Manual", "C:\\Windows\\..."),
        ServiceInfo("Dhcp", "DHCP Client", "Running", "Automatic", "C:\\Windows\\..."),
    ]
    summary = summarize_services(services)
    assert summary == {"total": 3, "running": 2, "stopped": 1, "automatic": 2}


def test_get_windows_services_non_windows() -> None:
    warnings: list[str] = []
    with patch("src.services.system_info.is_windows", return_value=False):
        services = get_windows_services(warnings=warnings)
    assert services == []
    assert warnings


def test_get_installed_software_deduplicates_and_formats() -> None:
    ps_mock = PowerShellResult(
        success=True,
        data=[
            {
                "Name": "Python 3.13.2",
                "Version": "3.13.2",
                "Publisher": "Python Software Foundation",
                "InstallDate": "20250205",
                "Source": "HKCU (User)",
            },
            {
                "Name": "Python 3.13.2",
                "Version": "3.13.2",
                "Publisher": "Python Software Foundation",
                "InstallDate": "20250205",
                "Source": "HKLM (64-bit)",
            },
            {
                "Name": "7-Zip",
                "Version": None,
                "Publisher": "",
                "InstallDate": None,
                "Source": "HKLM (64-bit)",
            },
        ],
        raw_output="",
    )
    with (
        patch("src.services.system_info.is_windows", return_value=True),
        patch("src.services.system_info.run_powershell_json", return_value=ps_mock),
    ):
        software = get_installed_software()

    assert len(software) == 2
    assert software[0].name == "7-Zip"
    assert software[0].version == UNKNOWN_VALUE
    assert software[0].publisher == UNKNOWN_VALUE
    assert software[1].name == "Python 3.13.2"
    assert software[1].install_date == "2025-02-05"


def test_system_info_live_smoke() -> None:
    os_info = get_os_info()
    total, procs = get_running_processes(limit=5)
    assert os_info.hostname != UNKNOWN_VALUE
    assert total >= 1
    assert len(procs) >= 1
