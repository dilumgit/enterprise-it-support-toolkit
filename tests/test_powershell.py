"""Unit tests for the safe read-only PowerShell and CIM runner."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace
from unittest.mock import patch

from src.utils.powershell import PowerShellResult, query_cim_result, run_powershell_json


def test_query_cim_rejects_invalid_identifiers() -> None:
    bad_class = query_cim_result("Win32_Processor; Remove-Item C:\\")
    assert not bad_class.success
    assert "Invalid CIM class name" in (bad_class.error or "")

    bad_prop = query_cim_result("Win32_Processor", properties=["Name", "Bad-Prop"])
    assert not bad_prop.success
    assert "Invalid CIM property name" in (bad_prop.error or "")

    bad_ns = query_cim_result("Win32_Processor", namespace="root/cimv2;bad")
    assert not bad_ns.success
    assert "Invalid CIM namespace" in (bad_ns.error or "")


def test_run_powershell_json_non_windows() -> None:
    with patch("src.utils.powershell.is_windows", return_value=False):
        res = run_powershell_json("Get-Date")
    assert not res.success
    assert "only available on Windows" in (res.error or "")


def test_run_powershell_json_timeout() -> None:
    with (
        patch("src.utils.powershell.is_windows", return_value=True),
        patch(
            "src.utils.powershell.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="powershell.exe", timeout=5),
        ),
    ):
        res = run_powershell_json("Get-CimInstance Win32_Processor", timeout=5)
    assert not res.success
    assert "timed out after 5s" in (res.error or "")


def test_run_powershell_json_invalid_json() -> None:
    fake_proc = SimpleNamespace(returncode=0, stdout="not-json", stderr="")
    with (
        patch("src.utils.powershell.is_windows", return_value=True),
        patch("src.utils.powershell.subprocess.run", return_value=fake_proc),
    ):
        res = run_powershell_json("Write-Output 'bad'")
    assert not res.success
    assert "Failed to parse PowerShell JSON" in (res.error or "")


def test_query_cim_result_normalizes_single_dict_to_list() -> None:
    mock_result = PowerShellResult(
        success=True,
        data={"Name": "Mock CPU"},
        raw_output='{"Name": "Mock CPU"}',
        error=None,
    )
    with patch("src.utils.powershell.run_powershell_json", return_value=mock_result):
        res = query_cim_result("Win32_Processor", properties=["Name"])
    assert res.success
    assert res.data == [{"Name": "Mock CPU"}]
