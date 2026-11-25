"""Unit tests for hardware diagnostics collectors."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from src.config.settings import UNAVAILABLE_VALUE, UNKNOWN_VALUE
from src.services.hardware_diagnostics import (
    collect_hardware_snapshot,
    get_battery_info,
    get_cpu_info,
    get_disk_info,
    get_memory_info,
    get_system_specs,
)
from src.utils.powershell import PowerShellResult


def test_get_cpu_info_with_mocked_telemetry() -> None:
    cim_mock = PowerShellResult(
        success=True,
        data=[
            {
                "Name": "Intel(R) Xeon(R) W-2245",
                "Manufacturer": "GenuineIntel",
                "NumberOfCores": 8,
                "NumberOfLogicalProcessors": 16,
                "MaxClockSpeed": 3900,
                "L2CacheSize": 8192,
                "L3CacheSize": 16896,
                "SocketDesignation": "LGA2066",
            }
        ],
        raw_output="",
    )
    with (
        patch("src.services.hardware_diagnostics.psutil.cpu_percent", return_value=[20.0, 40.0]),
        patch("src.services.hardware_diagnostics.psutil.cpu_count", side_effect=[8, 16]),
        patch("src.services.hardware_diagnostics.psutil.cpu_freq", return_value=SimpleNamespace(current=3500.0, max=3900.0)),
        patch("src.services.hardware_diagnostics.query_cim_result", return_value=cim_mock),
    ):
        cpu = get_cpu_info()

    assert cpu.processor_name == "Intel(R) Xeon(R) W-2245"
    assert cpu.usage_percent == 30.0
    assert cpu.physical_cores == 8
    assert cpu.logical_cores == 16
    assert cpu.status == "Healthy"


def test_get_memory_info_with_dimm_modules() -> None:
    vm = SimpleNamespace(total=32 * 1024**3, available=16 * 1024**3, used=16 * 1024**3, percent=50.0)
    swap = SimpleNamespace(total=4 * 1024**3, used=1 * 1024**3, percent=25.0)
    cim_mock = PowerShellResult(
        success=True,
        data=[
            {
                "DeviceLocator": "DIMM_A1",
                "Manufacturer": "Micron",
                "Capacity": 16 * 1024**3,
                "ConfiguredClockSpeed": 4800,
                "SMBIOSMemoryType": 34,
                "PartNumber": "MTC8C1084S1SC48BA1",
            }
        ],
        raw_output="",
    )
    with (
        patch("src.services.hardware_diagnostics.psutil.virtual_memory", return_value=vm),
        patch("src.services.hardware_diagnostics.psutil.swap_memory", return_value=swap),
        patch("src.services.hardware_diagnostics.query_cim_result", return_value=cim_mock),
    ):
        mem = get_memory_info()

    assert mem.percent_used == 50.0
    assert mem.status == "Healthy"
    assert len(mem.modules) == 1
    assert mem.modules[0].memory_type == "DDR5"
    assert mem.modules[0].speed_mhz == 4800


def test_get_disk_info_skips_inaccessible_partitions() -> None:
    part_ok = SimpleNamespace(device="C:\\", mountpoint="C:\\", fstype="NTFS", opts="rw,fixed")
    part_denied = SimpleNamespace(device="E:\\", mountpoint="E:\\", fstype="NTFS", opts="rw,fixed")
    usage_ok = SimpleNamespace(total=500 * 1024**3, used=420 * 1024**3, free=80 * 1024**3, percent=84.0)

    def fake_disk_usage(mount: str) -> SimpleNamespace:
        if mount == "E:\\":
            raise PermissionError("Access is denied")
        return usage_ok

    cim_mock = PowerShellResult(success=True, data=[], raw_output="")
    warnings: list[str] = []
    with (
        patch("src.services.hardware_diagnostics.psutil.disk_partitions", return_value=[part_ok, part_denied]),
        patch("src.services.hardware_diagnostics.psutil.disk_usage", side_effect=fake_disk_usage),
        patch("src.services.hardware_diagnostics.query_cim_result", return_value=cim_mock),
    ):
        logical, physical = get_disk_info(warnings=warnings)

    assert len(logical) == 1
    assert logical[0].status == "Warning"
    assert physical == []
    assert any("E:\\" in w for w in warnings)


def test_get_battery_info_unavailable_on_desktop() -> None:
    with patch("src.services.hardware_diagnostics.psutil.sensors_battery", return_value=None):
        bat = get_battery_info()

    assert not bat.present
    assert bat.percent is None
    assert bat.time_left_display == UNAVAILABLE_VALUE
    assert bat.status == UNAVAILABLE_VALUE


def test_get_system_specs_falls_back_to_unknown_on_cim_failure() -> None:
    cim_fail = PowerShellResult(success=False, data=[], raw_output="", error="CIM timeout")
    warnings: list[str] = []
    with patch("src.services.hardware_diagnostics.query_cim_result", return_value=cim_fail):
        specs = get_system_specs(warnings=warnings)

    assert specs.manufacturer == UNKNOWN_VALUE
    assert specs.bios_version == UNKNOWN_VALUE
    assert len(warnings) == 3


def test_collect_hardware_snapshot_live_smoke() -> None:
    snapshot = collect_hardware_snapshot()
    assert snapshot.collected_at != UNKNOWN_VALUE
    assert snapshot.cpu.logical_cores is None or snapshot.cpu.logical_cores >= 1
    assert snapshot.memory.total_bytes is None or snapshot.memory.total_bytes > 0
