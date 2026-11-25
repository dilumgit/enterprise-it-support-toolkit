"""Read-only hardware diagnostics collector using psutil and Windows CIM."""

from __future__ import annotations

import platform
import socket
import time
from dataclasses import dataclass, field
from typing import Any

import psutil

from src.config.settings import (
    CPU_CRITICAL_THRESHOLD,
    CPU_WARNING_THRESHOLD,
    DISK_CRITICAL_THRESHOLD,
    DISK_WARNING_THRESHOLD,
    RAM_CRITICAL_THRESHOLD,
    RAM_WARNING_THRESHOLD,
    UNAVAILABLE_VALUE,
    UNKNOWN_VALUE,
)
from src.utils.formatting import (
    classify_utilization,
    format_bytes,
    format_cim_date,
    format_timestamp,
    format_uptime,
    safe_str,
)
from src.utils.powershell import query_cim_result

_SMBIOS_MEMORY_TYPES: dict[int, str] = {
    20: "DDR",
    21: "DDR2",
    24: "DDR3",
    26: "DDR4",
    34: "DDR5",
}


@dataclass(frozen=True)
class CpuInfo:
    """CPU utilization and processor specification summary."""

    processor_name: str
    manufacturer: str
    architecture: str
    physical_cores: int | None
    logical_cores: int | None
    current_freq_mhz: float | None
    max_freq_mhz: float | None
    usage_percent: float | None
    per_core_percent: list[float]
    l2_cache_kb: int | None
    l3_cache_kb: int | None
    socket_designation: str
    status: str


@dataclass(frozen=True)
class MemoryModuleInfo:
    """Physical DIMM slot details from Windows CIM."""

    slot: str
    manufacturer: str
    capacity_bytes: int | None
    capacity_display: str
    speed_mhz: int | None
    memory_type: str
    part_number: str


@dataclass(frozen=True)
class MemoryInfo:
    """Virtual (RAM) and swap memory utilization plus physical DIMM inventory."""

    total_bytes: int | None
    available_bytes: int | None
    used_bytes: int | None
    percent_used: float | None
    swap_total_bytes: int | None
    swap_used_bytes: int | None
    swap_percent: float | None
    modules: list[MemoryModuleInfo]
    status: str


@dataclass(frozen=True)
class LogicalDiskInfo:
    """Mounted filesystem partition metrics."""

    device: str
    mountpoint: str
    fstype: str
    total_bytes: int | None
    used_bytes: int | None
    free_bytes: int | None
    percent_used: float | None
    status: str


@dataclass(frozen=True)
class PhysicalDiskInfo:
    """Physical storage hardware details from Windows CIM."""

    model: str
    interface_type: str
    media_type: str
    size_bytes: int | None
    size_display: str
    serial_number: str
    status: str


@dataclass(frozen=True)
class BatteryInfo:
    """Endpoint battery telemetry when a battery is present."""

    present: bool
    percent: float | None
    power_plugged: bool | None
    secs_left: int | None
    time_left_display: str
    status: str


@dataclass(frozen=True)
class SystemSpecs:
    """Chassis, system model, BIOS, and motherboard metadata."""

    hostname: str
    manufacturer: str
    model: str
    system_type: str
    serial_number: str
    bios_vendor: str
    bios_version: str
    bios_release_date: str
    baseboard_manufacturer: str
    baseboard_product: str


@dataclass(frozen=True)
class HardwareSnapshot:
    """Complete read-only hardware diagnostics snapshot."""

    collected_at: str
    cpu: CpuInfo
    memory: MemoryInfo
    logical_disks: list[LogicalDiskInfo]
    physical_disks: list[PhysicalDiskInfo]
    battery: BatteryInfo
    system_specs: SystemSpecs
    warnings: list[str] = field(default_factory=list)


def _to_int(value: Any) -> int | None:
    """Safely coerce a CIM numeric field to int or return None."""
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _first_row(rows: Any) -> dict[str, Any]:
    """Return the first CIM row dictionary or an empty dictionary."""
    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
        return rows[0]
    return {}


def get_cpu_info(warnings: list[str] | None = None) -> CpuInfo:
    """Collect real-time CPU usage, core counts, frequencies, and CIM processor metadata."""
    try:
        per_core = psutil.cpu_percent(interval=0.2, percpu=True)
        overall_usage = round(sum(per_core) / len(per_core), 1) if per_core else psutil.cpu_percent(interval=0.1)
    except Exception as exc:
        per_core = []
        overall_usage = None
        if warnings is not None:
            warnings.append(f"CPU utilization check failed: {exc}")

    physical_cores = psutil.cpu_count(logical=False)
    logical_cores = psutil.cpu_count(logical=True)

    current_freq_mhz: float | None = None
    max_freq_mhz: float | None = None
    try:
        freq = psutil.cpu_freq()
        if freq is not None:
            current_freq_mhz = round(freq.current, 1) if freq.current else None
            max_freq_mhz = round(freq.max, 1) if freq.max else None
    except Exception:
        pass

    cim_res = query_cim_result(
        "Win32_Processor",
        properties=[
            "Name",
            "Manufacturer",
            "NumberOfCores",
            "NumberOfLogicalProcessors",
            "MaxClockSpeed",
            "L2CacheSize",
            "L3CacheSize",
            "SocketDesignation",
        ],
    )
    if not cim_res.success and warnings is not None and cim_res.error:
        warnings.append(f"Processor CIM metadata unavailable: {cim_res.error}")

    row = _first_row(cim_res.data)
    processor_name = safe_str(row.get("Name") or platform.processor())
    manufacturer = safe_str(row.get("Manufacturer"))
    cim_max_clock = _to_int(row.get("MaxClockSpeed"))
    if max_freq_mhz is None and cim_max_clock is not None:
        max_freq_mhz = float(cim_max_clock)

    if physical_cores is None:
        physical_cores = _to_int(row.get("NumberOfCores"))
    if logical_cores is None:
        logical_cores = _to_int(row.get("NumberOfLogicalProcessors"))

    return CpuInfo(
        processor_name=processor_name,
        manufacturer=manufacturer,
        architecture=safe_str(platform.machine()),
        physical_cores=physical_cores,
        logical_cores=logical_cores,
        current_freq_mhz=current_freq_mhz,
        max_freq_mhz=max_freq_mhz,
        usage_percent=overall_usage,
        per_core_percent=[round(val, 1) for val in per_core],
        l2_cache_kb=_to_int(row.get("L2CacheSize")),
        l3_cache_kb=_to_int(row.get("L3CacheSize")),
        socket_designation=safe_str(row.get("SocketDesignation")),
        status=classify_utilization(overall_usage, CPU_WARNING_THRESHOLD, CPU_CRITICAL_THRESHOLD),
    )


def get_memory_info(warnings: list[str] | None = None) -> MemoryInfo:
    """Collect RAM, swap, and physical memory module specifications."""
    try:
        vm = psutil.virtual_memory()
        total_bytes: int | None = int(vm.total)
        available_bytes: int | None = int(vm.available)
        used_bytes: int | None = int(vm.used)
        percent_used: float | None = round(float(vm.percent), 1)
    except Exception as exc:
        total_bytes = available_bytes = used_bytes = None
        percent_used = None
        if warnings is not None:
            warnings.append(f"Virtual memory telemetry unavailable: {exc}")

    try:
        swap = psutil.swap_memory()
        swap_total_bytes: int | None = int(swap.total)
        swap_used_bytes: int | None = int(swap.used)
        swap_percent: float | None = round(float(swap.percent), 1)
    except Exception:
        swap_total_bytes = swap_used_bytes = None
        swap_percent = None

    modules: list[MemoryModuleInfo] = []
    cim_res = query_cim_result(
        "Win32_PhysicalMemory",
        properties=[
            "DeviceLocator",
            "Manufacturer",
            "Capacity",
            "Speed",
            "ConfiguredClockSpeed",
            "SMBIOSMemoryType",
            "MemoryType",
            "PartNumber",
        ],
    )
    if not cim_res.success and warnings is not None and cim_res.error:
        warnings.append(f"Physical memory module details unavailable: {cim_res.error}")

    for row in cim_res.data or []:
        cap_bytes = _to_int(row.get("Capacity"))
        speed = _to_int(row.get("ConfiguredClockSpeed")) or _to_int(row.get("Speed"))
        mem_code = _to_int(row.get("SMBIOSMemoryType")) or _to_int(row.get("MemoryType"))
        mem_type = _SMBIOS_MEMORY_TYPES.get(mem_code, UNKNOWN_VALUE) if mem_code else UNKNOWN_VALUE
        modules.append(
            MemoryModuleInfo(
                slot=safe_str(row.get("DeviceLocator")),
                manufacturer=safe_str(row.get("Manufacturer")),
                capacity_bytes=cap_bytes,
                capacity_display=format_bytes(cap_bytes, fallback=UNKNOWN_VALUE),
                speed_mhz=speed,
                memory_type=mem_type,
                part_number=safe_str(row.get("PartNumber")),
            )
        )

    return MemoryInfo(
        total_bytes=total_bytes,
        available_bytes=available_bytes,
        used_bytes=used_bytes,
        percent_used=percent_used,
        swap_total_bytes=swap_total_bytes,
        swap_used_bytes=swap_used_bytes,
        swap_percent=swap_percent,
        modules=modules,
        status=classify_utilization(percent_used, RAM_WARNING_THRESHOLD, RAM_CRITICAL_THRESHOLD),
    )


def get_disk_info(
    warnings: list[str] | None = None,
) -> tuple[list[LogicalDiskInfo], list[PhysicalDiskInfo]]:
    """Collect logical partition capacities and physical storage drive metadata."""
    logical_disks: list[LogicalDiskInfo] = []
    try:
        partitions = psutil.disk_partitions(all=False)
    except Exception as exc:
        partitions = []
        if warnings is not None:
            warnings.append(f"Unable to enumerate disk partitions: {exc}")

    for part in partitions:
        # Skip empty optical drives or unformatted removable slots gracefully.
        if "cdrom" in part.opts.lower() and not part.fstype:
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
            percent_used = round(float(usage.percent), 1)
            logical_disks.append(
                LogicalDiskInfo(
                    device=safe_str(part.device),
                    mountpoint=safe_str(part.mountpoint),
                    fstype=safe_str(part.fstype),
                    total_bytes=int(usage.total),
                    used_bytes=int(usage.used),
                    free_bytes=int(usage.free),
                    percent_used=percent_used,
                    status=classify_utilization(
                        percent_used,
                        DISK_WARNING_THRESHOLD,
                        DISK_CRITICAL_THRESHOLD,
                    ),
                )
            )
        except (PermissionError, OSError) as exc:
            if warnings is not None:
                warnings.append(f"Disk '{part.mountpoint}' skipped: {exc}")

    physical_disks: list[PhysicalDiskInfo] = []
    cim_res = query_cim_result(
        "Win32_DiskDrive",
        properties=["Model", "InterfaceType", "MediaType", "Size", "SerialNumber", "Status"],
    )
    if not cim_res.success and warnings is not None and cim_res.error:
        warnings.append(f"Physical disk CIM metadata unavailable: {cim_res.error}")

    for row in cim_res.data or []:
        size_bytes = _to_int(row.get("Size"))
        physical_disks.append(
            PhysicalDiskInfo(
                model=safe_str(row.get("Model")),
                interface_type=safe_str(row.get("InterfaceType")),
                media_type=safe_str(row.get("MediaType")),
                size_bytes=size_bytes,
                size_display=format_bytes(size_bytes, fallback=UNKNOWN_VALUE),
                serial_number=safe_str(row.get("SerialNumber")),
                status=safe_str(row.get("Status")),
            )
        )

    return logical_disks, physical_disks


def get_battery_info() -> BatteryInfo:
    """Collect battery status, reporting Unavailable cleanly on desktops or VMs."""
    try:
        battery = psutil.sensors_battery()
    except Exception:
        battery = None

    if battery is None:
        return BatteryInfo(
            present=False,
            percent=None,
            power_plugged=None,
            secs_left=None,
            time_left_display=UNAVAILABLE_VALUE,
            status=UNAVAILABLE_VALUE,
        )

    percent = round(float(battery.percent), 1) if battery.percent is not None else None
    plugged = battery.power_plugged
    secs = battery.secsleft

    if plugged:
        time_left_display = "AC Power Connected"
    elif secs in (psutil.POWER_TIME_UNKNOWN, psutil.POWER_TIME_UNLIMITED, None) or secs < 0:
        time_left_display = UNKNOWN_VALUE
    else:
        time_left_display = format_uptime(secs)

    if plugged:
        status = "Healthy"
    elif percent is not None and percent <= 15.0:
        status = "Critical"
    elif percent is not None and percent <= 30.0:
        status = "Warning"
    elif percent is not None:
        status = "Healthy"
    else:
        status = UNKNOWN_VALUE

    return BatteryInfo(
        present=True,
        percent=percent,
        power_plugged=plugged,
        secs_left=secs if isinstance(secs, int) and secs >= 0 else None,
        time_left_display=time_left_display,
        status=status,
    )


def get_system_specs(warnings: list[str] | None = None) -> SystemSpecs:
    """Collect system model, BIOS, and baseboard hardware specifications."""
    cs_res = query_cim_result(
        "Win32_ComputerSystem",
        properties=["Name", "Manufacturer", "Model", "SystemType"],
    )
    bios_res = query_cim_result(
        "Win32_BIOS",
        properties=["Manufacturer", "SMBIOSBIOSVersion", "SerialNumber", "ReleaseDate"],
    )
    board_res = query_cim_result(
        "Win32_BaseBoard",
        properties=["Manufacturer", "Product"],
    )

    if warnings is not None:
        for label, res in (
            ("ComputerSystem", cs_res),
            ("BIOS", bios_res),
            ("BaseBoard", board_res),
        ):
            if not res.success and res.error:
                warnings.append(f"{label} CIM query unavailable: {res.error}")

    cs_row = _first_row(cs_res.data)
    bios_row = _first_row(bios_res.data)
    board_row = _first_row(board_res.data)

    return SystemSpecs(
        hostname=safe_str(cs_row.get("Name") or socket.gethostname()),
        manufacturer=safe_str(cs_row.get("Manufacturer")),
        model=safe_str(cs_row.get("Model")),
        system_type=safe_str(cs_row.get("SystemType") or platform.machine()),
        serial_number=safe_str(bios_row.get("SerialNumber")),
        bios_vendor=safe_str(bios_row.get("Manufacturer")),
        bios_version=safe_str(bios_row.get("SMBIOSBIOSVersion")),
        bios_release_date=format_cim_date(bios_row.get("ReleaseDate")),
        baseboard_manufacturer=safe_str(board_row.get("Manufacturer")),
        baseboard_product=safe_str(board_row.get("Product")),
    )


def collect_hardware_snapshot() -> HardwareSnapshot:
    """Gather all read-only hardware diagnostic telemetry in a single snapshot."""
    warnings: list[str] = []
    cpu = get_cpu_info(warnings=warnings)
    memory = get_memory_info(warnings=warnings)
    logical_disks, physical_disks = get_disk_info(warnings=warnings)
    battery = get_battery_info()
    system_specs = get_system_specs(warnings=warnings)

    return HardwareSnapshot(
        collected_at=format_timestamp(time.time()),
        cpu=cpu,
        memory=memory,
        logical_disks=logical_disks,
        physical_disks=physical_disks,
        battery=battery,
        system_specs=system_specs,
        warnings=warnings,
    )
