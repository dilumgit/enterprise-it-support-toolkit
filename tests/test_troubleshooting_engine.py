"""Unit tests for the centralized rule-based Troubleshooting Assistant engine."""

from __future__ import annotations

from pathlib import Path

from src.config.settings import UNAVAILABLE_VALUE, UNKNOWN_VALUE
from src.services.hardware_diagnostics import (
    BatteryInfo,
    CpuInfo,
    HardwareSnapshot,
    LogicalDiskInfo,
    MemoryInfo,
    SystemSpecs,
)
from src.services.helpdesk_service import get_ticket
from src.services.network_diagnostics import (
    ConnectivityProbeResult,
    DnsResolutionResult,
    NetworkAdapterInfo,
    NetworkSnapshot,
    PingResult,
    WifiInfo,
)
from src.services.security_posture import (
    BitLockerVolumeStatus,
    DefenderStatus,
    FirewallProfileStatus,
    RegisteredAntivirusInfo,
    SecuritySnapshot,
    UacStatus,
)
from src.services.system_info import OsInfo, ProcessInfo
from src.services.troubleshooting_engine import (
    create_ticket_from_finding,
    evaluate_troubleshooting_rules,
    run_troubleshooting_assessment,
)


def _healthy_hw() -> HardwareSnapshot:
    return HardwareSnapshot(
        collected_at="2026-11-25 07:30:00",
        cpu=CpuInfo("Intel Xeon", "GenuineIntel", "AMD64", 8, 16, 3400.0, 3900.0, 22.0, [20.0, 24.0], 8192, 16384, "LGA", "Healthy"),
        memory=MemoryInfo(32 * 1024**3, 20 * 1024**3, 12 * 1024**3, 37.5, 4 * 1024**3, 0, 0.0, [], "Healthy"),
        logical_disks=[LogicalDiskInfo("C:\\", "C:\\", "NTFS", 500 * 1024**3, 200 * 1024**3, 300 * 1024**3, 40.0, "Healthy")],
        physical_disks=[],
        battery=BatteryInfo(False, None, None, None, UNAVAILABLE_VALUE, UNAVAILABLE_VALUE),
        system_specs=SystemSpecs("FIN-HOST-01", "Dell", "OptiPlex", "x64", "SN123", "Dell", "1.2", "2025-01-01", "Dell", "Board"),
    )


def _healthy_os(uptime_days: float = 2.0) -> OsInfo:
    return OsInfo(
        "Windows 11 Enterprise",
        "10.0.22621",
        "22621",
        "64-bit",
        "FIN-HOST-01",
        "FIN-HOST-01.corp.local",
        "analyst",
        "CORP",
        1_700_000_000.0,
        "2026-11-23 07:30:00",
        uptime_days * 86400.0,
        f"{int(uptime_days)}d 00h 00m 00s",
        "2025-01-01",
        "FinCorp",
    )


def _healthy_net() -> NetworkSnapshot:
    adapter = NetworkAdapterInfo(
        "Ethernet",
        "Intel NIC",
        "Up",
        1000,
        1500,
        "AA:BB:CC:DD:EE:FF",
        ["10.10.1.25 / 255.255.255.0"],
        [],
        ["10.10.1.1"],
        ["10.10.0.10"],
        1000,
        2000,
        10,
        20,
        0,
        0,
    )
    wifi = WifiInfo(False, UNAVAILABLE_VALUE, UNAVAILABLE_VALUE, UNAVAILABLE_VALUE, UNAVAILABLE_VALUE, UNAVAILABLE_VALUE, UNAVAILABLE_VALUE, UNAVAILABLE_VALUE, UNAVAILABLE_VALUE, UNAVAILABLE_VALUE, None, UNAVAILABLE_VALUE, UNAVAILABLE_VALUE, UNAVAILABLE_VALUE)
    return NetworkSnapshot("2026-11-25 07:30:00", [adapter], ["10.10.1.1"], ["10.10.0.10"], 1000, 2000, wifi, [])


def _healthy_sec() -> SecuritySnapshot:
    return SecuritySnapshot(
        collected_at="2026-11-25 07:30:00",
        firewall_profiles=[FirewallProfileStatus("Domain", True, "Enabled", "Block", "Allow")],
        defender=DefenderStatus(True, True, True, True, True, "1.463.1.0", "2026-11-25 06:00:00", "2026-11-25 05:00:00", "Healthy"),
        registered_antivirus=[RegisteredAntivirusInfo("Windows Defender", "Enabled", "Up to Date", "0x061100", "now")],
        hotfixes=[],
        uac=UacStatus(True, 1, 5, 1, "UAC enabled", "Healthy"),
        bitlocker_volumes=[BitLockerVolumeStatus("C:", "On", "FullyEncrypted", "100%")],
        bitlocker_status_note="Accessible",
        findings=[],
    )


def test_normal_healthy_telemetry_returns_informational_finding() -> None:
    res = evaluate_troubleshooting_rules(
        hardware_snapshot=_healthy_hw(),
        os_info=_healthy_os(1.5),
        processes=[ProcessInfo(123, "explorer.exe", "CORP\\analyst", "running", 1.2, 120.0, 0.4)],
        network_snapshot=_healthy_net(),
        security_snapshot=_healthy_sec(),
        connectivity_result=ConnectivityProbeResult(True, "ok", [], None, "Connected", "All good", "2026-11-25 07:30:00"),
    )
    assert len(res.findings) == 1
    assert res.findings[0].finding_id == "TRB-GEN-HEALTHY"
    assert res.findings[0].severity == "Informational"


def test_critical_and_cross_module_performance_scenarios() -> None:
    hw = HardwareSnapshot(
        collected_at="2026-11-25 07:30:00",
        cpu=CpuInfo("Intel Xeon", "GenuineIntel", "AMD64", 8, 16, 3400.0, 3900.0, 94.5, [95.0, 94.0], 8192, 16384, "LGA", "Critical"),
        memory=MemoryInfo(16 * 1024**3, 1 * 1024**3, 15 * 1024**3, 93.8, 4 * 1024**3, 2 * 1024**3, 50.0, [], "Critical"),
        logical_disks=[LogicalDiskInfo("C:\\", "C:\\", "NTFS", 256 * 1024**3, 240 * 1024**3, 16 * 1024**3, 93.7, "Critical")],
        physical_disks=[],
        battery=BatteryInfo(False, None, None, None, UNAVAILABLE_VALUE, UNAVAILABLE_VALUE),
        system_specs=SystemSpecs("FIN-HOST-01", "Dell", "OptiPlex", "x64", "SN123", "Dell", "1.2", "2025-01-01", "Dell", "Board"),
    )
    procs = [ProcessInfo(4200, "python.exe", "CORP\\analyst", "running", 55.0, 2400.0, 15.0)]
    res = evaluate_troubleshooting_rules(
        categories=("Hardware", "System"),
        hardware_snapshot=hw,
        os_info=_healthy_os(uptime_days=20.0),
        processes=procs,
    )
    ids = {f.finding_id for f in res.findings}
    assert "TRB-HW-CPU-CRIT" in ids
    assert "TRB-HW-RAM-CRIT" in ids
    assert "TRB-HW-DISK-C" in ids
    assert "TRB-SYS-PROC-HOG" in ids
    assert "TRB-SYS-UPTIME" in ids
    assert "TRB-XMOD-PERF" in ids


def test_network_rules_distinguish_gateway_dns_wifi_latency_and_icmp() -> None:
    adapter = NetworkAdapterInfo("WiFi", "Intel Wi-Fi", "Up", 300, 1500, "AA:BB:CC:DD:EE:FF", ["192.168.1.50 / 255.255.255.0"], [], [], [], 10, 20, 1, 2, 0, 0)
    wifi = WifiInfo(True, "WiFi", "Connected", "Office-5G", "11:22:33:44:55:66", "802.11ac", "WPA2", "CCMP", "5 GHz", "36", 25, "100", "100", "Critical")
    net = NetworkSnapshot("2026-11-25 07:30:00", [adapter], [], [], 10, 20, wifi, [])

    ping_loss = PingResult("1.1.1.1", "1.1.1.1", True, 4, 2, 50.0, 120.0, 180.0, 240.0, None, "", "2026-11-25 07:30:00")
    dns_fail = DnsResolutionResult("intranet.corp", False, [], [], None, "Lookup timed out", "2026-11-25 07:30:00")
    conn_fail = ConnectivityProbeResult(False, "DNS failed", [], None, "DNS Resolution Failure", "DNS failed", "2026-11-25 07:30:00")

    res = evaluate_troubleshooting_rules(
        categories=("Network",),
        network_snapshot=net,
        ping_result=ping_loss,
        dns_result=dns_fail,
        connectivity_result=conn_fail,
    )
    ids = {f.finding_id for f in res.findings}
    assert {"TRB-NET-NOGW", "TRB-NET-NODNS", "TRB-NET-WIFI-WEAK", "TRB-NET-DNS-FAIL", "TRB-NET-LATENCY-LOSS", "TRB-NET-CONN"}.issubset(ids)


def test_security_rules_cover_firewall_av_signatures_uac_and_bitlocker() -> None:
    sec = SecuritySnapshot(
        collected_at="2026-11-25 07:30:00",
        firewall_profiles=[FirewallProfileStatus("Public", False, "Disabled", "Block", "Allow")],
        defender=DefenderStatus(True, True, False, False, True, "1.0", "2026-11-01", "Unknown", "Warning"),
        registered_antivirus=[RegisteredAntivirusInfo("ThirdPartyAV", "Disabled / Snoozed", "Out of Date", "0x000010", "now")],
        hotfixes=[],
        uac=UacStatus(True, 1, 0, 0, "Elevate without prompting", "Warning"),
        bitlocker_volumes=[BitLockerVolumeStatus("C:", "Off", "FullyDecrypted", "0%")],
        bitlocker_status_note="Accessible",
        findings=[],
    )
    res = evaluate_troubleshooting_rules(categories=("Security",), security_snapshot=sec)
    ids = {f.finding_id for f in res.findings}
    assert {"TRB-SEC-FW-OFF", "TRB-SEC-AV-OFF", "TRB-SEC-AV-SIG", "TRB-SEC-UAC-SILENT", "TRB-SEC-BL-OFF"}.issubset(ids)


def test_unavailable_telemetry_handled_gracefully_with_limitations() -> None:
    hw_unavail = HardwareSnapshot(
        collected_at="2026-11-25 07:30:00",
        cpu=CpuInfo(UNKNOWN_VALUE, UNKNOWN_VALUE, "AMD64", None, None, None, None, None, [], None, None, UNKNOWN_VALUE, UNKNOWN_VALUE),
        memory=MemoryInfo(None, None, None, None, None, None, None, [], UNKNOWN_VALUE),
        logical_disks=[],
        physical_disks=[],
        battery=BatteryInfo(False, None, None, None, UNAVAILABLE_VALUE, UNAVAILABLE_VALUE),
        system_specs=SystemSpecs("HOST", UNKNOWN_VALUE, UNKNOWN_VALUE, UNKNOWN_VALUE, UNKNOWN_VALUE, UNKNOWN_VALUE, UNKNOWN_VALUE, UNKNOWN_VALUE, UNKNOWN_VALUE, UNKNOWN_VALUE),
    )
    sec_unavail = SecuritySnapshot(
        collected_at="2026-11-25 07:30:00",
        firewall_profiles=[],
        defender=DefenderStatus(False, None, None, None, None, UNAVAILABLE_VALUE, UNAVAILABLE_VALUE, UNAVAILABLE_VALUE, UNAVAILABLE_VALUE),
        registered_antivirus=[],
        hotfixes=[],
        uac=UacStatus(False, None, None, None, UNAVAILABLE_VALUE, UNAVAILABLE_VALUE),
        bitlocker_volumes=[],
        bitlocker_status_note="Unavailable without elevation",
        findings=[],
    )
    res = evaluate_troubleshooting_rules(
        categories=("Hardware", "Network", "Security"),
        hardware_snapshot=hw_unavail,
        network_snapshot=_healthy_net(),
        security_snapshot=sec_unavail,
    )
    assert len(res.limitations) >= 4
    assert any(f.finding_id == "TRB-SEC-BL-UNAVAIL" for f in res.findings)


def test_create_ticket_from_finding_persists_to_sqlite(tmp_path: Path) -> None:
    db = tmp_path / "trb_helpdesk.db"
    res = evaluate_troubleshooting_rules(
        categories=("Security",),
        security_snapshot=SecuritySnapshot(
            collected_at="2026-11-25 07:30:00",
            firewall_profiles=[FirewallProfileStatus("Domain", False, "Disabled", "Block", "Allow")],
            defender=_healthy_sec().defender,
            registered_antivirus=_healthy_sec().registered_antivirus,
            hotfixes=[],
            uac=_healthy_sec().uac,
            bitlocker_volumes=_healthy_sec().bitlocker_volumes,
            bitlocker_status_note="Accessible",
            findings=[],
        ),
    )
    fw_finding = next(f for f in res.findings if f.finding_id == "TRB-SEC-FW-OFF")
    ticket = create_ticket_from_finding(
        fw_finding,
        requester_name="Desk Analyst",
        department="Risk & Compliance",
        db_path=db,
    )
    stored = get_ticket(ticket.ticket_id, db_path=db)
    assert stored.category == "Security"
    assert stored.priority == "Critical"
    assert "TRB-SEC-FW-OFF" in stored.title


def test_run_troubleshooting_assessment_single_category_smoke() -> None:
    res = run_troubleshooting_assessment(categories=("Hardware",))
    assert res.categories_evaluated == ("Hardware",)
    assert len(res.findings) >= 1
