"""Unit tests for the centralized Technical Reporting service."""

from __future__ import annotations

from pathlib import Path

from src.services.asset_service import create_asset, create_software_license
from src.services.hardware_diagnostics import (
    BatteryInfo,
    CpuInfo,
    HardwareSnapshot,
    LogicalDiskInfo,
    MemoryInfo,
    SystemSpecs,
)
from src.services.helpdesk_service import create_ticket
from src.services.network_diagnostics import NetworkAdapterInfo, NetworkSnapshot, WifiInfo
from src.services.reporting_service import REPORT_TYPES, build_report, generate_report
from src.services.security_posture import (
    BitLockerVolumeStatus,
    DefenderStatus,
    FirewallProfileStatus,
    RegisteredAntivirusInfo,
    SecuritySnapshot,
    UacStatus,
)
from src.services.system_info import OsInfo


def _sample_hw() -> HardwareSnapshot:
    return HardwareSnapshot(
        collected_at="2026-11-25 07:30:00",
        cpu=CpuInfo("Intel Core i7", "GenuineIntel", "AMD64", 8, 16, 3200.0, 4200.0, 35.0, [35.0], 4096, 16384, "U3E1", "Healthy"),
        memory=MemoryInfo(32 * 1024**3, 18 * 1024**3, 14 * 1024**3, 43.8, 4 * 1024**3, 0, 0.0, [], "Healthy"),
        logical_disks=[LogicalDiskInfo("C:\\", "C:\\", "NTFS", 500 * 1024**3, 250 * 1024**3, 250 * 1024**3, 50.0, "Healthy")],
        physical_disks=[],
        battery=BatteryInfo(True, 90.0, True, None, "AC Power Connected", "Healthy"),
        system_specs=SystemSpecs("FIN-WS-999", "Lenovo", "ThinkPad", "x64", "SN-SECRET-888", "Lenovo", "1.0", "2025-01-01", "Lenovo", "Board"),
    )


def _sample_os() -> OsInfo:
    return OsInfo(
        "Windows 11 Enterprise",
        "10.0.22621",
        "22621",
        "64-bit",
        "FIN-WS-999",
        "FIN-WS-999.fincorp.internal",
        "j.analyst",
        "FINCORP",
        1_700_000_000.0,
        "2026-11-24 07:30:00",
        86400.0,
        "1d 00h 00m 00s",
        "2025-02-01",
        "FinCorp",
    )


def _sample_net() -> NetworkSnapshot:
    adapter = NetworkAdapterInfo(
        "WiFi",
        "Intel Wireless",
        "Up",
        600,
        1500,
        "02:00:00:00:00:01",
        ["10.20.30.40 / 255.255.255.0"],
        ["fe80::1a2b:3c4d:5e6f"],
        ["10.20.30.1"],
        ["10.20.0.10"],
        1024,
        2048,
        10,
        20,
        0,
        0,
    )
    wifi = WifiInfo(True, "WiFi", "Connected", "Corp-WiFi", "AA:BB:CC:DD:EE:FF", "802.11ax", "WPA2", "CCMP", "5 GHz", "36", 85, "600", "600", "Healthy")
    return NetworkSnapshot("2026-11-25 07:30:00", [adapter], ["10.20.30.1"], ["10.20.0.10"], 1024, 2048, wifi, [])


def _sample_sec() -> SecuritySnapshot:
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


def test_all_eight_report_types_build_with_empty_and_complete_data() -> None:
    for key, label in REPORT_TYPES:
        empty_report = build_report(key)
        assert empty_report.report_id.startswith("RPT-")
        assert empty_report.title == label
        assert empty_report.csv_content
        assert "<!DOCTYPE html>" in empty_report.html_content

        populated = build_report(
            key,
            hardware_snapshot=_sample_hw(),
            os_info=_sample_os(),
            network_snapshot=_sample_net(),
            security_snapshot=_sample_sec(),
        )
        assert populated.title == label
        assert populated.csv_content


def test_html_report_escapes_injection_and_contains_no_scripts_or_external_urls() -> None:
    xss_payload = "<script>alert('xss')</script><img src=x onerror=alert(1)>"
    ticket = build_report(
        "helpdesk",
        tickets=[],
    )
    assert "<script" not in ticket.html_content.lower()

    # Create a ticket with XSS payload via Help Desk dataclass structure
    from src.services.helpdesk_service import Ticket

    malicious_ticket = Ticket(
        ticket_id="INC-XSS-0001",
        ticket_type="Incident",
        title=xss_payload,
        description="desc",
        requester_name="<b>Bob</b>",
        department="IT",
        category="Security",
        priority="High",
        status="Open",
        assigned_technician="Analyst",
        troubleshooting_notes="",
        resolution_notes="",
        is_demo=False,
        created_at="2026-11-25 07:30:00",
        updated_at="2026-11-25 07:30:00",
        resolved_at=None,
    )
    rpt = build_report("helpdesk", tickets=[malicious_ticket])
    lowered = rpt.html_content.lower()
    assert "<script" not in lowered
    assert "http://" not in lowered
    assert "https://" not in lowered
    assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in rpt.html_content


def test_privacy_safe_redaction_scrubs_pii_and_network_identifiers(tmp_path: Path) -> None:
    db = tmp_path / "rpt_priv.db"
    ticket = create_ticket(
        ticket_type="Incident",
        title="Workstation issue on FIN-WS-999 for j.analyst@fincorp.internal in C:\\Users\\j.analyst",
        description="User FINCORP\\j.analyst cannot reach 10.20.30.1",
        requester_name="Jordan Blake",
        department="Treasury",
        category="Network",
        priority="High",
        assigned_technician="Tier 2 Analyst",
        db_path=db,
    )
    asset = create_asset(
        asset_name="FIN-WS-999",
        category="Laptop",
        manufacturer="Lenovo",
        model="ThinkPad",
        serial_number="SN-SECRET-888",
        assigned_employee="Jordan Blake",
        department="Treasury",
        db_path=db,
    )
    rpt = build_report(
        "comprehensive",
        privacy_redacted=True,
        hardware_snapshot=_sample_hw(),
        os_info=_sample_os(),
        network_snapshot=_sample_net(),
        security_snapshot=_sample_sec(),
        tickets=[ticket],
        assets=[asset],
    )

    for payload in (rpt.csv_content, rpt.html_content):
        assert "FIN-WS-999" not in payload
        assert "j.analyst" not in payload
        assert "j.analyst@fincorp.internal" not in payload
        assert "SN-SECRET-888" not in payload
        assert "02:00:00:00:00:01" not in payload
        assert "10.20.30.40" not in payload
        assert "10.20.30.1" not in payload
        assert "Jordan Blake" not in payload
        assert "[REDACTED" in payload


def test_csv_formula_injection_neutralized_in_reports() -> None:
    from src.services.helpdesk_service import Ticket

    t = Ticket(
        ticket_id="INC-CSV-1",
        ticket_type="Incident",
        title="=SUM(1,2)",
        description="desc",
        requester_name="User",
        department="IT",
        category="Other",
        priority="Low",
        status="Open",
        assigned_technician="Tech",
        troubleshooting_notes="",
        resolution_notes="",
        is_demo=False,
        created_at="2026-11-25 07:30:00",
        updated_at="2026-11-25 07:30:00",
        resolved_at=None,
    )
    rpt = build_report("helpdesk", tickets=[t])
    assert "'=SUM(1,2)" in rpt.csv_content


def test_generate_report_from_temp_sqlite_for_helpdesk_assets_licenses(tmp_path: Path) -> None:
    db = tmp_path / "rpt_db.db"
    create_ticket(
        ticket_type="Incident",
        title="Printer offline",
        description="Paper jam cleared, spooler checked",
        requester_name="Alex",
        department="Ops",
        category="Hardware",
        priority="Low",
        db_path=db,
    )
    create_asset(
        asset_name="PRT-01",
        category="Printer",
        manufacturer="HP",
        model="LaserJet",
        db_path=db,
    )
    create_software_license(
        software_name="Office Suite",
        vendor="Microsoft",
        license_type="Subscription",
        quantity=10,
        assigned_count=5,
        db_path=db,
    )

    r_hd = generate_report("helpdesk", db_path=db)
    r_as = generate_report("assets", db_path=db)
    r_lic = generate_report("licenses", db_path=db)

    assert "Printer offline" in r_hd.csv_content
    assert "PRT-01" in r_as.csv_content
    assert "Office Suite" in r_lic.csv_content
