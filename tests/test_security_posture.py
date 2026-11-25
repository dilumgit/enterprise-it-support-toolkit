"""Unit tests for the Information Security baseline assessment service."""

from __future__ import annotations

from unittest.mock import patch

from src.config.settings import UNAVAILABLE_VALUE
from src.services.security_posture import (
    BitLockerVolumeStatus,
    DefenderStatus,
    FirewallProfileStatus,
    HotfixItem,
    RegisteredAntivirusInfo,
    UacStatus,
    collect_security_snapshot,
    evaluate_security_findings,
    get_bitlocker_status,
    get_defender_status,
    get_firewall_profiles,
    get_hotfix_history,
    get_registered_antivirus,
    get_uac_status,
)
from src.utils.powershell import PowerShellResult


def test_get_firewall_profiles_parses_enabled_and_disabled() -> None:
    ps_res = PowerShellResult(
        success=True,
        data=[
            {"Name": "Domain", "Enabled": "True", "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"},
            {"Name": "Private", "Enabled": "False", "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"},
        ],
        raw_output="",
    )
    with (
        patch("src.services.security_posture.is_windows", return_value=True),
        patch("src.services.security_posture.run_powershell_json", return_value=ps_res),
    ):
        profiles = get_firewall_profiles()

    assert len(profiles) == 2
    assert profiles[0].enabled is True
    assert profiles[0].status_display == "Enabled"
    assert profiles[1].enabled is False
    assert profiles[1].status_display == "Disabled"


def test_get_defender_status_and_failure_fallback() -> None:
    ps_ok = PowerShellResult(
        success=True,
        data={
            "AMServiceEnabled": True,
            "AntivirusEnabled": True,
            "RealTimeProtectionEnabled": True,
            "AntispywareEnabled": True,
            "AntivirusSignatureVersion": "1.463.457.0",
            "AntivirusSignatureLastUpdated": "2026-11-24 10:00:00",
            "QuickScanEndTime": "2026-11-24 08:00:00",
        },
        raw_output="",
    )
    with (
        patch("src.services.security_posture.is_windows", return_value=True),
        patch("src.services.security_posture.run_powershell_json", return_value=ps_ok),
    ):
        defender = get_defender_status()
    assert defender.available is True
    assert defender.status_display == "Healthy"
    assert defender.signature_version == "1.463.457.0"

    ps_fail = PowerShellResult(success=False, data=None, raw_output="", error="Access denied")
    warnings: list[str] = []
    with (
        patch("src.services.security_posture.is_windows", return_value=True),
        patch("src.services.security_posture.run_powershell_json", return_value=ps_fail),
    ):
        defender_fail = get_defender_status(warnings=warnings)
    assert defender_fail.available is False
    assert defender_fail.status_display == UNAVAILABLE_VALUE
    assert warnings


def test_get_registered_antivirus_decodes_product_state() -> None:
    cim_ok = PowerShellResult(
        success=True,
        data=[
            {"displayName": "Windows Defender", "productState": 397568, "timestamp": "Tue, 24 Nov 2026 05:46:09 GMT"},
            {"displayName": "ThirdParty AV", "productState": 270352, "timestamp": "Fri, 13 Feb 2026 16:57:02 GMT"},
        ],
        raw_output="",
    )
    with patch("src.services.security_posture.query_cim_result", return_value=cim_ok):
        avs = get_registered_antivirus()

    assert len(avs) == 2
    assert avs[0].enabled_state == "Enabled"
    assert avs[0].signature_state == "Up to Date"
    assert avs[1].enabled_state == "Disabled / Snoozed"
    assert avs[1].signature_state == "Out of Date"


def test_get_hotfix_history_formats_dates() -> None:
    ps_ok = PowerShellResult(
        success=True,
        data=[
            {
                "HotFixID": "KB5044033",
                "Description": "Security Update",
                "InstalledOn": "2024-11-23",
                "InstalledBy": "NT AUTHORITY\\SYSTEM",
            }
        ],
        raw_output="",
    )
    with (
        patch("src.services.security_posture.is_windows", return_value=True),
        patch("src.services.security_posture.run_powershell_json", return_value=ps_ok),
    ):
        hotfixes = get_hotfix_history()

    assert len(hotfixes) == 1
    assert hotfixes[0].hotfix_id == "KB5044033"
    assert hotfixes[0].installed_on == "2024-11-23"


def test_get_uac_status_levels() -> None:
    with (
        patch("src.services.security_posture.is_windows", return_value=True),
        patch(
            "src.services.security_posture.run_powershell_json",
            return_value=PowerShellResult(
                success=True,
                data={"EnableLUA": 1, "ConsentPromptBehaviorAdmin": 5, "PromptOnSecureDesktop": 1},
                raw_output="",
            ),
        ),
    ):
        uac_ok = get_uac_status()
    assert uac_ok.status == "Healthy"

    with (
        patch("src.services.security_posture.is_windows", return_value=True),
        patch(
            "src.services.security_posture.run_powershell_json",
            return_value=PowerShellResult(
                success=True,
                data={"EnableLUA": 1, "ConsentPromptBehaviorAdmin": 0, "PromptOnSecureDesktop": 0},
                raw_output="",
            ),
        ),
    ):
        uac_warn = get_uac_status()
    assert uac_warn.status == "Warning"

    with (
        patch("src.services.security_posture.is_windows", return_value=True),
        patch(
            "src.services.security_posture.run_powershell_json",
            return_value=PowerShellResult(
                success=True,
                data={"EnableLUA": 0, "ConsentPromptBehaviorAdmin": 0, "PromptOnSecureDesktop": 0},
                raw_output="",
            ),
        ),
    ):
        uac_crit = get_uac_status()
    assert uac_crit.status == "Critical"


def test_get_bitlocker_status_handles_restricted_and_accessible() -> None:
    ps_restricted = PowerShellResult(
        success=True,
        data={"Available": False, "Reason": "Access is denied.", "Volumes": []},
        raw_output="",
    )
    with (
        patch("src.services.security_posture.is_windows", return_value=True),
        patch("src.services.security_posture.run_powershell_json", return_value=ps_restricted),
    ):
        vols, note = get_bitlocker_status()
    assert vols == []
    assert "Unavailable" in note

    ps_ok = PowerShellResult(
        success=True,
        data={
            "Available": True,
            "Reason": None,
            "Volumes": [
                {
                    "MountPoint": "C:",
                    "ProtectionStatus": "On",
                    "VolumeStatus": "FullyEncrypted",
                    "EncryptionPercentage": 100,
                }
            ],
        },
        raw_output="",
    )
    with (
        patch("src.services.security_posture.is_windows", return_value=True),
        patch("src.services.security_posture.run_powershell_json", return_value=ps_ok),
    ):
        vols_ok, note_ok = get_bitlocker_status()
    assert len(vols_ok) == 1
    assert vols_ok[0].protection_status == "On"
    assert note_ok == "Accessible"


def test_evaluate_security_findings_flags_critical_issues() -> None:
    findings = evaluate_security_findings(
        firewall_profiles=[
            FirewallProfileStatus("Domain", False, "Disabled", "Block", "Allow"),
        ],
        defender=DefenderStatus(True, True, False, False, True, "1.0", "2026-11-24", "Unknown", "Warning"),
        registered_av=[RegisteredAntivirusInfo("TestAV", "Disabled / Snoozed", "Out of Date", "0x000010", "now")],
        hotfixes=[HotfixItem("KB5000001", "Update", "2026-11-01", "SYSTEM")],
        uac=UacStatus(True, 0, 0, 0, "UAC disabled", "Critical"),
        bitlocker_volumes=[BitLockerVolumeStatus("C:", "Off", "FullyDecrypted", "0%")],
        bitlocker_note="Accessible",
    )
    categories = {f.category for f in findings}
    assert {"Firewall", "Antivirus", "Access Control", "Encryption"}.issubset(categories)


def test_collect_security_snapshot_live_smoke() -> None:
    snap = collect_security_snapshot(include_hotfixes=False)
    assert snap.collected_at
    assert "does not guarantee" in snap.disclaimer.lower()
    assert isinstance(snap.findings, list)
    assert len(snap.findings) >= 1
