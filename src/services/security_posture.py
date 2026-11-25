"""Read-only endpoint information security baseline assessment service."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from src.config.settings import (
    HOTFIX_QUERY_TIMEOUT_SECONDS,
    POWERSHELL_TIMEOUT_SECONDS,
    UNAVAILABLE_VALUE,
    UNKNOWN_VALUE,
)
from src.utils.formatting import format_cim_date, format_timestamp, safe_str
from src.utils.powershell import is_windows, query_cim_result, run_powershell_json

SECURITY_ASSESSMENT_DISCLAIMER: str = (
    "These read-only checks evaluate selected local endpoint baseline indicators only. "
    "Passing these checks does not guarantee that the workstation is fully secure, "
    "free of malware, or fully patched against all vulnerabilities."
)

_UAC_PROMPT_LABELS: dict[int, str] = {
    0: "Elevate without prompting",
    1: "Prompt for credentials on secure desktop",
    2: "Always notify (Prompt for consent on secure desktop)",
    3: "Prompt for credentials",
    4: "Prompt for consent",
    5: "Notify only when apps try to make changes (Default)",
}


@dataclass(frozen=True)
class FirewallProfileStatus:
    """Windows Firewall configuration for a single network profile."""

    profile_name: str
    enabled: bool | None
    status_display: str
    default_inbound: str
    default_outbound: str


@dataclass(frozen=True)
class DefenderStatus:
    """Microsoft Defender service, real-time protection, and signature telemetry."""

    available: bool
    am_service_enabled: bool | None
    antivirus_enabled: bool | None
    real_time_protection_enabled: bool | None
    antispyware_enabled: bool | None
    signature_version: str
    signature_last_updated: str
    quick_scan_end_time: str
    status_display: str


@dataclass(frozen=True)
class RegisteredAntivirusInfo:
    """Antivirus product registered with Windows Security Center."""

    display_name: str
    enabled_state: str
    signature_state: str
    raw_state_hex: str
    timestamp: str


@dataclass(frozen=True)
class HotfixItem:
    """Installed Windows Update / HotFix entry."""

    hotfix_id: str
    description: str
    installed_on: str
    installed_by: str


@dataclass(frozen=True)
class UacStatus:
    """User Account Control policy settings from Windows Registry."""

    available: bool
    enable_lua: int | None
    consent_prompt_admin: int | None
    prompt_on_secure_desktop: int | None
    policy_summary: str
    status: str


@dataclass(frozen=True)
class BitLockerVolumeStatus:
    """BitLocker volume encryption status when readable without elevation."""

    mount_point: str
    protection_status: str
    volume_status: str
    encryption_percentage: str


@dataclass(frozen=True)
class SecurityFinding:
    """Rule-based security posture observation and non-destructive guidance."""

    severity: str
    category: str
    title: str
    explanation: str
    recommendations: list[str]


@dataclass(frozen=True)
class SecuritySnapshot:
    """Complete read-only endpoint security baseline snapshot."""

    collected_at: str
    firewall_profiles: list[FirewallProfileStatus]
    defender: DefenderStatus
    registered_antivirus: list[RegisteredAntivirusInfo]
    hotfixes: list[HotfixItem]
    uac: UacStatus
    bitlocker_volumes: list[BitLockerVolumeStatus]
    bitlocker_status_note: str
    findings: list[SecurityFinding]
    disclaimer: str = SECURITY_ASSESSMENT_DISCLAIMER
    warnings: list[str] = field(default_factory=list)


def _to_bool_or_none(value: Any) -> bool | None:
    """Convert bool or stringified boolean ('True'/'False') to bool or None."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
    return None


def _to_int_or_none(value: Any) -> int | None:
    """Safely coerce an integer registry/CIM value or return None."""
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def get_firewall_profiles(warnings: list[str] | None = None) -> list[FirewallProfileStatus]:
    """Read Domain, Private, and Public Windows Firewall profile states."""
    if not is_windows():
        if warnings is not None:
            warnings.append("Windows Firewall checks are unavailable on non-Windows hosts.")
        return []

    script = r"""
$profiles = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
    [PSCustomObject]@{
        Name                  = $_.Name
        Enabled               = $_.Enabled.ToString()
        DefaultInboundAction  = $_.DefaultInboundAction.ToString()
        DefaultOutboundAction = $_.DefaultOutboundAction.ToString()
    }
})
$profiles | ConvertTo-Json -Depth 2 -Compress
"""
    res = run_powershell_json(script, timeout=POWERSHELL_TIMEOUT_SECONDS)
    if not res.success:
        if warnings is not None and res.error:
            warnings.append(f"Windows Firewall telemetry unavailable: {res.error}")
        return []

    rows = res.data if isinstance(res.data, list) else ([res.data] if isinstance(res.data, dict) else [])
    profiles: list[FirewallProfileStatus] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        enabled = _to_bool_or_none(row.get("Enabled"))
        status_display = "Enabled" if enabled is True else ("Disabled" if enabled is False else UNKNOWN_VALUE)
        profiles.append(
            FirewallProfileStatus(
                profile_name=safe_str(row.get("Name")),
                enabled=enabled,
                status_display=status_display,
                default_inbound=safe_str(row.get("DefaultInboundAction")),
                default_outbound=safe_str(row.get("DefaultOutboundAction")),
            )
        )
    return profiles


def get_defender_status(warnings: list[str] | None = None) -> DefenderStatus:
    """Read Microsoft Defender service, real-time protection, and signature status."""
    if not is_windows():
        return DefenderStatus(
            available=False,
            am_service_enabled=None,
            antivirus_enabled=None,
            real_time_protection_enabled=None,
            antispyware_enabled=None,
            signature_version=UNAVAILABLE_VALUE,
            signature_last_updated=UNAVAILABLE_VALUE,
            quick_scan_end_time=UNAVAILABLE_VALUE,
            status_display=UNAVAILABLE_VALUE,
        )

    script = r"""
$st = Get-MpComputerStatus -ErrorAction Stop
[PSCustomObject]@{
    AMServiceEnabled              = $st.AMServiceEnabled
    AntivirusEnabled              = $st.AntivirusEnabled
    RealTimeProtectionEnabled     = $st.RealTimeProtectionEnabled
    AntispywareEnabled            = $st.AntispywareEnabled
    AntivirusSignatureVersion     = $st.AntivirusSignatureVersion
    AntivirusSignatureLastUpdated = if ($st.AntivirusSignatureLastUpdated) { $st.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
    QuickScanEndTime              = if ($st.QuickScanEndTime) { $st.QuickScanEndTime.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
} | ConvertTo-Json -Compress
"""
    res = run_powershell_json(script, timeout=POWERSHELL_TIMEOUT_SECONDS)
    if not res.success or not isinstance(res.data, dict):
        if warnings is not None and res.error:
            warnings.append(f"Microsoft Defender status unavailable: {res.error}")
        return DefenderStatus(
            available=False,
            am_service_enabled=None,
            antivirus_enabled=None,
            real_time_protection_enabled=None,
            antispyware_enabled=None,
            signature_version=UNAVAILABLE_VALUE,
            signature_last_updated=UNAVAILABLE_VALUE,
            quick_scan_end_time=UNAVAILABLE_VALUE,
            status_display=UNAVAILABLE_VALUE,
        )

    row = res.data
    am_enabled = _to_bool_or_none(row.get("AMServiceEnabled"))
    av_enabled = _to_bool_or_none(row.get("AntivirusEnabled"))
    rtp_enabled = _to_bool_or_none(row.get("RealTimeProtectionEnabled"))
    as_enabled = _to_bool_or_none(row.get("AntispywareEnabled"))

    if rtp_enabled is True and av_enabled is True:
        status_display = "Healthy"
    elif av_enabled is False or rtp_enabled is False:
        status_display = "Warning"
    else:
        status_display = UNKNOWN_VALUE

    return DefenderStatus(
        available=True,
        am_service_enabled=am_enabled,
        antivirus_enabled=av_enabled,
        real_time_protection_enabled=rtp_enabled,
        antispyware_enabled=as_enabled,
        signature_version=safe_str(row.get("AntivirusSignatureVersion")),
        signature_last_updated=safe_str(row.get("AntivirusSignatureLastUpdated")),
        quick_scan_end_time=safe_str(row.get("QuickScanEndTime")),
        status_display=status_display,
    )


def _decode_wsc_product_state(raw_state: int | None) -> tuple[str, str, str]:
    """Decode Windows Security Center AntiVirusProduct productState bitflags."""
    if raw_state is None:
        return UNKNOWN_VALUE, UNKNOWN_VALUE, UNKNOWN_VALUE
    hex_str = f"0x{raw_state:06X}"
    enabled_state = "Enabled" if (raw_state & 0x1000) else "Disabled / Snoozed"
    signature_state = "Up to Date" if (raw_state & 0x00F0) == 0 else "Out of Date"
    return enabled_state, signature_state, hex_str


def get_registered_antivirus(warnings: list[str] | None = None) -> list[RegisteredAntivirusInfo]:
    """Query Windows Security Center (root/SecurityCenter2) for registered AV products."""
    cim_res = query_cim_result(
        class_name="AntiVirusProduct",
        properties=["displayName", "productState", "timestamp"],
        namespace="root/SecurityCenter2",
        timeout=POWERSHELL_TIMEOUT_SECONDS,
    )
    if not cim_res.success:
        if warnings is not None and cim_res.error:
            warnings.append(f"Registered antivirus query unavailable: {cim_res.error}")
        return []

    products: list[RegisteredAntivirusInfo] = []
    for row in cim_res.data or []:
        raw_state = _to_int_or_none(row.get("productState"))
        enabled_state, sig_state, hex_str = _decode_wsc_product_state(raw_state)
        products.append(
            RegisteredAntivirusInfo(
                display_name=safe_str(row.get("displayName")),
                enabled_state=enabled_state,
                signature_state=sig_state,
                raw_state_hex=hex_str,
                timestamp=safe_str(row.get("timestamp")),
            )
        )
    return products


def get_hotfix_history(
    limit: int = 40,
    warnings: list[str] | None = None,
) -> list[HotfixItem]:
    """Retrieve recently installed Windows updates/hotfixes in read-only mode."""
    if not is_windows():
        if warnings is not None:
            warnings.append("Windows hotfix history is unavailable on non-Windows hosts.")
        return []

    bounded_limit = max(1, min(int(limit), 100))
    script = f"""
$items = @(Get-HotFix -ErrorAction Stop |
    Sort-Object -Property InstalledOn -Descending |
    Select-Object -First {bounded_limit} |
    ForEach-Object {{
        [PSCustomObject]@{{
            HotFixID    = $_.HotFixID
            Description = $_.Description
            InstalledOn = if ($_.InstalledOn) {{ $_.InstalledOn.ToString('yyyy-MM-dd') }} else {{ $null }}
            InstalledBy = $_.InstalledBy
        }}
    }})
$items | ConvertTo-Json -Depth 2 -Compress
"""
    res = run_powershell_json(script, timeout=HOTFIX_QUERY_TIMEOUT_SECONDS)
    if not res.success:
        if warnings is not None and res.error:
            warnings.append(f"Windows Update/HotFix history unavailable: {res.error}")
        return []

    rows = res.data if isinstance(res.data, list) else ([res.data] if isinstance(res.data, dict) else [])
    hotfixes: list[HotfixItem] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        hotfixes.append(
            HotfixItem(
                hotfix_id=safe_str(row.get("HotFixID")),
                description=safe_str(row.get("Description")),
                installed_on=format_cim_date(row.get("InstalledOn")),
                installed_by=safe_str(row.get("InstalledBy")),
            )
        )
    return hotfixes


def get_uac_status(warnings: list[str] | None = None) -> UacStatus:
    """Read User Account Control (UAC) policy keys from Windows Registry."""
    if not is_windows():
        return UacStatus(
            available=False,
            enable_lua=None,
            consent_prompt_admin=None,
            prompt_on_secure_desktop=None,
            policy_summary=UNAVAILABLE_VALUE,
            status=UNAVAILABLE_VALUE,
        )

    script = r"""
$path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$props = Get-ItemProperty -Path $path -ErrorAction Stop
[PSCustomObject]@{
    EnableLUA                  = $props.EnableLUA
    ConsentPromptBehaviorAdmin = $props.ConsentPromptBehaviorAdmin
    PromptOnSecureDesktop      = $props.PromptOnSecureDesktop
} | ConvertTo-Json -Compress
"""
    res = run_powershell_json(script, timeout=POWERSHELL_TIMEOUT_SECONDS)
    if not res.success or not isinstance(res.data, dict):
        if warnings is not None and res.error:
            warnings.append(f"UAC registry policy unavailable: {res.error}")
        return UacStatus(
            available=False,
            enable_lua=None,
            consent_prompt_admin=None,
            prompt_on_secure_desktop=None,
            policy_summary=UNAVAILABLE_VALUE,
            status=UNAVAILABLE_VALUE,
        )

    row = res.data
    enable_lua = _to_int_or_none(row.get("EnableLUA"))
    consent = _to_int_or_none(row.get("ConsentPromptBehaviorAdmin"))
    secure_desktop = _to_int_or_none(row.get("PromptOnSecureDesktop"))

    if enable_lua == 0:
        status = "Critical"
        summary = "UAC is disabled (EnableLUA = 0)"
    elif enable_lua == 1 and consent == 0:
        status = "Warning"
        summary = f"UAC enabled, but Admin Approval Mode is set to: {_UAC_PROMPT_LABELS.get(0)}"
    elif enable_lua == 1:
        status = "Healthy"
        prompt_desc = _UAC_PROMPT_LABELS.get(consent, UNKNOWN_VALUE) if consent is not None else UNKNOWN_VALUE
        summary = f"UAC enabled ({prompt_desc})"
    else:
        status = UNKNOWN_VALUE
        summary = UNKNOWN_VALUE

    return UacStatus(
        available=True,
        enable_lua=enable_lua,
        consent_prompt_admin=consent,
        prompt_on_secure_desktop=secure_desktop,
        policy_summary=summary,
        status=status,
    )


def get_bitlocker_status(warnings: list[str] | None = None) -> tuple[list[BitLockerVolumeStatus], str]:
    """
    Check BitLocker encryption status when permitted without elevation.

    Gracefully returns Unavailable if the BitLocker PowerShell module is absent
    or if standard user permissions restrict access.
    """
    if not is_windows():
        return [], "BitLocker diagnostics are unavailable on non-Windows hosts."

    script = r"""
if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
    [PSCustomObject]@{ Available = $false; Reason = 'BitLocker PowerShell module is unavailable on this Windows edition.'; Volumes = @() } | ConvertTo-Json -Compress
    exit 0
}
try {
    $vols = @(Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            MountPoint           = $_.MountPoint
            ProtectionStatus     = $_.ProtectionStatus.ToString()
            VolumeStatus         = $_.VolumeStatus.ToString()
            EncryptionPercentage = $_.EncryptionPercentage
        }
    })
    [PSCustomObject]@{ Available = $true; Reason = $null; Volumes = $vols } | ConvertTo-Json -Depth 3 -Compress
} catch {
    [PSCustomObject]@{ Available = $false; Reason = $_.Exception.Message; Volumes = @() } | ConvertTo-Json -Compress
}
"""
    res = run_powershell_json(script, timeout=POWERSHELL_TIMEOUT_SECONDS)
    if not res.success or not isinstance(res.data, dict):
        reason = res.error or "BitLocker status query could not be completed."
        if warnings is not None:
            warnings.append(f"BitLocker check unavailable: {reason}")
        return [], f"Unavailable ({reason})"

    if not res.data.get("Available"):
        reason = safe_str(res.data.get("Reason"), fallback="Restricted or unsupported without elevation")
        return [], f"Unavailable — {reason}"

    raw_vols = res.data.get("Volumes")
    rows = raw_vols if isinstance(raw_vols, list) else ([raw_vols] if isinstance(raw_vols, dict) else [])
    volumes: list[BitLockerVolumeStatus] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        pct = row.get("EncryptionPercentage")
        pct_display = f"{pct}%" if pct is not None else UNKNOWN_VALUE
        volumes.append(
            BitLockerVolumeStatus(
                mount_point=safe_str(row.get("MountPoint")),
                protection_status=safe_str(row.get("ProtectionStatus")),
                volume_status=safe_str(row.get("VolumeStatus")),
                encryption_percentage=pct_display,
            )
        )

    if not volumes:
        return [], "Unavailable — no BitLocker-compatible volumes returned."
    return volumes, "Accessible"


def evaluate_security_findings(
    firewall_profiles: list[FirewallProfileStatus],
    defender: DefenderStatus,
    registered_av: list[RegisteredAntivirusInfo],
    hotfixes: list[HotfixItem],
    uac: UacStatus,
    bitlocker_volumes: list[BitLockerVolumeStatus],
    bitlocker_note: str,
    hotfixes_checked: bool = True,
) -> list[SecurityFinding]:
    """Generate rule-based baseline security findings and read-only guidance."""
    findings: list[SecurityFinding] = []

    if not firewall_profiles:
        findings.append(
            SecurityFinding(
                severity="Warning",
                category="Firewall",
                title="Windows Firewall Profile Status Unknown",
                explanation="Unable to verify Domain, Private, or Public firewall profile states.",
                recommendations=[
                    "Verify the Windows Defender Firewall (mpssvc) service status.",
                    "Confirm firewall policy via an enterprise management console or elevated session.",
                ],
            )
        )
    else:
        disabled = [p.profile_name for p in firewall_profiles if p.enabled is False]
        if disabled:
            findings.append(
                SecurityFinding(
                    severity="Critical",
                    category="Firewall",
                    title=f"Windows Firewall Disabled ({', '.join(disabled)})",
                    explanation=(
                        "One or more Windows Firewall profiles are disabled, increasing exposure "
                        "to unauthorized lateral movement or inbound network probes."
                    ),
                    recommendations=[
                        "Verify whether a third-party endpoint firewall or enterprise GPO manages host filtering.",
                        "Escalate to IT Security / Endpoint Operations to re-enable host firewall enforcement.",
                    ],
                )
            )

    any_enabled_av = any(av.enabled_state == "Enabled" for av in registered_av)
    if defender.available and defender.real_time_protection_enabled is False and not any_enabled_av:
        findings.append(
            SecurityFinding(
                severity="Critical",
                category="Antivirus",
                title="Real-Time Antivirus Protection Disabled",
                explanation="Microsoft Defender real-time protection is off and no active third-party AV is reported.",
                recommendations=[
                    "Investigate why endpoint protection is disabled before connecting to corporate resources.",
                    "Escalate to SOC / Endpoint Support to restore managed EDR/antivirus protection.",
                ],
            )
        )
    elif defender.available and defender.real_time_protection_enabled is False and any_enabled_av:
        active_names = ", ".join(av.display_name for av in registered_av if av.enabled_state == "Enabled")
        findings.append(
            SecurityFinding(
                severity="Info",
                category="Antivirus",
                title="Defender Passive / Delegated to Registered AV",
                explanation=f"Microsoft Defender real-time scanning is off while '{active_names}' is registered as active.",
                recommendations=[
                    "Confirm the registered antivirus product is the approved enterprise endpoint agent.",
                ],
            )
        )
    elif not defender.available and not any_enabled_av:
        findings.append(
            SecurityFinding(
                severity="Warning",
                category="Antivirus",
                title="Active Antivirus Posture Could Not Be Confirmed",
                explanation="Neither Microsoft Defender status nor an enabled SecurityCenter2 AV product could be confirmed.",
                recommendations=[
                    "Check installed enterprise EDR/AV agents via System Administration or endpoint console.",
                ],
            )
        )

    outdated_sigs = [av.display_name for av in registered_av if av.signature_state == "Out of Date"]
    if outdated_sigs:
        findings.append(
            SecurityFinding(
                severity="Warning",
                category="Antivirus",
                title=f"Antivirus Signatures Out of Date ({', '.join(outdated_sigs)})",
                explanation="Security Center reports outdated malware definition signatures.",
                recommendations=[
                    "Trigger a definition update through the approved antivirus client or WSUS/Defender update channel.",
                ],
            )
        )

    if uac.available and uac.enable_lua == 0:
        findings.append(
            SecurityFinding(
                severity="Critical",
                category="Access Control",
                title="User Account Control (UAC) Is Disabled",
                explanation="EnableLUA is set to 0, removing privilege-elevation boundaries for standard and admin tokens.",
                recommendations=[
                    "Escalate to Security/Desktop Engineering to restore enterprise UAC baseline policy.",
                ],
            )
        )
    elif uac.available and uac.enable_lua == 1 and uac.consent_prompt_admin == 0:
        findings.append(
            SecurityFinding(
                severity="Warning",
                category="Access Control",
                title="UAC Admin Approval Mode Set to Elevate Without Prompting",
                explanation="UAC is enabled, but ConsentPromptBehaviorAdmin=0 allows silent elevation without confirmation.",
                recommendations=[
                    "Review local security policy against financial-sector least-privilege standards (recommend prompt on secure desktop).",
                ],
            )
        )

    unprotected_vols = [
        v.mount_point for v in bitlocker_volumes if v.protection_status.lower() == "off"
    ]
    if unprotected_vols:
        findings.append(
            SecurityFinding(
                severity="Critical",
                category="Encryption",
                title=f"BitLocker Protection Off ({', '.join(unprotected_vols)})",
                explanation="One or more accessible volumes report BitLocker protection as Off.",
                recommendations=[
                    "Verify full-disk encryption compliance in Intune/BitLocker management and escrow recovery keys to AD/AAD.",
                ],
            )
        )
    elif not bitlocker_volumes:
        findings.append(
            SecurityFinding(
                severity="Info",
                category="Encryption",
                title="BitLocker Encryption Status Unavailable in Standard User Mode",
                explanation=bitlocker_note,
                recommendations=[
                    "Verify drive encryption compliance through an elevated admin console or MDM/Intune portal.",
                ],
            )
        )

    if hotfixes_checked and not hotfixes:
        findings.append(
            SecurityFinding(
                severity="Info",
                category="Patching",
                title="Windows Update / HotFix History Unavailable",
                explanation="No QuickFixEngineering hotfix records were returned.",
                recommendations=[
                    "Inspect Windows Update history in Settings or WSUS/SCCM compliance reports.",
                ],
            )
        )

    if not findings:
        findings.append(
            SecurityFinding(
                severity="Healthy",
                category="Baseline",
                title="Checked Local Baseline Indicators Passed",
                explanation=(
                    "Firewall profiles, active AV, UAC policy, and accessible baseline checks appear healthy. "
                    "Continue verifying patch currency and MDM compliance."
                ),
                recommendations=[
                    "Review hotfix dates and signature timestamps periodically against enterprise SLA targets.",
                ],
            )
        )

    return findings


def collect_security_snapshot(include_hotfixes: bool = True) -> SecuritySnapshot:
    """Gather all read-only endpoint security baseline checks."""
    warnings: list[str] = []
    firewall_profiles = get_firewall_profiles(warnings=warnings)
    defender = get_defender_status(warnings=warnings)
    registered_av = get_registered_antivirus(warnings=warnings)
    hotfixes = get_hotfix_history(warnings=warnings) if include_hotfixes else []
    uac = get_uac_status(warnings=warnings)
    bitlocker_volumes, bitlocker_note = get_bitlocker_status(warnings=warnings)

    findings = evaluate_security_findings(
        firewall_profiles=firewall_profiles,
        defender=defender,
        registered_av=registered_av,
        hotfixes=hotfixes,
        uac=uac,
        bitlocker_volumes=bitlocker_volumes,
        bitlocker_note=bitlocker_note,
        hotfixes_checked=include_hotfixes,
    )

    return SecuritySnapshot(
        collected_at=format_timestamp(time.time()),
        firewall_profiles=firewall_profiles,
        defender=defender,
        registered_antivirus=registered_av,
        hotfixes=hotfixes,
        uac=uac,
        bitlocker_volumes=bitlocker_volumes,
        bitlocker_status_note=bitlocker_note,
        findings=findings,
        disclaimer=SECURITY_ASSESSMENT_DISCLAIMER,
        warnings=warnings,
    )
