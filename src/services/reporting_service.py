"""Centralized technical reporting service with privacy redaction and CSV/HTML export."""

from __future__ import annotations

import csv
import html
import io
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from src.config.settings import (
    APP_NAME,
    APP_VERSION,
    DEFAULT_DB_PATH,
    UNAVAILABLE_VALUE,
    UNKNOWN_VALUE,
)
from src.services.asset_service import (
    Asset,
    SoftwareLicense,
    list_assets,
    list_software_licenses,
)
from src.services.hardware_diagnostics import HardwareSnapshot, collect_hardware_snapshot
from src.services.helpdesk_service import Ticket, list_tickets
from src.services.network_diagnostics import (
    ConnectivityProbeResult,
    NetworkSnapshot,
    collect_network_snapshot,
)
from src.services.security_posture import SecuritySnapshot, collect_security_snapshot
from src.services.system_info import OsInfo, ProcessInfo, get_os_info, get_running_processes
from src.services.troubleshooting_engine import (
    SEVERITY_LEVELS,
    TroubleshootingFinding,
    evaluate_troubleshooting_rules,
)
from src.utils.formatting import format_bytes, format_timestamp, sanitize_csv_cell

REPORT_TYPES: tuple[tuple[str, str], ...] = (
    ("endpoint_health", "Endpoint System Health Report"),
    ("hardware", "Hardware Diagnostic Report"),
    ("network", "Network Diagnostic Report"),
    ("security", "Endpoint Security Assessment Report"),
    ("helpdesk", "IT Help Desk Incident Report"),
    ("assets", "IT Asset Inventory Report"),
    ("licenses", "Software License Inventory Report"),
    ("comprehensive", "Comprehensive IT Infrastructure Assessment Report"),
)
REPORT_TYPE_LABELS: dict[str, str] = dict(REPORT_TYPES)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:\s*/\s*\d{1,3}(?:\.\d{1,3}){3})?\b")
_IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}\b")
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_DOMAIN_USER_RE = re.compile(r"\b[A-Za-z0-9_.-]+\\[A-Za-z0-9_.-]+\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_USER_PATH_RE = re.compile(r"(?i)([A-Za-z]:\\Users\\)([^\\/\s\"']+)")

_SENSITIVE_COLUMNS: set[str] = {
    "hostname",
    "fqdn",
    "current user",
    "user",
    "user domain",
    "serial number",
    "mac address",
    "bssid",
    "ipv4",
    "ipv4 / subnet",
    "ipv6",
    "gateway",
    "default gateway",
    "dns servers",
    "requester",
    "assigned technician",
    "assigned employee",
    "installed by",
}


@dataclass(frozen=True)
class ReportSection:
    """Tabular section inside a generated technical report."""

    title: str
    columns: list[str]
    rows: list[dict[str, Any]]


@dataclass(frozen=True)
class TechnicalReport:
    """Self-contained technical report with CSV and HTML export payloads."""

    report_id: str
    report_key: str
    title: str
    generated_at: str
    privacy_redacted: bool
    executive_summary: str
    severity_breakdown: dict[str, int]
    findings: list[TroubleshootingFinding]
    sections: list[ReportSection]
    recommended_actions: list[str]
    limitations: list[str]
    csv_content: str
    html_content: str


def _new_report_id() -> str:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    suffix = uuid.uuid4().hex[:4].upper()
    return f"RPT-{stamp}-{suffix}"


def _build_redactor(sensitive_literals: list[tuple[str, str]]):
    """Build a redaction helper that scrubs sensitive literals, emails, paths, and network IDs."""
    cleaned_literals = [
        (lit.strip(), token)
        for lit, token in sensitive_literals
        if lit and lit.strip() and lit.strip() not in {UNKNOWN_VALUE, UNAVAILABLE_VALUE, "Unassigned", "N/A"}
    ]
    # Replace longest literals first to avoid partial substring collisions.
    cleaned_literals.sort(key=lambda pair: len(pair[0]), reverse=True)
    compiled_literals = [
        (re.compile(re.escape(literal), re.IGNORECASE), token)
        for literal, token in cleaned_literals
    ]

    def redact(value: Any) -> str:
        text = "" if value is None else str(value)
        for pattern, token in compiled_literals:
            text = pattern.sub(token, text)
        text = _EMAIL_RE.sub("[REDACTED-EMAIL]", text)
        text = _USER_PATH_RE.sub(r"\1[REDACTED-USER]", text)
        text = _MAC_RE.sub("[REDACTED-MAC]", text)
        text = _IPV4_RE.sub("[REDACTED-IP]", text)
        text = _IPV6_RE.sub("[REDACTED-IP]", text)
        text = _DOMAIN_USER_RE.sub("[REDACTED-USER]", text)
        return text

    return redact


def _redact_section(section: ReportSection, redact_fn) -> ReportSection:
    redacted_rows: list[dict[str, Any]] = []
    for row in section.rows:
        new_row: dict[str, Any] = {}
        for col in section.columns:
            raw_val = row.get(col, "")
            if col.strip().lower() in _SENSITIVE_COLUMNS and str(raw_val).strip():
                new_row[col] = "[REDACTED]"
            else:
                new_row[col] = redact_fn(raw_val)
        redacted_rows.append(new_row)
    return ReportSection(title=section.title, columns=section.columns, rows=redacted_rows)


def _redact_finding(finding: TroubleshootingFinding, redact_fn) -> TroubleshootingFinding:
    return TroubleshootingFinding(
        finding_id=finding.finding_id,
        title=redact_fn(finding.title),
        category=finding.category,
        severity=finding.severity,
        confirmed_evidence=[redact_fn(x) for x in finding.confirmed_evidence],
        suspected_root_causes=[redact_fn(x) for x in finding.suspected_root_causes],
        confidence_and_limitations=redact_fn(finding.confidence_and_limitations),
        recommended_steps=[redact_fn(x) for x in finding.recommended_steps],
        verification_steps=[redact_fn(x) for x in finding.verification_steps],
        escalation_guidance=redact_fn(finding.escalation_guidance),
        helpdesk_category=finding.helpdesk_category,
        helpdesk_priority=finding.helpdesk_priority,
    )


def _render_csv(
    *,
    report_id: str,
    title: str,
    generated_at: str,
    privacy_redacted: bool,
    executive_summary: str,
    severity_breakdown: dict[str, int],
    findings: list[TroubleshootingFinding],
    sections: list[ReportSection],
    recommended_actions: list[str],
    limitations: list[str],
) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)

    writer.writerow(["Report Metadata", "Value"])
    writer.writerow(["Report ID", sanitize_csv_cell(report_id)])
    writer.writerow(["Report Title", sanitize_csv_cell(title)])
    writer.writerow(["Generated At", sanitize_csv_cell(generated_at)])
    writer.writerow(["Privacy Redacted", "Yes" if privacy_redacted else "No"])
    writer.writerow(["Executive Summary", sanitize_csv_cell(executive_summary)])
    writer.writerow([])

    writer.writerow(["Severity Breakdown", "Count"])
    for sev in SEVERITY_LEVELS:
        writer.writerow([sanitize_csv_cell(sev), severity_breakdown.get(sev, 0)])
    writer.writerow([])

    if findings:
        writer.writerow(["Findings"])
        writer.writerow(["Finding ID", "Category", "Severity", "Title", "Confirmed Evidence", "Suspected Causes", "Recommended Steps"])
        for f in findings:
            writer.writerow(
                [
                    sanitize_csv_cell(val)
                    for val in (
                        f.finding_id,
                        f.category,
                        f.severity,
                        f.title,
                        " | ".join(f.confirmed_evidence),
                        " | ".join(f.suspected_root_causes),
                        " | ".join(f.recommended_steps),
                    )
                ]
            )
        writer.writerow([])

    for sec in sections:
        writer.writerow([sanitize_csv_cell(sec.title)])
        if sec.rows:
            writer.writerow([sanitize_csv_cell(c) for c in sec.columns])
            for row in sec.rows:
                writer.writerow([sanitize_csv_cell(row.get(col, "")) for col in sec.columns])
        else:
            writer.writerow(["No records available for this section."])
        writer.writerow([])

    if recommended_actions:
        writer.writerow(["Recommended Actions"])
        for idx, act in enumerate(recommended_actions, start=1):
            writer.writerow([idx, sanitize_csv_cell(act)])
        writer.writerow([])

    if limitations:
        writer.writerow(["Limitations & Unavailable Checks"])
        for idx, lim in enumerate(limitations, start=1):
            writer.writerow([idx, sanitize_csv_cell(lim)])

    return buf.getvalue()


def _render_html(
    *,
    report_id: str,
    title: str,
    generated_at: str,
    privacy_redacted: bool,
    executive_summary: str,
    severity_breakdown: dict[str, int],
    findings: list[TroubleshootingFinding],
    sections: list[ReportSection],
    recommended_actions: list[str],
    limitations: list[str],
) -> str:
    """Render a fully escaped, self-contained HTML report with zero external resources."""
    e = lambda v: html.escape("" if v is None else str(v), quote=True)

    sev_cards = "".join(
        f'<div class="kpi"><div class="kpi-lbl">{e(sev)}</div>'
        f'<div class="kpi-val">{e(severity_breakdown.get(sev, 0))}</div></div>'
        for sev in SEVERITY_LEVELS
    )

    findings_html = ""
    if findings:
        items_html = []
        for f in findings:
            ev_li = "".join(f"<li>{e(x)}</li>" for x in f.confirmed_evidence)
            cause_li = "".join(f"<li>{e(x)}</li>" for x in f.suspected_root_causes)
            step_li = "".join(f"<li>{e(x)}</li>" for x in f.recommended_steps)
            items_html.append(
                f"""
                <div class="card">
                    <div class="card-head">
                        <strong>[{e(f.finding_id)}] {e(f.title)}</strong>
                        <span class="badge sev-{e(f.severity.lower())}">{e(f.severity)}</span>
                    </div>
                    <div class="meta">Category: {e(f.category)} | {e(f.confidence_and_limitations)}</div>
                    <p><strong>Confirmed Evidence:</strong></p><ul>{ev_li}</ul>
                    <p><strong>Suspected Root Causes:</strong></p><ul>{cause_li}</ul>
                    <p><strong>Recommended Actions:</strong></p><ul>{step_li}</ul>
                </div>
                """
            )
        findings_html = f"<h2>Diagnostic Findings</h2>{''.join(items_html)}"

    sections_html_parts: list[str] = []
    for sec in sections:
        if sec.rows:
            ths = "".join(f"<th>{e(col)}</th>" for col in sec.columns)
            trs = "".join(
                "<tr>" + "".join(f"<td>{e(row.get(col, ''))}</td>" for col in sec.columns) + "</tr>"
                for row in sec.rows
            )
            table_html = f"<table><thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table>"
        else:
            table_html = '<p class="muted">No records available for this section.</p>'
        sections_html_parts.append(f"<h2>{e(sec.title)}</h2>{table_html}")

    actions_html = ""
    if recommended_actions:
        lis = "".join(f"<li>{e(a)}</li>" for a in recommended_actions)
        actions_html = f"<h2>Recommended Actions</h2><ul>{lis}</ul>"

    limits_html = ""
    if limitations:
        lis = "".join(f"<li>{e(l)}</li>" for l in limitations)
        limits_html = f"<h2>Limitations &amp; Unavailable Checks</h2><ul>{lis}</ul>"

    redaction_label = "Privacy-Safe (Redacted)" if privacy_redacted else "Standard (Unredacted)"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>{e(title)} — {e(report_id)}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0B1120; color: #E2E8F0; margin: 0; padding: 28px; line-height: 1.5; }}
.wrap {{ max-width: 1120px; margin: 0 auto; }}
.header {{ background: #111827; border: 1px solid #1E293B; border-left: 4px solid #3B82F6; border-radius: 8px; padding: 18px 22px; margin-bottom: 18px; }}
h1 {{ margin: 0 0 6px 0; font-size: 22px; color: #F8FAFC; }}
h2 {{ margin: 22px 0 10px 0; font-size: 16px; color: #F1F5F9; border-bottom: 1px solid #1E293B; padding-bottom: 4px; }}
.meta {{ color: #94A3B8; font-size: 13px; }}
.kpi-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 14px 0; }}
.kpi {{ background: #111827; border: 1px solid #1E293B; border-radius: 6px; padding: 10px 12px; }}
.kpi-lbl {{ color: #94A3B8; font-size: 11px; text-transform: uppercase; }}
.kpi-val {{ color: #F8FAFC; font-size: 20px; font-weight: 600; margin-top: 4px; }}
.card {{ background: #111827; border: 1px solid #1E293B; border-radius: 6px; padding: 14px 16px; margin-bottom: 12px; }}
.card-head {{ display: flex; justify-content: space-between; align-items: center; gap: 10px; margin-bottom: 6px; }}
.badge {{ padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 600; }}
.sev-critical {{ background: #7F1D1D; color: #FCA5A5; }}
.sev-high {{ background: #9A3412; color: #FDBA74; }}
.sev-medium {{ background: #78350F; color: #FDE68A; }}
.sev-low {{ background: #1E3A8A; color: #BFDBFE; }}
.sev-informational {{ background: #1E293B; color: #CBD5E1; }}
table {{ width: 100%; border-collapse: collapse; background: #111827; margin-bottom: 16px; font-size: 13px; }}
th, td {{ border: 1px solid #1E293B; padding: 7px 9px; text-align: left; vertical-align: top; }}
th {{ background: #0F172A; color: #CBD5E1; font-weight: 600; }}
ul {{ margin: 4px 0 10px 0; padding-left: 20px; }}
.muted {{ color: #94A3B8; font-size: 13px; }}
.footer {{ margin-top: 26px; border-top: 1px solid #1E293B; padding-top: 10px; color: #64748B; font-size: 12px; }}
</style>
</head>
<body>
<div class="wrap">
    <div class="header">
        <h1>{e(title)}</h1>
        <div class="meta">
            Report ID: <strong>{e(report_id)}</strong> |
            Generated: <strong>{e(generated_at)}</strong> |
            Mode: <strong>{e(redaction_label)}</strong> |
            Source: {e(APP_NAME)} v{e(APP_VERSION)}
        </div>
    </div>
    <h2>Executive Summary</h2>
    <p>{e(executive_summary)}</p>
    <div class="kpi-grid">{sev_cards}</div>
    {findings_html}
    {''.join(sections_html_parts)}
    {actions_html}
    {limits_html}
    <div class="footer">
        Generated locally in read-only diagnostic mode. Self-contained HTML report (no external scripts or tracking).
    </div>
</div>
</body>
</html>"""


def build_report(
    report_key: str,
    *,
    privacy_redacted: bool = False,
    hardware_snapshot: HardwareSnapshot | None = None,
    os_info: OsInfo | None = None,
    processes: list[ProcessInfo] | None = None,
    network_snapshot: NetworkSnapshot | None = None,
    security_snapshot: SecuritySnapshot | None = None,
    connectivity_result: ConnectivityProbeResult | None = None,
    tickets: list[Ticket] | None = None,
    assets: list[Asset] | None = None,
    licenses: list[SoftwareLicense] | None = None,
) -> TechnicalReport:
    """Assemble a TechnicalReport from supplied telemetry/database records."""
    if report_key not in REPORT_TYPE_LABELS:
        raise ValueError(f"Unsupported report type: {report_key}")

    title = REPORT_TYPE_LABELS[report_key]
    report_id = _new_report_id()
    generated_at = format_timestamp(time.time())

    # Determine assessment categories relevant to this report
    cat_map: dict[str, tuple[str, ...]] = {
        "endpoint_health": ("Hardware", "System", "Network", "Security"),
        "hardware": ("Hardware",),
        "network": ("Network",),
        "security": ("Security",),
        "comprehensive": ("Hardware", "System", "Network", "Security"),
    }

    findings: list[TroubleshootingFinding] = []
    severity_breakdown: dict[str, int] = {sev: 0 for sev in SEVERITY_LEVELS}
    limitations: list[str] = []

    if report_key in cat_map:
        assessment = evaluate_troubleshooting_rules(
            categories=cat_map[report_key],
            hardware_snapshot=hardware_snapshot,
            os_info=os_info,
            processes=processes or [],
            network_snapshot=network_snapshot,
            security_snapshot=security_snapshot,
            connectivity_result=connectivity_result,
        )
        findings = list(assessment.findings)
        severity_breakdown = dict(assessment.severity_counts)
        limitations.extend(assessment.limitations)

    sections: list[ReportSection] = []
    sensitive_literals: list[tuple[str, str]] = []

    if os_info is not None:
        sensitive_literals.extend(
            [
                (os_info.fqdn, "[REDACTED-HOST]"),
                (os_info.hostname, "[REDACTED-HOST]"),
                (os_info.current_user, "[REDACTED-USER]"),
                (os_info.user_domain, "[REDACTED-DOMAIN]"),
            ]
        )
    if hardware_snapshot is not None:
        sensitive_literals.extend(
            [
                (hardware_snapshot.system_specs.hostname, "[REDACTED-HOST]"),
                (hardware_snapshot.system_specs.serial_number, "[REDACTED-SERIAL]"),
            ]
        )
        for pdisk in hardware_snapshot.physical_disks:
            sensitive_literals.append((pdisk.serial_number, "[REDACTED-SERIAL]"))
    for asset in assets or []:
        sensitive_literals.extend(
            [
                (asset.serial_number, "[REDACTED-SERIAL]"),
                (asset.assigned_employee, "[REDACTED-USER]"),
            ]
        )
    for t in tickets or []:
        sensitive_literals.extend(
            [
                (t.requester_name, "[REDACTED-USER]"),
                (t.assigned_technician, "[REDACTED-USER]"),
            ]
        )

    if report_key in {"endpoint_health", "hardware", "comprehensive"} and hardware_snapshot is not None:
        hw = hardware_snapshot
        sections.append(
            ReportSection(
                title="Hardware & System Overview",
                columns=["Metric", "Value", "Status"],
                rows=[
                    {"Metric": "Hostname", "Value": hw.system_specs.hostname, "Status": "Info"},
                    {"Metric": "Manufacturer / Model", "Value": f"{hw.system_specs.manufacturer} {hw.system_specs.model}", "Status": "Info"},
                    {"Metric": "Serial Number", "Value": hw.system_specs.serial_number, "Status": "Info"},
                    {"Metric": "Processor", "Value": hw.cpu.processor_name, "Status": hw.cpu.status},
                    {
                        "Metric": "CPU Utilization",
                        "Value": f"{hw.cpu.usage_percent:.1f}%" if hw.cpu.usage_percent is not None else UNKNOWN_VALUE,
                        "Status": hw.cpu.status,
                    },
                    {
                        "Metric": "RAM Utilization",
                        "Value": (
                            f"{hw.memory.percent_used:.1f}% ({format_bytes(hw.memory.used_bytes)} / {format_bytes(hw.memory.total_bytes)})"
                            if hw.memory.percent_used is not None
                            else UNKNOWN_VALUE
                        ),
                        "Status": hw.memory.status,
                    },
                    {
                        "Metric": "Battery",
                        "Value": f"{hw.battery.percent:.0f}% ({hw.battery.time_left_display})" if hw.battery.present and hw.battery.percent is not None else hw.battery.time_left_display,
                        "Status": hw.battery.status,
                    },
                ],
            )
        )
        sections.append(
            ReportSection(
                title="Logical Storage Volumes",
                columns=["Device", "Mount", "Filesystem", "Total", "Free", "Used %", "Status"],
                rows=[
                    {
                        "Device": d.device,
                        "Mount": d.mountpoint,
                        "Filesystem": d.fstype,
                        "Total": format_bytes(d.total_bytes),
                        "Free": format_bytes(d.free_bytes),
                        "Used %": f"{d.percent_used:.1f}%" if d.percent_used is not None else UNKNOWN_VALUE,
                        "Status": d.status,
                    }
                    for d in hw.logical_disks
                ],
            )
        )
        limitations.extend(hw.warnings)

    if report_key in {"endpoint_health", "comprehensive"} and os_info is not None:
        sections.append(
            ReportSection(
                title="Operating System & Runtime Identity",
                columns=["Field", "Value"],
                rows=[
                    {"Field": "OS Edition", "Value": f"{os_info.os_name} (Build {os_info.os_build})"},
                    {"Field": "Architecture", "Value": os_info.architecture},
                    {"Field": "Hostname", "Value": os_info.hostname},
                    {"Field": "Current User", "Value": f"{os_info.user_domain}\\{os_info.current_user}"},
                    {"Field": "Uptime", "Value": f"{os_info.uptime_display} (Boot: {os_info.boot_time_display})"},
                ],
            )
        )

    if report_key in {"network", "endpoint_health", "comprehensive"} and network_snapshot is not None:
        net = network_snapshot
        sections.append(
            ReportSection(
                title="Network Adapters",
                columns=["Adapter", "Status", "MAC Address", "IPv4 / Subnet", "Gateway", "DNS Servers"],
                rows=[
                    {
                        "Adapter": a.name,
                        "Status": a.status,
                        "MAC Address": a.mac_address,
                        "IPv4 / Subnet": ", ".join(a.ipv4_addresses) if a.ipv4_addresses else UNAVAILABLE_VALUE,
                        "Gateway": ", ".join(a.default_gateways) if a.default_gateways else UNAVAILABLE_VALUE,
                        "DNS Servers": ", ".join(a.dns_servers) if a.dns_servers else UNAVAILABLE_VALUE,
                    }
                    for a in net.adapters
                ],
            )
        )
        if connectivity_result is not None:
            sections.append(
                ReportSection(
                    title="User-Triggered Connectivity Check",
                    columns=["Classification", "DNS Result", "Summary", "Executed At"],
                    rows=[
                        {
                            "Classification": connectivity_result.classification,
                            "DNS Result": connectivity_result.dns_detail,
                            "Summary": connectivity_result.summary,
                            "Executed At": connectivity_result.executed_at,
                        }
                    ],
                )
            )
        limitations.extend(net.warnings)

    if report_key in {"security", "endpoint_health", "comprehensive"} and security_snapshot is not None:
        sec = security_snapshot
        sections.append(
            ReportSection(
                title="Windows Firewall Profiles",
                columns=["Profile", "Status", "Default Inbound", "Default Outbound"],
                rows=[
                    {
                        "Profile": p.profile_name,
                        "Status": p.status_display,
                        "Default Inbound": p.default_inbound,
                        "Default Outbound": p.default_outbound,
                    }
                    for p in sec.firewall_profiles
                ],
            )
        )
        sections.append(
            ReportSection(
                title="Antivirus, UAC & Encryption Posture",
                columns=["Control", "State", "Details"],
                rows=[
                    {
                        "Control": "Microsoft Defender Real-Time",
                        "State": sec.defender.status_display,
                        "Details": f"Signature: {sec.defender.signature_version} (Updated: {sec.defender.signature_last_updated})",
                    },
                    *[
                        {
                            "Control": f"Registered AV: {av.display_name}",
                            "State": av.enabled_state,
                            "Details": f"Signatures: {av.signature_state} ({av.raw_state_hex})",
                        }
                        for av in sec.registered_antivirus
                    ],
                    {
                        "Control": "User Account Control (UAC)",
                        "State": sec.uac.status,
                        "Details": sec.uac.policy_summary,
                    },
                    {
                        "Control": "BitLocker Encryption",
                        "State": "Accessible" if sec.bitlocker_volumes else UNAVAILABLE_VALUE,
                        "Details": (
                            ", ".join(f"{v.mount_point}: {v.protection_status}" for v in sec.bitlocker_volumes)
                            if sec.bitlocker_volumes
                            else sec.bitlocker_status_note
                        ),
                    },
                ],
            )
        )
        limitations.append(sec.disclaimer)
        limitations.extend(sec.warnings)

    if report_key in {"helpdesk", "comprehensive"}:
        ticket_rows = [
            {
                "Ticket ID": t.ticket_id,
                "Type": t.ticket_type,
                "Title": t.title,
                "Category": t.category,
                "Priority": t.priority,
                "Status": t.status,
                "Requester": t.requester_name,
                "Department": t.department,
                "Assigned Technician": t.assigned_technician,
                "Updated At": t.updated_at,
            }
            for t in (tickets or [])
        ]
        sections.append(
            ReportSection(
                title="IT Help Desk Tickets",
                columns=[
                    "Ticket ID",
                    "Type",
                    "Title",
                    "Category",
                    "Priority",
                    "Status",
                    "Requester",
                    "Department",
                    "Assigned Technician",
                    "Updated At",
                ],
                rows=ticket_rows,
            )
        )

    if report_key in {"assets", "comprehensive"}:
        asset_rows = [
            {
                "Asset ID": a.asset_id,
                "Asset Name": a.asset_name,
                "Category": a.category,
                "Manufacturer": a.manufacturer,
                "Model": a.model,
                "Serial Number": a.serial_number or "N/A",
                "Operating System": a.operating_system or "N/A",
                "Assigned Employee": a.assigned_employee or "Unassigned",
                "Department": a.department or "Unassigned",
                "Status": a.status,
            }
            for a in (assets or [])
        ]
        sections.append(
            ReportSection(
                title="IT Asset Inventory",
                columns=[
                    "Asset ID",
                    "Asset Name",
                    "Category",
                    "Manufacturer",
                    "Model",
                    "Serial Number",
                    "Operating System",
                    "Assigned Employee",
                    "Department",
                    "Status",
                ],
                rows=asset_rows,
            )
        )

    if report_key in {"licenses", "comprehensive"}:
        lic_rows = [
            {
                "License ID": lic.license_id,
                "Software": lic.software_name,
                "Vendor": lic.vendor,
                "Type": lic.license_type,
                "Quantity": lic.quantity,
                "Assigned": lic.assigned_count,
                "Available": max(0, lic.quantity - lic.assigned_count),
                "Expiration": lic.expiration_date or "N/A",
                "Department": lic.department or "Enterprise",
            }
            for lic in (licenses or [])
        ]
        sections.append(
            ReportSection(
                title="Software License Inventory (No Keys Stored)",
                columns=[
                    "License ID",
                    "Software",
                    "Vendor",
                    "Type",
                    "Quantity",
                    "Assigned",
                    "Available",
                    "Expiration",
                    "Department",
                ],
                rows=lic_rows,
            )
        )

    # Executive Summary & Recommended Actions
    crit_high = severity_breakdown.get("Critical", 0) + severity_breakdown.get("High", 0)
    if report_key in {"helpdesk", "assets", "licenses"}:
        total_rows = sum(len(s.rows) for s in sections)
        executive_summary = f"{title} compiled with {total_rows} persisted record(s)."
    else:
        executive_summary = (
            f"{title} evaluated {len(findings)} finding(s): "
            f"{severity_breakdown.get('Critical', 0)} Critical, "
            f"{severity_breakdown.get('High', 0)} High, "
            f"{severity_breakdown.get('Medium', 0)} Medium, "
            f"{severity_breakdown.get('Low', 0)} Low, "
            f"{severity_breakdown.get('Informational', 0)} Informational."
        )
        if crit_high > 0:
            executive_summary += " Immediate review of Critical/High items is recommended."

    recommended_actions: list[str] = []
    seen_actions: set[str] = set()
    for f in findings:
        for step in f.recommended_steps:
            if step not in seen_actions:
                seen_actions.add(step)
                recommended_actions.append(step)

    dedup_limitations: list[str] = []
    seen_limits: set[str] = set()
    for lim in limitations:
        if lim and lim not in seen_limits:
            seen_limits.add(lim)
            dedup_limitations.append(lim)

    if privacy_redacted:
        redact_fn = _build_redactor(sensitive_literals)
        executive_summary = redact_fn(executive_summary)
        findings = [_redact_finding(f, redact_fn) for f in findings]
        sections = [_redact_section(s, redact_fn) for s in sections]
        recommended_actions = [redact_fn(a) for a in recommended_actions]
        dedup_limitations = [redact_fn(l) for l in dedup_limitations]

    csv_content = _render_csv(
        report_id=report_id,
        title=title,
        generated_at=generated_at,
        privacy_redacted=privacy_redacted,
        executive_summary=executive_summary,
        severity_breakdown=severity_breakdown,
        findings=findings,
        sections=sections,
        recommended_actions=recommended_actions,
        limitations=dedup_limitations,
    )
    html_content = _render_html(
        report_id=report_id,
        title=title,
        generated_at=generated_at,
        privacy_redacted=privacy_redacted,
        executive_summary=executive_summary,
        severity_breakdown=severity_breakdown,
        findings=findings,
        sections=sections,
        recommended_actions=recommended_actions,
        limitations=dedup_limitations,
    )

    return TechnicalReport(
        report_id=report_id,
        report_key=report_key,
        title=title,
        generated_at=generated_at,
        privacy_redacted=privacy_redacted,
        executive_summary=executive_summary,
        severity_breakdown=severity_breakdown,
        findings=findings,
        sections=sections,
        recommended_actions=recommended_actions,
        limitations=dedup_limitations,
        csv_content=csv_content,
        html_content=html_content,
    )


def generate_report(
    report_key: str,
    *,
    privacy_redacted: bool = False,
    connectivity_result: ConnectivityProbeResult | None = None,
    db_path: Path | str = DEFAULT_DB_PATH,
) -> TechnicalReport:
    """Collect live telemetry/SQLite data required for the selected report and render exports."""
    if report_key not in REPORT_TYPE_LABELS:
        raise ValueError(f"Unsupported report type: {report_key}")

    hw = collect_hardware_snapshot() if report_key in {"endpoint_health", "hardware", "comprehensive"} else None
    os_info = get_os_info() if report_key in {"endpoint_health", "comprehensive"} else None
    processes: list[ProcessInfo] = []
    if report_key in {"endpoint_health", "comprehensive"}:
        _, processes = get_running_processes(limit=20, sort_by="memory_mb")

    net = collect_network_snapshot() if report_key in {"endpoint_health", "network", "comprehensive"} else None
    sec = (
        collect_security_snapshot(include_hotfixes=(report_key in {"security", "comprehensive"}))
        if report_key in {"endpoint_health", "security", "comprehensive"}
        else None
    )

    tickets = list_tickets(db_path=db_path) if report_key in {"helpdesk", "comprehensive"} else None
    assets = list_assets(db_path=db_path) if report_key in {"assets", "comprehensive"} else None
    licenses = list_software_licenses(db_path=db_path) if report_key in {"licenses", "comprehensive"} else None

    return build_report(
        report_key,
        privacy_redacted=privacy_redacted,
        hardware_snapshot=hw,
        os_info=os_info,
        processes=processes,
        network_snapshot=net,
        security_snapshot=sec,
        connectivity_result=connectivity_result,
        tickets=tickets,
        assets=assets,
        licenses=licenses,
    )
