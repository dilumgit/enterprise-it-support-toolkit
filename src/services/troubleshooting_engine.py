"""Centralized rule-based IT troubleshooting engine correlating multi-module telemetry."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from src.config.settings import (
    CPU_CRITICAL_THRESHOLD,
    CPU_WARNING_THRESHOLD,
    DEFAULT_DB_PATH,
    DISK_CRITICAL_THRESHOLD,
    DISK_WARNING_THRESHOLD,
    RAM_CRITICAL_THRESHOLD,
    RAM_WARNING_THRESHOLD,
    UNKNOWN_VALUE,
)
from src.services.hardware_diagnostics import HardwareSnapshot, collect_hardware_snapshot
from src.services.helpdesk_service import Ticket, create_ticket
from src.services.network_diagnostics import (
    ConnectivityProbeResult,
    DnsResolutionResult,
    NetworkSnapshot,
    PingResult,
    collect_network_snapshot,
)
from src.services.security_posture import SecuritySnapshot, collect_security_snapshot
from src.services.system_info import OsInfo, ProcessInfo, get_os_info, get_running_processes
from src.utils.formatting import format_bytes, format_timestamp

SEVERITY_LEVELS: tuple[str, ...] = (
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
)
ASSESSMENT_CATEGORIES: tuple[str, ...] = (
    "Hardware",
    "System",
    "Network",
    "Security",
)
_SEVERITY_RANK: dict[str, int] = {level: idx for idx, level in enumerate(SEVERITY_LEVELS)}

_PROCESS_MEMORY_THRESHOLD_MB: float = 1536.0
_PROCESS_CPU_THRESHOLD_PCT: float = 40.0
_LONG_UPTIME_DAYS: float = 14.0


@dataclass(frozen=True)
class TroubleshootingFinding:
    """Structured diagnostic finding distinguishing evidence from suspected root causes."""

    finding_id: str
    title: str
    category: str
    severity: str
    confirmed_evidence: list[str]
    suspected_root_causes: list[str]
    confidence_and_limitations: str
    recommended_steps: list[str]
    verification_steps: list[str]
    escalation_guidance: str
    helpdesk_category: str
    helpdesk_priority: str


@dataclass(frozen=True)
class TroubleshootingAssessment:
    """Complete read-only troubleshooting evaluation across selected diagnostic categories."""

    assessed_at: str
    categories_evaluated: tuple[str, ...]
    findings: list[TroubleshootingFinding]
    severity_counts: dict[str, int]
    limitations: list[str] = field(default_factory=list)
    hardware_snapshot: HardwareSnapshot | None = None
    os_info: OsInfo | None = None
    processes: list[ProcessInfo] = field(default_factory=list)
    network_snapshot: NetworkSnapshot | None = None
    security_snapshot: SecuritySnapshot | None = None


def _evaluate_hardware_and_system(
    hw: HardwareSnapshot | None,
    os_info: OsInfo | None,
    processes: list[ProcessInfo],
    findings: list[TroubleshootingFinding],
    limitations: list[str],
    include_hw: bool,
    include_sys: bool,
) -> None:
    """Evaluate CPU, memory, disk, uptime, process hogs, and slow-performance correlation."""
    cpu_pct = hw.cpu.usage_percent if hw else None
    ram_pct = hw.memory.percent_used if hw else None
    high_cpu = cpu_pct is not None and cpu_pct >= CPU_WARNING_THRESHOLD
    high_ram = ram_pct is not None and ram_pct >= RAM_WARNING_THRESHOLD
    low_disk_mounts: list[str] = []

    if include_hw and hw is not None:
        if cpu_pct is None:
            limitations.append("CPU utilization sample was unavailable; high-CPU rules skipped.")
        elif cpu_pct >= CPU_CRITICAL_THRESHOLD:
            findings.append(
                TroubleshootingFinding(
                    finding_id="TRB-HW-CPU-CRIT",
                    title=f"Critical CPU Utilization ({cpu_pct:.1f}%)",
                    category="Hardware",
                    severity="Critical",
                    confirmed_evidence=[
                        f"Measured CPU utilization is {cpu_pct:.1f}% (threshold >= {CPU_CRITICAL_THRESHOLD:.0f}%).",
                        f"Processor: {hw.cpu.processor_name} ({hw.cpu.logical_cores or UNKNOWN_VALUE} logical cores).",
                    ],
                    suspected_root_causes=[
                        "Runaway background service, batch calculation, security scan, or hung user application.",
                        "Insufficient CPU headroom for concurrent financial/analytics workloads.",
                    ],
                    confidence_and_limitations="High confidence based on a short live psutil sample; transient spikes may settle.",
                    recommended_steps=[
                        "Open System Administration -> Running Processes and sort by CPU %.",
                        "Confirm whether a scheduled Windows Update, Defender scan, or batch job is running.",
                        "Close idle high-CPU user applications or restart hung client processes with user consent.",
                    ],
                    verification_steps=[
                        "Re-run Hardware Diagnostics and confirm CPU utilization drops below 75%.",
                    ],
                    escalation_guidance="Escalate to Tier 2 Endpoint Engineering if sustained >90% CPU persists with no user workload.",
                    helpdesk_category="Hardware",
                    helpdesk_priority="Critical",
                )
            )
        elif cpu_pct >= CPU_WARNING_THRESHOLD:
            findings.append(
                TroubleshootingFinding(
                    finding_id="TRB-HW-CPU-WARN",
                    title=f"Elevated CPU Utilization ({cpu_pct:.1f}%)",
                    category="Hardware",
                    severity="Medium",
                    confirmed_evidence=[
                        f"Measured CPU utilization is {cpu_pct:.1f}% (warning threshold >= {CPU_WARNING_THRESHOLD:.0f}%).",
                    ],
                    suspected_root_causes=[
                        "Multiple active applications or background indexing/antivirus activity.",
                    ],
                    confidence_and_limitations="Medium confidence from point-in-time CPU sampling.",
                    recommended_steps=[
                        "Inspect top CPU-consuming processes in System Administration.",
                        "Monitor utilization for 2-3 minutes before taking action.",
                    ],
                    verification_steps=["Verify CPU utilization stabilizes below 75% under normal workload."],
                    escalation_guidance="Escalate to Desktop Support if sluggishness persists across reboots.",
                    helpdesk_category="Hardware",
                    helpdesk_priority="Medium",
                )
            )

        if ram_pct is None:
            limitations.append("RAM utilization telemetry was unavailable.")
        elif ram_pct >= RAM_CRITICAL_THRESHOLD:
            findings.append(
                TroubleshootingFinding(
                    finding_id="TRB-HW-RAM-CRIT",
                    title=f"Critical Memory Pressure ({ram_pct:.1f}% Used)",
                    category="Hardware",
                    severity="Critical",
                    confirmed_evidence=[
                        f"RAM usage is {ram_pct:.1f}% ({format_bytes(hw.memory.used_bytes)} / {format_bytes(hw.memory.total_bytes)}).",
                        f"Available RAM remaining: {format_bytes(hw.memory.available_bytes)}.",
                    ],
                    suspected_root_causes=[
                        "Memory leak or excessive browser/spreadsheet/JVM heap consumption.",
                        "Installed physical RAM may be undersized for current enterprise workloads.",
                    ],
                    confidence_and_limitations="High confidence from live OS virtual memory counters.",
                    recommended_steps=[
                        "Inspect top memory-consuming processes in System Administration.",
                        "Close unused browser tabs or duplicate application sessions cleanly.",
                        "Check pagefile/swap utilization and reboot if memory remains fragmented.",
                    ],
                    verification_steps=["Confirm RAM usage drops below 75% and swap pressure subsides."],
                    escalation_guidance="Escalate to Desktop Engineering to evaluate a RAM capacity upgrade.",
                    helpdesk_category="Hardware",
                    helpdesk_priority="High",
                )
            )
        elif ram_pct >= RAM_WARNING_THRESHOLD:
            findings.append(
                TroubleshootingFinding(
                    finding_id="TRB-HW-RAM-WARN",
                    title=f"Elevated Memory Utilization ({ram_pct:.1f}% Used)",
                    category="Hardware",
                    severity="Medium",
                    confirmed_evidence=[
                        f"RAM usage is {ram_pct:.1f}% ({format_bytes(hw.memory.used_bytes)} / {format_bytes(hw.memory.total_bytes)}).",
                    ],
                    suspected_root_causes=["Heavy multitasking or cached application working sets."],
                    confidence_and_limitations="High confidence from psutil memory counters.",
                    recommended_steps=[
                        "Review top memory consumers in System Administration.",
                        "Close non-essential background applications.",
                    ],
                    verification_steps=["Confirm memory utilization returns below 75%."],
                    escalation_guidance="Log an upgrade request if warning thresholds recur daily.",
                    helpdesk_category="Hardware",
                    helpdesk_priority="Medium",
                )
            )

        for disk in hw.logical_disks:
            if disk.percent_used is None:
                continue
            if disk.percent_used >= DISK_CRITICAL_THRESHOLD:
                low_disk_mounts.append(disk.mountpoint)
                findings.append(
                    TroubleshootingFinding(
                        finding_id=f"TRB-HW-DISK-{disk.mountpoint.replace(':', '').replace('\\', '')}",
                        title=f"Critical Low Disk Space on {disk.mountpoint} ({disk.percent_used:.1f}% Full)",
                        category="Hardware",
                        severity="Critical",
                        confirmed_evidence=[
                            f"Volume {disk.mountpoint} ({disk.fstype}) has only {format_bytes(disk.free_bytes)} free "
                            f"of {format_bytes(disk.total_bytes)} ({disk.percent_used:.1f}% used).",
                        ],
                        suspected_root_causes=[
                            "Accumulated Windows Update cache, user downloads, large log files, or PST/OST mail stores.",
                        ],
                        confidence_and_limitations="High confidence from filesystem capacity counters; per-folder breakdown is not scanned.",
                        recommended_steps=[
                            "Have the user clear browser caches, Recycle Bin, and temporary downloads.",
                            "Coordinate with IT Support to review Windows Update cleanup or stale user profiles.",
                        ],
                        verification_steps=[f"Confirm free space on {disk.mountpoint} exceeds 20% of volume capacity."],
                        escalation_guidance="Escalate to Endpoint Operations if OS drive (<10% free) risks update/pagefile failures.",
                        helpdesk_category="Hardware",
                        helpdesk_priority="Critical",
                    )
                )
            elif disk.percent_used >= DISK_WARNING_THRESHOLD:
                low_disk_mounts.append(disk.mountpoint)
                findings.append(
                    TroubleshootingFinding(
                        finding_id=f"TRB-HW-DISK-{disk.mountpoint.replace(':', '').replace('\\', '')}",
                        title=f"Low Disk Space Warning on {disk.mountpoint} ({disk.percent_used:.1f}% Full)",
                        category="Hardware",
                        severity="Medium",
                        confirmed_evidence=[
                            f"Volume {disk.mountpoint} is {disk.percent_used:.1f}% full ({format_bytes(disk.free_bytes)} free).",
                        ],
                        suspected_root_causes=["Growing application caches or unarchived local datasets."],
                        confidence_and_limitations="High confidence from filesystem capacity counters.",
                        recommended_steps=[
                            "Review large user files and archive approved data to network/OneDrive storage.",
                        ],
                        verification_steps=[f"Verify {disk.mountpoint} utilization drops below 80%."],
                        escalation_guidance="Escalate for storage expansion or profile cleanup if growth continues.",
                        helpdesk_category="Hardware",
                        helpdesk_priority="Medium",
                    )
                )

    if include_sys and processes:
        heavy_procs = [
            p
            for p in processes
            if p.memory_mb >= _PROCESS_MEMORY_THRESHOLD_MB or p.cpu_percent >= _PROCESS_CPU_THRESHOLD_PCT
        ]
        if heavy_procs:
            top = heavy_procs[:5]
            sev = "High" if (high_cpu or high_ram) else "Medium"
            findings.append(
                TroubleshootingFinding(
                    finding_id="TRB-SYS-PROC-HOG",
                    title="High Resource Consumption by Running Process(es)",
                    category="System",
                    severity=sev,
                    confirmed_evidence=[
                        f"{p.name} (PID {p.pid}): {p.memory_mb:.1f} MB RAM, {p.cpu_percent:.1f}% CPU"
                        for p in top
                    ],
                    suspected_root_causes=[
                        "Single application retaining excessive memory or spinning a worker thread.",
                    ],
                    confidence_and_limitations=(
                        "Process metrics exclude protected system processes that return AccessDenied without elevation."
                    ),
                    recommended_steps=[
                        "Verify with the user whether the listed application(s) are performing an expected task.",
                        "Save work and gracefully restart the offending user application if unresponsive.",
                    ],
                    verification_steps=["Confirm process CPU/RAM usage returns to normal bounds in System Administration."],
                    escalation_guidance="Escalate to Application Support if a corporate line-of-business app leaks memory repeatedly.",
                    helpdesk_category="Software",
                    helpdesk_priority="High" if sev == "High" else "Medium",
                )
            )

    if include_sys and os_info is not None and os_info.uptime_seconds is not None:
        uptime_days = os_info.uptime_seconds / 86400.0
        if uptime_days >= _LONG_UPTIME_DAYS:
            findings.append(
                TroubleshootingFinding(
                    finding_id="TRB-SYS-UPTIME",
                    title=f"Extended System Uptime ({uptime_days:.1f} Days Without Reboot)",
                    category="System",
                    severity="Low",
                    confirmed_evidence=[
                        f"System uptime is {os_info.uptime_display} (last boot: {os_info.boot_time_display}).",
                    ],
                    suspected_root_causes=[
                        "Pending Windows Updates awaiting restart or Fast Startup retaining kernel session state.",
                    ],
                    confidence_and_limitations="High confidence from OS boot timestamp.",
                    recommended_steps=[
                        "Schedule a controlled workstation restart after saving all user work.",
                    ],
                    verification_steps=["Confirm boot timestamp updates after restart."],
                    escalation_guidance="Coordinate maintenance window if workstation runs overnight batch jobs.",
                    helpdesk_category="Other",
                    helpdesk_priority="Low",
                )
            )

    # Cross-module slow computer performance correlation
    pressure_factors: list[str] = []
    if high_cpu and cpu_pct is not None:
        pressure_factors.append(f"CPU at {cpu_pct:.1f}%")
    if high_ram and ram_pct is not None:
        pressure_factors.append(f"RAM at {ram_pct:.1f}%")
    if low_disk_mounts:
        pressure_factors.append(f"Low disk on {', '.join(low_disk_mounts)}")
    if os_info and os_info.uptime_seconds and (os_info.uptime_seconds / 86400.0) >= _LONG_UPTIME_DAYS:
        pressure_factors.append(f"Uptime {os_info.uptime_display}")

    if len(pressure_factors) >= 2:
        findings.append(
            TroubleshootingFinding(
                finding_id="TRB-XMOD-PERF",
                title="Compound Slow Computer Performance Indicators Detected",
                category="Cross-Module",
                severity="High",
                confirmed_evidence=[f"Concurrent resource pressure observed: {'; '.join(pressure_factors)}."],
                suspected_root_causes=[
                    "Combined CPU/RAM contention and storage or pending-reboot overhead degrading UI responsiveness.",
                ],
                confidence_and_limitations="Correlates point-in-time hardware and process snapshots.",
                recommended_steps=[
                    "Address critical disk space or runaway user processes first.",
                    "Perform a clean restart after saving work to clear memory leaks and pending updates.",
                ],
                verification_steps=["Re-run Overview Dashboard and confirm CPU, RAM, and Disk return to Healthy status."],
                escalation_guidance="Escalate to Desktop Engineering for hardware lifecycle review if sluggishness persists.",
                helpdesk_category="Hardware",
                helpdesk_priority="High",
            )
        )


def _evaluate_network(
    net: NetworkSnapshot | None,
    ping_result: PingResult | None,
    dns_result: DnsResolutionResult | None,
    connectivity_result: ConnectivityProbeResult | None,
    findings: list[TroubleshootingFinding],
    limitations: list[str],
) -> None:
    """Evaluate passive network config and optional user-triggered probe results."""
    if net is None:
        return

    non_loopback = [a for a in net.adapters if "loopback" not in a.name.lower()]
    up_adapters = [a for a in non_loopback if a.status == "Up"]

    if not up_adapters:
        findings.append(
            TroubleshootingFinding(
                finding_id="TRB-NET-NOADAPTER",
                title="No Active Network Adapter Connected",
                category="Network",
                severity="Critical",
                confirmed_evidence=[
                    f"0 of {len(non_loopback)} non-loopback network adapters report status 'Up'.",
                ],
                suspected_root_causes=[
                    "Unplugged Ethernet patch cable, disabled Wi-Fi adapter, or disconnected docking station.",
                ],
                confidence_and_limitations="High confidence from local interface state counters.",
                recommended_steps=[
                    "Check physical Ethernet link lights or verify Wi-Fi radio is enabled.",
                    "Confirm adapter is not disabled in Windows Network Connections.",
                ],
                verification_steps=["Refresh Network Diagnostics and verify at least one adapter shows 'Up' with an IP."],
                escalation_guidance="Escalate to Desktop Support / Facilities if wall jack has no link.",
                helpdesk_category="Network",
                helpdesk_priority="Critical",
            )
        )
    else:
        if not net.default_gateways:
            findings.append(
                TroubleshootingFinding(
                    finding_id="TRB-NET-NOGW",
                    title="Missing Default Gateway on Active Adapter(s)",
                    category="Network",
                    severity="High",
                    confirmed_evidence=[
                        f"{len(up_adapters)} active adapter(s) detected, but no default IPv4/IPv6 gateway is configured.",
                    ],
                    suspected_root_causes=[
                        "DHCP lease failure (APIPA 169.254.x.x), misconfigured static IP, or disconnected VLAN.",
                    ],
                    confidence_and_limitations="High confidence from Get-NetIPConfiguration.",
                    recommended_steps=[
                        "Inspect adapter IPv4 addresses for 169.254.x.x (APIPA) indicating DHCP timeout.",
                        "Verify cable/SSID connection to the correct corporate network.",
                    ],
                    verification_steps=["Verify a valid Default Gateway appears in Network Diagnostics."],
                    escalation_guidance="Escalate to Network Operations if DHCP server is unreachable on the floor switch.",
                    helpdesk_category="Network",
                    helpdesk_priority="High",
                )
            )
        if not net.dns_servers:
            findings.append(
                TroubleshootingFinding(
                    finding_id="TRB-NET-NODNS",
                    title="No DNS Servers Configured",
                    category="Network",
                    severity="High",
                    confirmed_evidence=["No DNS server addresses are assigned to active network interfaces."],
                    suspected_root_causes=["Incomplete DHCP options or VPN adapter route/DNS conflict."],
                    confidence_and_limitations="High confidence from Windows IP configuration.",
                    recommended_steps=[
                        "Check DHCP status and VPN client connection state.",
                        "Test resolving an IP vs. hostname in Network Diagnostics.",
                    ],
                    verification_steps=["Confirm enterprise DNS servers appear and hostname resolution succeeds."],
                    escalation_guidance="Escalate to Network Engineering if DHCP is omitting DNS options.",
                    helpdesk_category="Network",
                    helpdesk_priority="High",
                )
            )

    if net.wifi.available and net.wifi.state.lower() == "connected" and net.wifi.signal_percent is not None:
        if net.wifi.signal_percent < 40:
            findings.append(
                TroubleshootingFinding(
                    finding_id="TRB-NET-WIFI-WEAK",
                    title=f"Weak Wi-Fi Signal Strength ({net.wifi.signal_percent}%)",
                    category="Network",
                    severity="Medium",
                    confirmed_evidence=[
                        f"Wi-Fi SSID '{net.wifi.ssid}' on {net.wifi.band} reports signal {net.wifi.signal_percent}%.",
                    ],
                    suspected_root_causes=[
                        "Distance from access point, physical shielding, or 2.4 GHz co-channel interference.",
                    ],
                    confidence_and_limitations="Point-in-time netsh WLAN interface reading.",
                    recommended_steps=[
                        "Relocate closer to an enterprise access point or connect via wired Ethernet dock.",
                    ],
                    verification_steps=["Verify Wi-Fi signal rises above 60% or wired adapter is Up."],
                    escalation_guidance="Report dead zones to Workplace Network Team with floor/location details.",
                    helpdesk_category="Network",
                    helpdesk_priority="Medium",
                )
            )

    # User-triggered active probes (never executed automatically)
    if ping_result is None and dns_result is None and connectivity_result is None:
        limitations.append(
            "Active external network probes (Ping, DNS lookup, Connectivity Check) were not triggered; "
            "run them in Network Diagnostics or opt into active probe inclusion to test live reachability."
        )

    if dns_result is not None and not dns_result.success:
        findings.append(
            TroubleshootingFinding(
                finding_id="TRB-NET-DNS-FAIL",
                title=f"DNS Resolution Failure ({dns_result.hostname})",
                category="Network",
                severity="High",
                confirmed_evidence=[
                    f"DNS lookup for '{dns_result.hostname}' failed: {dns_result.error or 'Unknown error'}.",
                ],
                suspected_root_causes=[
                    "Unreachable internal DNS server, misconfigured DNS suffix, or blocked UDP/TCP port 53.",
                ],
                confidence_and_limitations="Observed from user-triggered socket.getaddrinfo probe.",
                recommended_steps=[
                    "Test pinging the configured DNS server IP directly.",
                    "Confirm spelling of the target FQDN and check VPN split-DNS behavior.",
                ],
                verification_steps=["Re-run DNS Resolution Test and confirm IPv4/IPv6 addresses return."],
                escalation_guidance="Escalate to Network/DNS Operations if internal corporate domains fail to resolve.",
                helpdesk_category="Network",
                helpdesk_priority="High",
            )
        )

    if ping_result is not None:
        if not ping_result.success:
            if ping_result.failure_reason == "DNS Resolution Failed":
                findings.append(
                    TroubleshootingFinding(
                        finding_id="TRB-NET-PING-DNS",
                        title=f"Ping Target Unresolvable via DNS ({ping_result.target})",
                        category="Network",
                        severity="High",
                        confirmed_evidence=[f"Pre-ping DNS lookup failed for {ping_result.target}."],
                        suspected_root_causes=["DNS outage, incorrect hostname, or isolated DNS zone."],
                        confidence_and_limitations="Distinguished DNS failure before ICMP transmission.",
                        recommended_steps=["Verify target hostname and test direct IP reachability."],
                        verification_steps=["Confirm DNS resolution succeeds prior to pinging."],
                        escalation_guidance="Escalate to NetOps if corporate DNS records are missing.",
                        helpdesk_category="Network",
                        helpdesk_priority="High",
                    )
                )
            elif ping_result.failure_reason == "Destination Unreachable":
                findings.append(
                    TroubleshootingFinding(
                        finding_id="TRB-NET-PING-UNREACH",
                        title=f"Destination Host/Network Unreachable ({ping_result.target})",
                        category="Network",
                        severity="High",
                        confirmed_evidence=[
                            f"ICMP test to {ping_result.target} ({ping_result.resolved_ip}) reported Destination Unreachable.",
                        ],
                        suspected_root_causes=["Missing local route, inactive VPN tunnel, or host offline."],
                        confidence_and_limitations="Confirmed via Windows ping output.",
                        recommended_steps=[
                            "Verify corporate VPN status if targeting an internal subnet.",
                            "Run Traceroute to locate where routing stops.",
                        ],
                        verification_steps=["Re-run Ping and confirm 0% packet loss."],
                        escalation_guidance="Escalate to Network Operations with Traceroute output.",
                        helpdesk_category="Network",
                        helpdesk_priority="High",
                    )
                )
            elif ping_result.failure_reason == "Timeout / ICMP Blocked":
                findings.append(
                    TroubleshootingFinding(
                        finding_id="TRB-NET-ICMP-TIMEOUT",
                        title=f"ICMP Echo Timed Out for {ping_result.target} (Possible ICMP Filtering)",
                        category="Network",
                        severity="Informational",
                        confirmed_evidence=[
                            f"Sent {ping_result.packets_sent} ICMP packets to {ping_result.target} ({ping_result.resolved_ip}); 0 replies received.",
                        ],
                        suspected_root_causes=[
                            "Upstream firewall or destination host drops ICMP echo requests (does not prove internet outage).",
                        ],
                        confidence_and_limitations="ICMP timeout alone cannot distinguish firewall ICMP filtering from packet drop.",
                        recommended_steps=[
                            "Run the multi-layer Internet Connectivity Check (TCP/443) to confirm application reachability.",
                        ],
                        verification_steps=["Confirm HTTPS/TCP connectivity succeeds in Network Diagnostics."],
                        escalation_guidance="Escalate only if TCP/application traffic also fails.",
                        helpdesk_category="Network",
                        helpdesk_priority="Low",
                    )
                )
        else:
            loss = ping_result.packet_loss_percent or 0.0
            avg_ms = ping_result.avg_ms or 0.0
            if loss > 0.0 or avg_ms > 150.0:
                findings.append(
                    TroubleshootingFinding(
                        finding_id="TRB-NET-LATENCY-LOSS",
                        title=f"High Latency or Packet Loss to {ping_result.target}",
                        category="Network",
                        severity="High" if loss >= 25.0 else "Medium",
                        confirmed_evidence=[
                            f"Packet loss: {loss:.0f}% | Average RTT: {avg_ms:.0f} ms (Max: {ping_result.max_ms} ms).",
                        ],
                        suspected_root_causes=[
                            "Wireless interference, WAN congestion, VPN hairpinning, or faulty patch cabling.",
                        ],
                        confidence_and_limitations="Based on bounded 1-6 packet ICMP sample.",
                        recommended_steps=[
                            "Test gateway ping vs. external target to isolate local vs. upstream loss.",
                            "Switch from Wi-Fi to wired Ethernet if available and re-test.",
                        ],
                        verification_steps=["Confirm 0% packet loss and RTT < 100 ms."],
                        escalation_guidance="Escalate to Network Operations with local gateway vs. WAN ping comparison.",
                        helpdesk_category="Network",
                        helpdesk_priority="High" if loss >= 25.0 else "Medium",
                    )
                )

    if connectivity_result is not None and connectivity_result.classification in {
        "DNS Resolution Failure",
        "Local Network / Gateway Unreachable",
        "Limited / Offline",
    }:
        sev = "Critical" if connectivity_result.classification != "DNS Resolution Failure" else "High"
        findings.append(
            TroubleshootingFinding(
                finding_id="TRB-NET-CONN",
                title=f"Internet / Network Connectivity Issue: {connectivity_result.classification}",
                category="Network",
                severity=sev,
                confirmed_evidence=[
                    connectivity_result.summary,
                    f"DNS check: {connectivity_result.dns_detail}",
                ],
                suspected_root_causes=[
                    "Gateway routing failure, captive portal, proxy misconfiguration, or DNS server outage.",
                ],
                confidence_and_limitations="Observed from user-triggered TCP/DNS/gateway probe.",
                recommended_steps=[
                    "Verify proxy/VPN authentication status and default gateway reachability.",
                    "Confirm DNS resolution works independently of ICMP ping.",
                ],
                verification_steps=["Re-run Internet Connectivity Check and confirm 'Connected'."],
                escalation_guidance="Escalate to Tier 2 Network Operations if local link is up but gateway/outbound fails.",
                helpdesk_category="Network",
                helpdesk_priority=sev,
            )
        )


def _evaluate_security(
    sec: SecuritySnapshot | None,
    findings: list[TroubleshootingFinding],
    limitations: list[str],
) -> None:
    """Evaluate firewall, antivirus, signatures, UAC, and encryption posture."""
    if sec is None:
        return

    if not sec.firewall_profiles:
        limitations.append("Windows Firewall profile status could not be retrieved.")
    else:
        disabled_fw = [p.profile_name for p in sec.firewall_profiles if p.enabled is False]
        if disabled_fw:
            findings.append(
                TroubleshootingFinding(
                    finding_id="TRB-SEC-FW-OFF",
                    title=f"Windows Firewall Disabled ({', '.join(disabled_fw)})",
                    category="Security",
                    severity="Critical",
                    confirmed_evidence=[
                        f"Firewall profile(s) reporting Disabled: {', '.join(disabled_fw)}.",
                    ],
                    suspected_root_causes=[
                        "Local policy override, troubleshooting leftover, or third-party security suite takeover.",
                    ],
                    confidence_and_limitations="Read-only query of Windows Firewall profiles; third-party host firewalls are not separately audited.",
                    recommended_steps=[
                        "Check whether an approved third-party endpoint firewall is intentionally managing host filtering.",
                        "Do not leave endpoint unprotected; coordinate with Endpoint Security to restore firewall policy.",
                    ],
                    verification_steps=["Re-run Information Security assessment and confirm Domain/Private/Public profiles show Enabled."],
                    escalation_guidance="Escalate immediately to Information Security / Endpoint Ops for financial compliance.",
                    helpdesk_category="Security",
                    helpdesk_priority="Critical",
                )
            )

    any_reg_av_on = any(av.enabled_state == "Enabled" for av in sec.registered_antivirus)
    if sec.defender.available and sec.defender.real_time_protection_enabled is False and not any_reg_av_on:
        findings.append(
            TroubleshootingFinding(
                finding_id="TRB-SEC-AV-OFF",
                title="Antivirus Real-Time Protection Disabled",
                category="Security",
                severity="Critical",
                confirmed_evidence=[
                    "Microsoft Defender RealTimeProtectionEnabled is False.",
                    "No third-party SecurityCenter2 antivirus product reports Enabled state.",
                ],
                suspected_root_causes=[
                    "Stopped AV service, tamper/policy misconfiguration, or expired security agent.",
                ],
                confidence_and_limitations="High confidence from Get-MpComputerStatus and SecurityCenter2.",
                recommended_steps=[
                    "Isolate workstation from sensitive trading/banking shares if unauthorized tampering is suspected.",
                    "Contact SOC / Endpoint Engineering to restore real-time protection.",
                ],
                verification_steps=["Confirm Active real-time protection in Information Security."],
                escalation_guidance="Escalate immediately to SOC / Information Security.",
                helpdesk_category="Security",
                helpdesk_priority="Critical",
            )
        )
    elif not sec.defender.available and not any_reg_av_on:
        findings.append(
            TroubleshootingFinding(
                finding_id="TRB-SEC-AV-UNK",
                title="Active Antivirus Protection Could Not Be Confirmed",
                category="Security",
                severity="Medium",
                confirmed_evidence=[
                    "Microsoft Defender telemetry is unavailable and no active SecurityCenter2 AV was detected.",
                ],
                suspected_root_causes=["Enterprise EDR agent uses a custom provider or WMI query was restricted."],
                confidence_and_limitations="Low confidence due to unavailable AV telemetry.",
                recommended_steps=["Verify installed EDR/AV agent in System Administration -> Installed Software."],
                verification_steps=["Confirm approved endpoint security agent is running and checking in with MDM/EDR console."],
                escalation_guidance="Escalate to SOC if no approved EDR agent is installed.",
                helpdesk_category="Security",
                helpdesk_priority="Medium",
            )
        )

    outdated_sigs = [av.display_name for av in sec.registered_antivirus if av.signature_state == "Out of Date"]
    if outdated_sigs:
        findings.append(
            TroubleshootingFinding(
                finding_id="TRB-SEC-AV-SIG",
                title=f"Outdated Antivirus Signatures ({', '.join(outdated_sigs)})",
                category="Security",
                severity="High",
                confirmed_evidence=[
                    f"SecurityCenter2 reports 'Out of Date' signature state for: {', '.join(outdated_sigs)}.",
                ],
                suspected_root_causes=["Blocked update server access, offline endpoint, or stalled AV update task."],
                confidence_and_limitations="Based on SecurityCenter2 productState bitflags.",
                recommended_steps=[
                    "Confirm internet/WSUS/management server connectivity.",
                    "Trigger a signature update from the approved antivirus client.",
                ],
                verification_steps=["Re-run Information Security and confirm signature state shows 'Up to Date'."],
                escalation_guidance="Escalate to Endpoint Security if definitions fail to update.",
                helpdesk_category="Security",
                helpdesk_priority="High",
            )
        )

    if sec.uac.available:
        if sec.uac.enable_lua == 0:
            findings.append(
                TroubleshootingFinding(
                    finding_id="TRB-SEC-UAC-OFF",
                    title="User Account Control (UAC) Disabled",
                    category="Security",
                    severity="Critical",
                    confirmed_evidence=["Registry key EnableLUA is set to 0."],
                    suspected_root_causes=["Non-compliant local security policy or manual registry change."],
                    confidence_and_limitations="High confidence from HKLM UAC policy registry key.",
                    recommended_steps=[
                        "Do not modify registry directly in standard-user context; report policy drift to Desktop Engineering.",
                    ],
                    verification_steps=["Confirm EnableLUA = 1 after GPO/MDM policy refresh."],
                    escalation_guidance="Escalate to Desktop Engineering / InfoSec for compliance remediation.",
                    helpdesk_category="Security",
                    helpdesk_priority="Critical",
                )
            )
        elif sec.uac.enable_lua == 1 and sec.uac.consent_prompt_admin == 0:
            findings.append(
                TroubleshootingFinding(
                    finding_id="TRB-SEC-UAC-SILENT",
                    title="UAC Configured for Silent Elevation (No Prompt)",
                    category="Security",
                    severity="Medium",
                    confirmed_evidence=[
                        "EnableLUA=1, but ConsentPromptBehaviorAdmin=0 (Elevate without prompting).",
                    ],
                    suspected_root_causes=["Permissive local policy or legacy compatibility setting."],
                    confidence_and_limitations="High confidence from HKLM UAC registry policy.",
                    recommended_steps=[
                        "Review against financial-sector endpoint hardening baseline (recommend consent/credential prompt).",
                    ],
                    verification_steps=["Verify ConsentPromptBehaviorAdmin reflects hardened corporate GPO."],
                    escalation_guidance="Escalate to Desktop Engineering / InfoSec if unapproved.",
                    helpdesk_category="Security",
                    helpdesk_priority="Medium",
                )
            )
    else:
        limitations.append("UAC registry policy could not be read.")

    unprotected = [v.mount_point for v in sec.bitlocker_volumes if v.protection_status.lower() == "off"]
    if unprotected:
        findings.append(
            TroubleshootingFinding(
                finding_id="TRB-SEC-BL-OFF",
                title=f"Disk Encryption Disabled on Volume(s): {', '.join(unprotected)}",
                category="Security",
                severity="High",
                confirmed_evidence=[f"BitLocker ProtectionStatus is 'Off' for {', '.join(unprotected)}."],
                suspected_root_causes=["BitLocker suspended for maintenance or never provisioned."],
                confidence_and_limitations="Read from Get-BitLockerVolume.",
                recommended_steps=[
                    "Verify whether BitLocker was temporarily suspended during BIOS/firmware updates.",
                    "Coordinate with Endpoint Security to enable encryption and escrow recovery keys.",
                ],
                verification_steps=["Confirm ProtectionStatus shows 'On' and 100% encrypted."],
                escalation_guidance="Escalate immediately to Information Security for mobile/laptop devices.",
                helpdesk_category="Security",
                helpdesk_priority="High",
            )
        )
    elif not sec.bitlocker_volumes:
        limitations.append(f"BitLocker volume inspection unavailable: {sec.bitlocker_status_note}")
        findings.append(
            TroubleshootingFinding(
                finding_id="TRB-SEC-BL-UNAVAIL",
                title="Disk Encryption Status Unavailable in Standard-User Mode",
                category="Security",
                severity="Informational",
                confirmed_evidence=[sec.bitlocker_status_note],
                suspected_root_causes=[
                    "Standard user privileges or missing BitLocker PowerShell module prevent local volume encryption readback.",
                ],
                confidence_and_limitations="Cannot confirm encryption state without elevated admin/MDM access.",
                recommended_steps=[
                    "Verify disk encryption compliance in the enterprise MDM/Intune or elevated admin console.",
                ],
                verification_steps=["Confirm BitLocker compliance status in central endpoint management."],
                escalation_guidance="Escalate to Desktop Support if MDM reports non-compliant encryption.",
                helpdesk_category="Security",
                helpdesk_priority="Low",
            )
        )


def evaluate_troubleshooting_rules(
    *,
    categories: tuple[str, ...] = ASSESSMENT_CATEGORIES,
    hardware_snapshot: HardwareSnapshot | None = None,
    os_info: OsInfo | None = None,
    processes: list[ProcessInfo] | None = None,
    network_snapshot: NetworkSnapshot | None = None,
    security_snapshot: SecuritySnapshot | None = None,
    ping_result: PingResult | None = None,
    dns_result: DnsResolutionResult | None = None,
    connectivity_result: ConnectivityProbeResult | None = None,
) -> TroubleshootingAssessment:
    """Evaluate deterministic troubleshooting rules over supplied or collected telemetry."""
    selected = tuple(cat for cat in categories if cat in ASSESSMENT_CATEGORIES) or ASSESSMENT_CATEGORIES
    findings: list[TroubleshootingFinding] = []
    limitations: list[str] = []

    include_hw = "Hardware" in selected
    include_sys = "System" in selected
    if include_hw or include_sys:
        _evaluate_hardware_and_system(
            hw=hardware_snapshot,
            os_info=os_info,
            processes=processes or [],
            findings=findings,
            limitations=limitations,
            include_hw=include_hw,
            include_sys=include_sys,
        )

    if "Network" in selected:
        _evaluate_network(
            net=network_snapshot,
            ping_result=ping_result,
            dns_result=dns_result,
            connectivity_result=connectivity_result,
            findings=findings,
            limitations=limitations,
        )

    if "Security" in selected:
        _evaluate_security(
            sec=security_snapshot,
            findings=findings,
            limitations=limitations,
        )

    if not findings:
        findings.append(
            TroubleshootingFinding(
                finding_id="TRB-GEN-HEALTHY",
                title="No Actionable Issues Detected Across Evaluated Checks",
                category="Cross-Module",
                severity="Informational",
                confirmed_evidence=[
                    f"Evaluated categories ({', '.join(selected)}) returned metrics within healthy baseline thresholds.",
                ],
                suspected_root_causes=["No active fault pattern matched current diagnostic rules."],
                confidence_and_limitations=(
                    "Baseline rules cover common endpoint indicators and do not replace deep application logs or active probes."
                ),
                recommended_steps=["Continue periodic monitoring or run targeted probes if an intermittent symptom occurs."],
                verification_steps=["No remediation required."],
                escalation_guidance="Escalate with detailed user reproduction steps if a symptom is not captured by baseline telemetry.",
                helpdesk_category="Other",
                helpdesk_priority="Low",
            )
        )

    findings.sort(key=lambda f: (_SEVERITY_RANK.get(f.severity, 99), f.finding_id))
    severity_counts = {sev: 0 for sev in SEVERITY_LEVELS}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    return TroubleshootingAssessment(
        assessed_at=format_timestamp(time.time()),
        categories_evaluated=selected,
        findings=findings,
        severity_counts=severity_counts,
        limitations=limitations,
        hardware_snapshot=hardware_snapshot,
        os_info=os_info,
        processes=processes or [],
        network_snapshot=network_snapshot,
        security_snapshot=security_snapshot,
    )


def run_troubleshooting_assessment(
    *,
    categories: tuple[str, ...] = ASSESSMENT_CATEGORIES,
    ping_result: PingResult | None = None,
    dns_result: DnsResolutionResult | None = None,
    connectivity_result: ConnectivityProbeResult | None = None,
    include_hotfixes: bool = False,
) -> TroubleshootingAssessment:
    """
    Execute read-only telemetry collection for requested categories and evaluate rules.

    Never executes external network probes automatically unless explicitly passed in.
    """
    selected = tuple(cat for cat in categories if cat in ASSESSMENT_CATEGORIES) or ASSESSMENT_CATEGORIES
    hw = collect_hardware_snapshot() if "Hardware" in selected else None
    os_info = get_os_info() if "System" in selected else None
    processes: list[ProcessInfo] = []
    if "System" in selected:
        _, processes = get_running_processes(limit=25, sort_by="memory_mb")
    net = collect_network_snapshot() if "Network" in selected else None
    sec = collect_security_snapshot(include_hotfixes=include_hotfixes) if "Security" in selected else None

    return evaluate_troubleshooting_rules(
        categories=selected,
        hardware_snapshot=hw,
        os_info=os_info,
        processes=processes,
        network_snapshot=net,
        security_snapshot=sec,
        ping_result=ping_result,
        dns_result=dns_result,
        connectivity_result=connectivity_result,
    )


def create_ticket_from_finding(
    finding: TroubleshootingFinding,
    *,
    requester_name: str,
    department: str,
    assigned_technician: str = "Tier 1 Support",
    additional_notes: str = "",
    db_path: Path | str = DEFAULT_DB_PATH,
) -> Ticket:
    """Create a persisted IT Help Desk incident from a confirmed troubleshooting finding."""
    evidence_block = "\n".join(f"- {item}" for item in finding.confirmed_evidence)
    causes_block = "\n".join(f"- {item}" for item in finding.suspected_root_causes)
    steps_block = "\n".join(f"- {item}" for item in finding.recommended_steps)
    verify_block = "\n".join(f"- {item}" for item in finding.verification_steps)

    description = (
        f"[Troubleshooting Finding {finding.finding_id} | Severity: {finding.severity}]\n\n"
        f"Confirmed Diagnostic Evidence:\n{evidence_block}\n\n"
        f"Suspected Root Causes:\n{causes_block}\n\n"
        f"Confidence & Limitations:\n{finding.confidence_and_limitations}"
    )
    if additional_notes.strip():
        description += f"\n\nAnalyst Context:\n{additional_notes.strip()}"

    troubleshooting_notes = (
        f"Recommended Steps:\n{steps_block}\n\n"
        f"Verification Steps:\n{verify_block}\n\n"
        f"Escalation Guidance: {finding.escalation_guidance}"
    )

    return create_ticket(
        ticket_type="Incident",
        title=f"[{finding.finding_id}] {finding.title}",
        description=description,
        requester_name=requester_name,
        department=department,
        category=finding.helpdesk_category,
        priority=finding.helpdesk_priority,
        assigned_technician=assigned_technician,
        troubleshooting_notes=troubleshooting_notes,
        db_path=db_path,
    )
