"""Read-only Windows network diagnostics and connectivity troubleshooting service."""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

import psutil

from src.config.settings import (
    PING_TIMEOUT_SECONDS,
    POWERSHELL_TIMEOUT_SECONDS,
    TCP_PROBE_TIMEOUT_SECONDS,
    TRACEROUTE_TIMEOUT_SECONDS,
    UNAVAILABLE_VALUE,
    UNKNOWN_VALUE,
)
from src.utils.formatting import format_timestamp, safe_str
from src.utils.powershell import is_windows, run_powershell_json

_HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
_DISALLOWED_CHARS = re.compile(r"[;&|`$()<>\r\n\t'\"\\/\s]")

_PING_STATS_RE = re.compile(
    r"Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*(\d+)\s*\((\d+)%\s*loss\)",
    re.IGNORECASE,
)
_PING_RTT_RE = re.compile(
    r"Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms",
    re.IGNORECASE,
)
_TRACERT_HOP_RE = re.compile(
    r"^\s*(\d+)\s+([<\d*]+\s*(?:ms)?)\s+([<\d*]+\s*(?:ms)?)\s+([<\d*]+\s*(?:ms)?)\s+(.+?)\s*$"
)


@dataclass(frozen=True)
class NetworkAdapterInfo:
    """Network interface configuration, addresses, and I/O counters."""

    name: str
    description: str
    status: str
    speed_mbps: int | None
    mtu: int | None
    mac_address: str
    ipv4_addresses: list[str]
    ipv6_addresses: list[str]
    default_gateways: list[str]
    dns_servers: list[str]
    bytes_sent: int | None
    bytes_recv: int | None
    packets_sent: int | None
    packets_recv: int | None
    errin: int | None
    errout: int | None


@dataclass(frozen=True)
class WifiInfo:
    """Wireless interface and signal telemetry when a Wi-Fi adapter is available."""

    available: bool
    interface_name: str
    state: str
    ssid: str
    bssid: str
    radio_type: str
    authentication: str
    cipher: str
    band: str
    channel: str
    signal_percent: int | None
    receive_rate_mbps: str
    transmit_rate_mbps: str
    status: str


@dataclass(frozen=True)
class PingResult:
    """Results from a validated, bounded ICMP echo test."""

    target: str
    resolved_ip: str
    success: bool
    packets_sent: int
    packets_received: int
    packet_loss_percent: float | None
    min_ms: float | None
    avg_ms: float | None
    max_ms: float | None
    failure_reason: str | None
    raw_output: str
    executed_at: str


@dataclass(frozen=True)
class DnsResolutionResult:
    """Results from a hostname DNS lookup."""

    hostname: str
    success: bool
    ipv4_addresses: list[str]
    ipv6_addresses: list[str]
    latency_ms: float | None
    error: str | None
    executed_at: str


@dataclass(frozen=True)
class TracerouteHop:
    """Single parsed hop from Windows tracert output."""

    hop: int
    rtt_1: str
    rtt_2: str
    rtt_3: str
    address: str


@dataclass(frozen=True)
class TracerouteResult:
    """Results from a bounded traceroute execution."""

    target: str
    success: bool
    timed_out: bool
    hops: list[TracerouteHop]
    error: str | None
    raw_output: str
    executed_at: str


@dataclass(frozen=True)
class ConnectivityProbeResult:
    """Combined gateway, DNS, and TCP reachability classification."""

    dns_ok: bool
    dns_detail: str
    tcp_checks: list[dict[str, Any]]
    gateway_ping: PingResult | None
    classification: str
    summary: str
    executed_at: str


@dataclass(frozen=True)
class NetworkRecommendation:
    """Rule-based network troubleshooting guidance."""

    severity: str
    title: str
    explanation: str
    steps: list[str]


@dataclass(frozen=True)
class NetworkSnapshot:
    """Passive local network adapter, routing, DNS, and Wi-Fi snapshot."""

    collected_at: str
    adapters: list[NetworkAdapterInfo]
    default_gateways: list[str]
    dns_servers: list[str]
    total_bytes_sent: int | None
    total_bytes_recv: int | None
    wifi: WifiInfo
    recommendations: list[NetworkRecommendation]
    warnings: list[str] = field(default_factory=list)


def validate_network_target(target: str) -> tuple[bool, str, str | None]:
    """
    Validate a user-supplied IP address or hostname against strict allowlists.

    Rejects empty strings, leading dashes (flag injection), whitespace, and shell
    metacharacters before any subprocess or socket call is made.
    """
    cleaned = (target or "").strip()
    if not cleaned:
        return False, "", "Target host or IP address cannot be empty."
    if cleaned.startswith("-"):
        return False, cleaned, "Target cannot start with '-'."
    if _DISALLOWED_CHARS.search(cleaned):
        return False, cleaned, "Target contains disallowed characters or whitespace."

    try:
        ipaddress.ip_address(cleaned)
        return True, cleaned, None
    except ValueError:
        pass

    if _HOSTNAME_PATTERN.match(cleaned):
        return True, cleaned, None

    return False, cleaned, "Enter a valid IPv4/IPv6 address or RFC-compliant hostname."


def _is_ip_literal(value: str) -> bool:
    """Return True if value parses as an IPv4 or IPv6 literal."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _get_windows_ip_metadata(warnings: list[str] | None = None) -> dict[str, dict[str, Any]]:
    """Query per-adapter descriptions, gateways, and DNS servers via Get-NetIPConfiguration."""
    if not is_windows():
        return {}

    script = r"""
$configs = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        InterfaceAlias       = $_.InterfaceAlias
        InterfaceDescription = $_.InterfaceDescription
        IPv4Gateway          = if ($_.IPv4DefaultGateway) { @($_.IPv4DefaultGateway.NextHop) } else { @() }
        IPv6Gateway          = if ($_.IPv6DefaultGateway) { @($_.IPv6DefaultGateway.NextHop) } else { @() }
        DnsServers           = if ($_.DNSServer) { @($_.DNSServer.ServerAddresses) } else { @() }
    }
})
$configs | ConvertTo-Json -Depth 3 -Compress
"""
    res = run_powershell_json(script, timeout=POWERSHELL_TIMEOUT_SECONDS)
    if not res.success:
        if warnings is not None and res.error:
            warnings.append(f"Windows IP gateway/DNS metadata unavailable: {res.error}")
        return {}

    rows = res.data if isinstance(res.data, list) else ([res.data] if isinstance(res.data, dict) else [])
    by_alias: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        alias = safe_str(row.get("InterfaceAlias"), fallback="")
        if alias:
            by_alias[alias.lower()] = row
    return by_alias


def _as_str_list(value: Any) -> list[str]:
    """Normalize a single string or list of strings into a deduplicated list."""
    if value is None:
        return []
    raw_items = [value] if isinstance(value, str) else (list(value) if isinstance(value, list) else [])
    seen: set[str] = set()
    cleaned: list[str] = []
    for item in raw_items:
        text = safe_str(item, fallback="")
        if text and text not in seen:
            seen.add(text)
            cleaned.append(text)
    return cleaned


def get_network_adapters(warnings: list[str] | None = None) -> list[NetworkAdapterInfo]:
    """Collect network adapter status, IPv4/IPv6, MAC, gateway, DNS, and I/O stats."""
    try:
        addrs_map = psutil.net_if_addrs()
    except Exception as exc:
        if warnings is not None:
            warnings.append(f"Unable to enumerate network interfaces: {exc}")
        return []

    try:
        stats_map = psutil.net_if_stats()
    except Exception:
        stats_map = {}

    try:
        io_map = psutil.net_io_counters(pernic=True)
    except Exception:
        io_map = {}

    win_meta = _get_windows_ip_metadata(warnings=warnings)
    af_link = getattr(psutil, "AF_LINK", None)
    adapters: list[NetworkAdapterInfo] = []

    for nic_name, addr_list in addrs_map.items():
        ipv4_list: list[str] = []
        ipv6_list: list[str] = []
        mac_address = UNAVAILABLE_VALUE

        for addr in addr_list:
            if addr.family == socket.AF_INET:
                ip_str = addr.address
                if addr.netmask:
                    ip_str = f"{addr.address} / {addr.netmask}"
                ipv4_list.append(ip_str)
            elif addr.family == socket.AF_INET6:
                clean_v6 = addr.address.split("%")[0]
                ipv6_list.append(clean_v6)
            elif af_link is not None and addr.family == af_link:
                if addr.address:
                    mac_address = addr.address.replace("-", ":").upper()

        nic_stat = stats_map.get(nic_name)
        is_up = nic_stat.isup if nic_stat is not None else None
        status_str = "Up" if is_up is True else ("Down" if is_up is False else UNKNOWN_VALUE)
        speed_mbps = int(nic_stat.speed) if nic_stat is not None and nic_stat.speed else None
        mtu = int(nic_stat.mtu) if nic_stat is not None and nic_stat.mtu else None

        nic_io = io_map.get(nic_name)
        meta = win_meta.get(nic_name.lower(), {})
        gateways = _as_str_list(meta.get("IPv4Gateway")) + _as_str_list(meta.get("IPv6Gateway"))
        dns_servers = _as_str_list(meta.get("DnsServers"))

        adapters.append(
            NetworkAdapterInfo(
                name=nic_name,
                description=safe_str(meta.get("InterfaceDescription"), fallback=nic_name),
                status=status_str,
                speed_mbps=speed_mbps,
                mtu=mtu,
                mac_address=mac_address,
                ipv4_addresses=ipv4_list,
                ipv6_addresses=ipv6_list,
                default_gateways=gateways,
                dns_servers=dns_servers,
                bytes_sent=int(nic_io.bytes_sent) if nic_io is not None else None,
                bytes_recv=int(nic_io.bytes_recv) if nic_io is not None else None,
                packets_sent=int(nic_io.packets_sent) if nic_io is not None else None,
                packets_recv=int(nic_io.packets_recv) if nic_io is not None else None,
                errin=int(nic_io.errin) if nic_io is not None else None,
                errout=int(nic_io.errout) if nic_io is not None else None,
            )
        )

    # Sort Up physical/primary adapters first, loopback last.
    adapters.sort(
        key=lambda a: (
            "loopback" in a.name.lower(),
            a.status != "Up",
            not bool(a.default_gateways),
            a.name.lower(),
        )
    )
    return adapters


def _parse_wlan_output(raw_output: str) -> WifiInfo:
    """Parse `netsh wlan show interfaces` output into structured Wi-Fi telemetry."""
    fields: dict[str, str] = {}
    for line in raw_output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        cleaned_key = key.strip().lower()
        cleaned_val = value.strip()
        if cleaned_key and cleaned_key not in fields:
            fields[cleaned_key] = cleaned_val

    state = safe_str(fields.get("state"), fallback=UNAVAILABLE_VALUE)
    if not fields or "no wireless interface" in raw_output.lower():
        return WifiInfo(
            available=False,
            interface_name=UNAVAILABLE_VALUE,
            state=UNAVAILABLE_VALUE,
            ssid=UNAVAILABLE_VALUE,
            bssid=UNAVAILABLE_VALUE,
            radio_type=UNAVAILABLE_VALUE,
            authentication=UNAVAILABLE_VALUE,
            cipher=UNAVAILABLE_VALUE,
            band=UNAVAILABLE_VALUE,
            channel=UNAVAILABLE_VALUE,
            signal_percent=None,
            receive_rate_mbps=UNAVAILABLE_VALUE,
            transmit_rate_mbps=UNAVAILABLE_VALUE,
            status=UNAVAILABLE_VALUE,
        )

    signal_raw = fields.get("signal", "").replace("%", "").strip()
    signal_pct = int(signal_raw) if signal_raw.isdigit() else None

    if state.lower() != "connected":
        wifi_status = "Warning" if state != UNAVAILABLE_VALUE else UNAVAILABLE_VALUE
    elif signal_pct is None:
        wifi_status = UNKNOWN_VALUE
    elif signal_pct < 35:
        wifi_status = "Critical"
    elif signal_pct < 60:
        wifi_status = "Warning"
    else:
        wifi_status = "Healthy"

    return WifiInfo(
        available=True,
        interface_name=safe_str(fields.get("name")),
        state=state.title() if state != UNAVAILABLE_VALUE else UNAVAILABLE_VALUE,
        ssid=safe_str(fields.get("ssid")),
        bssid=safe_str(fields.get("bssid")),
        radio_type=safe_str(fields.get("radio type")),
        authentication=safe_str(fields.get("authentication")),
        cipher=safe_str(fields.get("cipher")),
        band=safe_str(fields.get("band")),
        channel=safe_str(fields.get("channel")),
        signal_percent=signal_pct,
        receive_rate_mbps=safe_str(fields.get("receive rate (mbps)")),
        transmit_rate_mbps=safe_str(fields.get("transmit rate (mbps)")),
        status=wifi_status,
    )


def get_wifi_info(warnings: list[str] | None = None) -> WifiInfo:
    """Query local Wi-Fi connection details safely via netsh."""
    if not is_windows():
        return _parse_wlan_output("")

    try:
        completed = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=POWERSHELL_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        if warnings is not None:
            warnings.append("Wi-Fi interface query timed out.")
        return _parse_wlan_output("")
    except (FileNotFoundError, OSError) as exc:
        if warnings is not None:
            warnings.append(f"Wi-Fi interface query unavailable: {exc}")
        return _parse_wlan_output("")

    if completed.returncode != 0 and "no wireless interface" not in (completed.stdout or "").lower():
        if warnings is not None and completed.stderr:
            warnings.append(f"Wi-Fi query notice: {completed.stderr.strip()}")
    return _parse_wlan_output(completed.stdout or "")


def resolve_dns(hostname: str) -> DnsResolutionResult:
    """Resolve a validated hostname to IPv4 and IPv6 addresses via socket.getaddrinfo."""
    executed_at = format_timestamp(time.time())
    valid, cleaned, err = validate_network_target(hostname)
    if not valid:
        return DnsResolutionResult(
            hostname=cleaned or hostname,
            success=False,
            ipv4_addresses=[],
            ipv6_addresses=[],
            latency_ms=None,
            error=err,
            executed_at=executed_at,
        )

    start = time.perf_counter()
    try:
        infos = socket.getaddrinfo(cleaned, None)
        elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)
    except socket.gaierror as exc:
        return DnsResolutionResult(
            hostname=cleaned,
            success=False,
            ipv4_addresses=[],
            ipv6_addresses=[],
            latency_ms=None,
            error=f"DNS resolution failed: {exc}",
            executed_at=executed_at,
        )
    except OSError as exc:
        return DnsResolutionResult(
            hostname=cleaned,
            success=False,
            ipv4_addresses=[],
            ipv6_addresses=[],
            latency_ms=None,
            error=f"Socket error during DNS lookup: {exc}",
            executed_at=executed_at,
        )

    v4_seen: list[str] = []
    v6_seen: list[str] = []
    for family, _, _, _, sockaddr in infos:
        addr = str(sockaddr[0]).split("%")[0]
        if family == socket.AF_INET and addr not in v4_seen:
            v4_seen.append(addr)
        elif family == socket.AF_INET6 and addr not in v6_seen:
            v6_seen.append(addr)

    return DnsResolutionResult(
        hostname=cleaned,
        success=bool(v4_seen or v6_seen),
        ipv4_addresses=v4_seen,
        ipv6_addresses=v6_seen,
        latency_ms=elapsed_ms,
        error=None if (v4_seen or v6_seen) else "No DNS records returned.",
        executed_at=executed_at,
    )


def run_ping(
    target: str,
    count: int = 4,
    timeout_ms: int = 1500,
) -> PingResult:
    """
    Execute a bounded, user-triggered Windows ICMP ping test.

    Pre-resolves hostnames so DNS resolution failures are clearly distinguished
    from unreachable routes and ICMP timeouts.
    """
    executed_at = format_timestamp(time.time())
    valid, cleaned, err = validate_network_target(target)
    if not valid:
        return PingResult(
            target=cleaned or target,
            resolved_ip=UNAVAILABLE_VALUE,
            success=False,
            packets_sent=0,
            packets_received=0,
            packet_loss_percent=None,
            min_ms=None,
            avg_ms=None,
            max_ms=None,
            failure_reason="Invalid Target",
            raw_output=err or "Invalid target.",
            executed_at=executed_at,
        )

    bounded_count = max(1, min(int(count), 6))
    bounded_wait = max(500, min(int(timeout_ms), 4000))

    resolved_ip = cleaned
    if not _is_ip_literal(cleaned):
        dns_res = resolve_dns(cleaned)
        if not dns_res.success:
            return PingResult(
                target=cleaned,
                resolved_ip=UNAVAILABLE_VALUE,
                success=False,
                packets_sent=0,
                packets_received=0,
                packet_loss_percent=None,
                min_ms=None,
                avg_ms=None,
                max_ms=None,
                failure_reason="DNS Resolution Failed",
                raw_output=dns_res.error or "DNS lookup failed.",
                executed_at=executed_at,
            )
        resolved_ip = (
            dns_res.ipv4_addresses[0]
            if dns_res.ipv4_addresses
            else dns_res.ipv6_addresses[0]
        )

    if not is_windows():
        return PingResult(
            target=cleaned,
            resolved_ip=resolved_ip,
            success=False,
            packets_sent=0,
            packets_received=0,
            packet_loss_percent=None,
            min_ms=None,
            avg_ms=None,
            max_ms=None,
            failure_reason="Unavailable",
            raw_output="Windows ping.exe diagnostics are only supported on Windows hosts.",
            executed_at=executed_at,
        )

    try:
        completed = subprocess.run(
            ["ping", "-n", str(bounded_count), "-w", str(bounded_wait), cleaned],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=PING_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return PingResult(
            target=cleaned,
            resolved_ip=resolved_ip,
            success=False,
            packets_sent=bounded_count,
            packets_received=0,
            packet_loss_percent=100.0,
            min_ms=None,
            avg_ms=None,
            max_ms=None,
            failure_reason="Timeout / ICMP Blocked",
            raw_output=f"Ping command timed out after {PING_TIMEOUT_SECONDS}s.",
            executed_at=executed_at,
        )
    except (FileNotFoundError, OSError) as exc:
        return PingResult(
            target=cleaned,
            resolved_ip=resolved_ip,
            success=False,
            packets_sent=0,
            packets_received=0,
            packet_loss_percent=None,
            min_ms=None,
            avg_ms=None,
            max_ms=None,
            failure_reason="Command Error",
            raw_output=str(exc),
            executed_at=executed_at,
        )

    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
    stats_match = _PING_STATS_RE.search(output)
    rtt_match = _PING_RTT_RE.search(output)

    if stats_match:
        sent = int(stats_match.group(1))
        received = int(stats_match.group(2))
        loss_pct = float(stats_match.group(4))
    else:
        sent = bounded_count
        received = 0
        loss_pct = 100.0 if completed.returncode != 0 else None

    min_ms = float(rtt_match.group(1)) if rtt_match else None
    max_ms = float(rtt_match.group(2)) if rtt_match else None
    avg_ms = float(rtt_match.group(3)) if rtt_match else None

    lowered = output.lower()
    failure_reason: str | None = None
    if received == 0:
        if "could not find host" in lowered:
            failure_reason = "DNS Resolution Failed"
        elif "unreachable" in lowered or "transmit failed" in lowered or "general failure" in lowered:
            failure_reason = "Destination Unreachable"
        elif "timed out" in lowered or completed.returncode != 0:
            failure_reason = "Timeout / ICMP Blocked"
        else:
            failure_reason = "No Reply"

    return PingResult(
        target=cleaned,
        resolved_ip=resolved_ip,
        success=received > 0,
        packets_sent=sent,
        packets_received=received,
        packet_loss_percent=loss_pct,
        min_ms=min_ms,
        avg_ms=avg_ms,
        max_ms=max_ms,
        failure_reason=failure_reason,
        raw_output=output,
        executed_at=executed_at,
    )


def _parse_tracert_hops(raw_output: str) -> list[TracerouteHop]:
    """Parse structured hop entries from Windows `tracert -d` output."""
    hops: list[TracerouteHop] = []
    for line in raw_output.splitlines():
        match = _TRACERT_HOP_RE.match(line)
        if not match:
            continue
        hops.append(
            TracerouteHop(
                hop=int(match.group(1)),
                rtt_1=match.group(2).strip(),
                rtt_2=match.group(3).strip(),
                rtt_3=match.group(4).strip(),
                address=match.group(5).strip(),
            )
        )
    return hops


def run_traceroute(target: str, max_hops: int = 15) -> TracerouteResult:
    """Execute a bounded Windows `tracert -d` trace to a validated destination."""
    executed_at = format_timestamp(time.time())
    valid, cleaned, err = validate_network_target(target)
    if not valid:
        return TracerouteResult(
            target=cleaned or target,
            success=False,
            timed_out=False,
            hops=[],
            error=err,
            raw_output=err or "Invalid target.",
            executed_at=executed_at,
        )

    if not _is_ip_literal(cleaned):
        dns_res = resolve_dns(cleaned)
        if not dns_res.success:
            return TracerouteResult(
                target=cleaned,
                success=False,
                timed_out=False,
                hops=[],
                error=f"DNS resolution failed for '{cleaned}'.",
                raw_output=dns_res.error or "DNS lookup failed.",
                executed_at=executed_at,
            )

    if not is_windows():
        return TracerouteResult(
            target=cleaned,
            success=False,
            timed_out=False,
            hops=[],
            error="Windows tracert is only supported on Windows hosts.",
            raw_output="",
            executed_at=executed_at,
        )

    bounded_hops = max(3, min(int(max_hops), 20))
    try:
        completed = subprocess.run(
            ["tracert", "-d", "-h", str(bounded_hops), "-w", "1000", cleaned],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=TRACEROUTE_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        partial = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        hops = _parse_tracert_hops(partial)
        return TracerouteResult(
            target=cleaned,
            success=False,
            timed_out=True,
            hops=hops,
            error=f"Traceroute reached the {TRACEROUTE_TIMEOUT_SECONDS}s execution limit.",
            raw_output=partial.strip(),
            executed_at=executed_at,
        )
    except (FileNotFoundError, OSError) as exc:
        return TracerouteResult(
            target=cleaned,
            success=False,
            timed_out=False,
            hops=[],
            error=f"Unable to run tracert: {exc}",
            raw_output="",
            executed_at=executed_at,
        )

    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
    hops = _parse_tracert_hops(output)
    return TracerouteResult(
        target=cleaned,
        success=completed.returncode == 0 and bool(hops),
        timed_out=False,
        hops=hops,
        error=None if completed.returncode == 0 else f"tracert exited with code {completed.returncode}.",
        raw_output=output,
        executed_at=executed_at,
    )


def _probe_tcp(host: str, port: int, timeout: int = TCP_PROBE_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Attempt a bounded TCP connect check without sending application payload."""
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = round((time.perf_counter() - start) * 1000.0, 2)
        return {"target": f"{host}:{port}", "reachable": True, "latency_ms": elapsed, "error": None}
    except OSError as exc:
        return {"target": f"{host}:{port}", "reachable": False, "latency_ms": None, "error": str(exc)}


def run_connectivity_check(
    adapters: list[NetworkAdapterInfo],
    default_gateways: list[str],
) -> ConnectivityProbeResult:
    """
    Run a user-triggered multi-layer connectivity check (Adapter -> Gateway -> DNS -> TCP).

    Deliberately checks TCP reachability alongside DNS and ICMP so blocked ICMP
    does not falsely report the internet as disconnected.
    """
    executed_at = format_timestamp(time.time())
    active_non_loopback = [
        a
        for a in adapters
        if a.status == "Up"
        and "loopback" not in a.name.lower()
        and (a.ipv4_addresses or a.ipv6_addresses)
    ]
    if not active_non_loopback:
        return ConnectivityProbeResult(
            dns_ok=False,
            dns_detail="Skipped: no active network adapter with an assigned IP address.",
            tcp_checks=[],
            gateway_ping=None,
            classification="No Active Network Adapter",
            summary="No active non-loopback network adapter has an assigned IP address.",
            executed_at=executed_at,
        )

    gateway_ping = run_ping(default_gateways[0], count=2, timeout_ms=1000) if default_gateways else None
    dns_res = resolve_dns("www.microsoft.com")
    tcp_ip = _probe_tcp("1.1.1.1", 443)
    tcp_dns_host = _probe_tcp("www.microsoft.com", 443) if dns_res.success else {
        "target": "www.microsoft.com:443",
        "reachable": False,
        "latency_ms": None,
        "error": "Skipped due to DNS resolution failure",
    }
    tcp_checks = [tcp_ip, tcp_dns_host]

    ip_reachable = bool(tcp_ip["reachable"])
    web_reachable = bool(tcp_dns_host["reachable"])

    if web_reachable:
        if gateway_ping is not None and not gateway_ping.success:
            classification = "Connected (ICMP Potentially Blocked)"
            summary = (
                "DNS and HTTPS/TCP connectivity succeeded even though ICMP ping to the gateway did not respond."
            )
        else:
            classification = "Connected"
            summary = "Gateway, DNS resolution, and outbound TCP connectivity are operational."
    elif ip_reachable and not dns_res.success:
        classification = "DNS Resolution Failure"
        summary = (
            "Outbound IP/TCP connectivity succeeded (1.1.1.1:443), but hostname DNS resolution failed."
        )
    elif gateway_ping is not None and not gateway_ping.success and not ip_reachable:
        classification = "Local Network / Gateway Unreachable"
        summary = (
            "Default gateway did not respond and outbound TCP tests failed. Check local link, VLAN, or DHCP lease."
        )
    else:
        classification = "Limited / Offline"
        summary = "Outbound internet endpoints could not be reached via DNS or TCP."

    dns_detail = (
        f"Resolved www.microsoft.com in {dns_res.latency_ms} ms"
        if dns_res.success
        else (dns_res.error or "DNS resolution failed")
    )

    return ConnectivityProbeResult(
        dns_ok=dns_res.success,
        dns_detail=dns_detail,
        tcp_checks=tcp_checks,
        gateway_ping=gateway_ping,
        classification=classification,
        summary=summary,
        executed_at=executed_at,
    )


def generate_network_recommendations(
    adapters: list[NetworkAdapterInfo],
    default_gateways: list[str],
    dns_servers: list[str],
    wifi: WifiInfo,
    ping_result: PingResult | None = None,
    connectivity: ConnectivityProbeResult | None = None,
) -> list[NetworkRecommendation]:
    """Produce deterministic, read-only troubleshooting guidance from observed network state."""
    recs: list[NetworkRecommendation] = []
    non_loopback = [a for a in adapters if "loopback" not in a.name.lower()]
    up_adapters = [a for a in non_loopback if a.status == "Up"]

    if not up_adapters:
        recs.append(
            NetworkRecommendation(
                severity="Critical",
                title="No Active Network Adapter Detected",
                explanation="All non-loopback network interfaces appear disconnected or down.",
                steps=[
                    "Verify Ethernet cable link LEDs or ensure Wi-Fi radio/airplane mode is enabled appropriately.",
                    "Confirm the network interface is enabled in Windows Network Connections.",
                    "If using a corporate dock or VPN adapter, test direct onboard NIC connectivity.",
                ],
            )
        )
    else:
        if not default_gateways:
            recs.append(
                NetworkRecommendation(
                    severity="Warning",
                    title="No Default Gateway Configured",
                    explanation="Active interfaces lack a default IPv4/IPv6 gateway, preventing off-subnet routing.",
                    steps=[
                        "Check whether the adapter received an APIPA address (169.254.x.x), indicating DHCP failure.",
                        "Verify switch port VLAN assignment or DHCP server availability with the network team.",
                    ],
                )
            )
        if not dns_servers:
            recs.append(
                NetworkRecommendation(
                    severity="Warning",
                    title="No DNS Servers Assigned",
                    explanation="No active DNS server addresses were detected on enabled interfaces.",
                    steps=[
                        "Confirm DHCP scope options include internal enterprise DNS servers.",
                        "Verify VPN split-tunnel DNS configuration if connected remotely.",
                    ],
                )
            )

    if wifi.available and wifi.state.lower() == "connected" and wifi.signal_percent is not None:
        if wifi.signal_percent < 40:
            recs.append(
                NetworkRecommendation(
                    severity="Warning",
                    title=f"Weak Wi-Fi Signal ({wifi.signal_percent}%)",
                    explanation="Low wireless signal strength increases packet retransmissions and latency jitter.",
                    steps=[
                        "Move closer to the access point or switch to a 5 GHz/wired Ethernet connection if available.",
                        "Check for physical obstructions or channel congestion on 2.4 GHz.",
                    ],
                )
            )

    if ping_result is not None and not ping_result.success:
        if ping_result.failure_reason == "DNS Resolution Failed":
            recs.append(
                NetworkRecommendation(
                    severity="Critical",
                    title=f"DNS Resolution Failed for {ping_result.target}",
                    explanation="The hostname could not be resolved to an IP address prior to ICMP testing.",
                    steps=[
                        "Verify spelling of the target FQDN and internal DNS suffix search list.",
                        "Test resolving an internal host vs. external host using the DNS Resolution tool.",
                        "Check whether configured DNS servers are reachable on UDP/TCP port 53.",
                    ],
                )
            )
        elif ping_result.failure_reason == "Timeout / ICMP Blocked":
            recs.append(
                NetworkRecommendation(
                    severity="Info",
                    title=f"ICMP Timed Out for {ping_result.target}",
                    explanation=(
                        "ICMP echo requests received no reply. Many corporate firewalls and cloud hosts "
                        "drop ICMP while still permitting HTTPS/TCP traffic."
                    ),
                    steps=[
                        "Run the Internet Connectivity Check to verify TCP/443 reachability before assuming an outage.",
                        "Run Traceroute to identify where ICMP responses stop along the path.",
                    ],
                )
            )
        elif ping_result.failure_reason == "Destination Unreachable":
            recs.append(
                NetworkRecommendation(
                    severity="Critical",
                    title=f"Destination Unreachable ({ping_result.target})",
                    explanation="Local routing reported the target network or host as unreachable.",
                    steps=[
                        "Verify default gateway status and local subnet mask.",
                        "Check whether corporate VPN is required to reach the target subnet.",
                    ],
                )
            )
    elif ping_result is not None and ping_result.success:
        if (ping_result.packet_loss_percent or 0.0) > 0.0:
            recs.append(
                NetworkRecommendation(
                    severity="Warning",
                    title=f"Packet Loss Observed ({ping_result.packet_loss_percent:.0f}%)",
                    explanation=f"ICMP test to {ping_result.target} dropped packets.",
                    steps=[
                        "Check Wi-Fi signal quality or Ethernet cable/duplex errors.",
                        "Run Traceroute to isolate whether loss starts at the local gateway or upstream.",
                    ],
                )
            )
        elif (ping_result.avg_ms or 0.0) > 150.0:
            recs.append(
                NetworkRecommendation(
                    severity="Warning",
                    title=f"Elevated Latency ({ping_result.avg_ms:.0f} ms)",
                    explanation=f"Average round-trip latency to {ping_result.target} exceeds 150 ms.",
                    steps=[
                        "Check for bandwidth saturation, VPN hairpin routing, or weak Wi-Fi.",
                    ],
                )
            )

    if connectivity is not None and connectivity.classification in {
        "DNS Resolution Failure",
        "Local Network / Gateway Unreachable",
        "Limited / Offline",
    }:
        recs.append(
            NetworkRecommendation(
                severity="Critical" if connectivity.classification != "DNS Resolution Failure" else "Warning",
                title=f"Connectivity Classification: {connectivity.classification}",
                explanation=connectivity.summary,
                steps=[
                    "Review DNS server assignments and default gateway reachability.",
                    "Confirm whether a corporate proxy or VPN login is required for external access.",
                ],
            )
        )

    if not recs:
        recs.append(
            NetworkRecommendation(
                severity="Healthy",
                title="Baseline Network Configuration Looks Healthy",
                explanation="Active adapters, gateway/DNS assignments, and observed telemetry show no obvious faults.",
                steps=["Use the on-demand Ping, DNS, Traceroute, or Connectivity tools for targeted validation."],
            )
        )

    return recs


def collect_network_snapshot() -> NetworkSnapshot:
    """Collect passive local network configuration and telemetry without active probing."""
    warnings: list[str] = []
    adapters = get_network_adapters(warnings=warnings)
    wifi = get_wifi_info(warnings=warnings)

    gateways: list[str] = []
    dns_servers: list[str] = []
    for adapter in adapters:
        for gw in adapter.default_gateways:
            if gw not in gateways:
                gateways.append(gw)
        for dns in adapter.dns_servers:
            if dns not in dns_servers:
                dns_servers.append(dns)

    try:
        totals = psutil.net_io_counters()
        total_sent: int | None = int(totals.bytes_sent)
        total_recv: int | None = int(totals.bytes_recv)
    except Exception:
        total_sent = total_recv = None

    recommendations = generate_network_recommendations(
        adapters=adapters,
        default_gateways=gateways,
        dns_servers=dns_servers,
        wifi=wifi,
    )

    return NetworkSnapshot(
        collected_at=format_timestamp(time.time()),
        adapters=adapters,
        default_gateways=gateways,
        dns_servers=dns_servers,
        total_bytes_sent=total_sent,
        total_bytes_recv=total_recv,
        wifi=wifi,
        recommendations=recommendations,
        warnings=warnings,
    )
