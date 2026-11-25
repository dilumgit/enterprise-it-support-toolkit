"""Unit tests for the Network Diagnostics service."""

from __future__ import annotations

import socket
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

from src.config.settings import UNAVAILABLE_VALUE
from src.services.network_diagnostics import (
    NetworkAdapterInfo,
    WifiInfo,
    collect_network_snapshot,
    generate_network_recommendations,
    get_network_adapters,
    get_wifi_info,
    resolve_dns,
    run_connectivity_check,
    run_ping,
    run_traceroute,
    validate_network_target,
)
from src.utils.powershell import PowerShellResult


def test_validate_network_target_accepts_valid_and_rejects_injection() -> None:
    assert validate_network_target("1.1.1.1")[0] is True
    assert validate_network_target("2001:4860:4860::8888")[0] is True
    assert validate_network_target("portal.fincorp.internal")[0] is True

    for bad in ("", "   ", "-n", "1.1.1.1; whoami", "host && dir", "host | calc", "a b.com"):
        ok, _, err = validate_network_target(bad)
        assert ok is False
        assert err


def test_get_network_adapters_combines_psutil_and_windows_metadata() -> None:
    af_link = getattr(socket, "AF_LINK", -1000)
    addrs = {
        "Ethernet": [
            SimpleNamespace(family=socket.AF_INET, address="10.10.1.50", netmask="255.255.255.0"),
            SimpleNamespace(family=socket.AF_INET6, address="fe80::1%12", netmask=None),
        ],
        "Loopback Pseudo-Interface 1": [
            SimpleNamespace(family=socket.AF_INET, address="127.0.0.1", netmask="255.0.0.0"),
        ],
    }
    stats = {
        "Ethernet": SimpleNamespace(isup=True, speed=1000, mtu=1500),
        "Loopback Pseudo-Interface 1": SimpleNamespace(isup=True, speed=1073, mtu=1500),
    }
    io_counters = {
        "Ethernet": SimpleNamespace(
            bytes_sent=5_000_000,
            bytes_recv=12_000_000,
            packets_sent=4000,
            packets_recv=8000,
            errin=0,
            errout=0,
        )
    }
    ps_res = PowerShellResult(
        success=True,
        data=[
            {
                "InterfaceAlias": "Ethernet",
                "InterfaceDescription": "Intel(R) Ethernet Connection",
                "IPv4Gateway": ["10.10.1.1"],
                "IPv6Gateway": [],
                "DnsServers": ["10.10.0.10", "10.10.0.11"],
            }
        ],
        raw_output="",
    )
    with (
        patch("src.services.network_diagnostics.psutil.net_if_addrs", return_value=addrs),
        patch("src.services.network_diagnostics.psutil.net_if_stats", return_value=stats),
        patch("src.services.network_diagnostics.psutil.net_io_counters", return_value=io_counters),
        patch("src.services.network_diagnostics.psutil.AF_LINK", af_link, create=True),
        patch("src.services.network_diagnostics.is_windows", return_value=True),
        patch("src.services.network_diagnostics.run_powershell_json", return_value=ps_res),
    ):
        adapters = get_network_adapters()

    assert adapters[0].name == "Ethernet"
    assert adapters[0].status == "Up"
    assert adapters[0].default_gateways == ["10.10.1.1"]
    assert adapters[0].dns_servers == ["10.10.0.10", "10.10.0.11"]
    assert "10.10.1.50 / 255.255.255.0" in adapters[0].ipv4_addresses


def test_get_wifi_info_parses_connected_and_unavailable_states() -> None:
    sample_wlan = """
There is 1 interface on the system:
    Name                   : WiFi
    State                  : connected
    SSID                   : Corp-Secure
    BSSID                  : aa:bb:cc:dd:ee:ff
    Radio type             : 802.11ax
    Authentication         : WPA2-Enterprise
    Cipher                 : CCMP
    Band                   : 5 GHz
    Channel                : 36
    Receive rate (Mbps)    : 866.7
    Transmit rate (Mbps)   : 780
    Signal                 : 88%
"""
    with (
        patch("src.services.network_diagnostics.is_windows", return_value=True),
        patch(
            "src.services.network_diagnostics.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout=sample_wlan, stderr=""),
        ),
    ):
        wifi = get_wifi_info()

    assert wifi.available is True
    assert wifi.ssid == "Corp-Secure"
    assert wifi.signal_percent == 88
    assert wifi.status == "Healthy"

    with (
        patch("src.services.network_diagnostics.is_windows", return_value=True),
        patch(
            "src.services.network_diagnostics.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="netsh", timeout=8),
        ),
    ):
        warnings: list[str] = []
        wifi_timeout = get_wifi_info(warnings=warnings)

    assert wifi_timeout.available is False
    assert wifi_timeout.status == UNAVAILABLE_VALUE
    assert warnings


def test_resolve_dns_success_and_failure() -> None:
    fake_info = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
    with patch("src.services.network_diagnostics.socket.getaddrinfo", return_value=fake_info):
        ok = resolve_dns("example.com")
    assert ok.success is True
    assert ok.ipv4_addresses == ["93.184.216.34"]

    with patch("src.services.network_diagnostics.socket.getaddrinfo", side_effect=socket.gaierror("Name not resolved")):
        fail = resolve_dns("nonexistent.invalid")
    assert fail.success is False
    assert "DNS resolution failed" in (fail.error or "")


def test_run_ping_distinguishes_dns_icmp_block_and_unreachable() -> None:
    # 1. DNS failure
    with patch("src.services.network_diagnostics.socket.getaddrinfo", side_effect=socket.gaierror("No record")):
        dns_fail = run_ping("badhost.invalid")
    assert dns_fail.success is False
    assert dns_fail.failure_reason == "DNS Resolution Failed"

    # 2. Successful ping output
    ping_ok_out = """
Pinging 1.1.1.1 with 32 bytes of data:
Reply from 1.1.1.1: bytes=32 time=11ms TTL=56
Ping statistics for 1.1.1.1:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 10ms, Maximum = 14ms, Average = 12ms
"""
    with (
        patch("src.services.network_diagnostics.is_windows", return_value=True),
        patch(
            "src.services.network_diagnostics.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout=ping_ok_out, stderr=""),
        ),
    ):
        ping_ok = run_ping("1.1.1.1", count=4)
    assert ping_ok.success is True
    assert ping_ok.avg_ms == 12.0
    assert ping_ok.packet_loss_percent == 0.0

    # 3. ICMP timeout / blocked
    with (
        patch("src.services.network_diagnostics.is_windows", return_value=True),
        patch(
            "src.services.network_diagnostics.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="ping", timeout=8),
        ),
    ):
        ping_to = run_ping("1.1.1.1")
    assert ping_to.success is False
    assert ping_to.failure_reason == "Timeout / ICMP Blocked"

    # 4. Destination unreachable
    ping_unreach_out = """
Reply from 192.168.1.50: Destination host unreachable.
Ping statistics for 192.168.1.99:
    Packets: Sent = 2, Received = 0, Lost = 2 (100% loss),
"""
    with (
        patch("src.services.network_diagnostics.is_windows", return_value=True),
        patch(
            "src.services.network_diagnostics.subprocess.run",
            return_value=SimpleNamespace(returncode=1, stdout=ping_unreach_out, stderr=""),
        ),
    ):
        ping_unreach = run_ping("192.168.1.99", count=2)
    assert ping_unreach.success is False
    assert ping_unreach.failure_reason == "Destination Unreachable"


def test_run_traceroute_parses_hops_and_timeout() -> None:
    tracert_out = """
Tracing route to 1.1.1.1 over a maximum of 10 hops:
  1     2 ms     1 ms     1 ms  192.168.1.1
  2     *        *        *     Request timed out.
  3    12 ms    11 ms    13 ms  1.1.1.1
"""
    with (
        patch("src.services.network_diagnostics.is_windows", return_value=True),
        patch(
            "src.services.network_diagnostics.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout=tracert_out, stderr=""),
        ),
    ):
        tr = run_traceroute("1.1.1.1", max_hops=10)

    assert tr.success is True
    assert len(tr.hops) == 3
    assert tr.hops[0].address == "192.168.1.1"
    assert tr.hops[2].address == "1.1.1.1"

    with (
        patch("src.services.network_diagnostics.is_windows", return_value=True),
        patch(
            "src.services.network_diagnostics.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="tracert", timeout=15, output=tracert_out),
        ),
    ):
        tr_timeout = run_traceroute("1.1.1.1")
    assert tr_timeout.timed_out is True
    assert len(tr_timeout.hops) == 3


def test_run_connectivity_check_distinguishes_blocked_icmp_and_dns_failure() -> None:
    adapter = NetworkAdapterInfo(
        name="WiFi",
        description="Intel Wireless",
        status="Up",
        speed_mbps=300,
        mtu=1500,
        mac_address="AA:BB:CC:DD:EE:FF",
        ipv4_addresses=["192.168.1.25 / 255.255.255.0"],
        ipv6_addresses=[],
        default_gateways=["192.168.1.1"],
        dns_servers=["1.1.1.1"],
        bytes_sent=100,
        bytes_recv=200,
        packets_sent=1,
        packets_recv=2,
        errin=0,
        errout=0,
    )

    # Case A: ICMP to gateway fails, but DNS + TCP/443 succeed -> Connected (ICMP Potentially Blocked)
    gw_blocked = SimpleNamespace(
        target="192.168.1.1",
        resolved_ip="192.168.1.1",
        success=False,
        packets_sent=2,
        packets_received=0,
        packet_loss_percent=100.0,
        min_ms=None,
        avg_ms=None,
        max_ms=None,
        failure_reason="Timeout / ICMP Blocked",
        raw_output="",
        executed_at="2026-11-25 07:00:00",
    )
    dns_ok = SimpleNamespace(
        hostname="www.microsoft.com",
        success=True,
        ipv4_addresses=["23.50.1.1"],
        ipv6_addresses=[],
        latency_ms=14.0,
        error=None,
        executed_at="2026-11-25 07:00:00",
    )
    with (
        patch("src.services.network_diagnostics.run_ping", return_value=gw_blocked),
        patch("src.services.network_diagnostics.resolve_dns", return_value=dns_ok),
        patch(
            "src.services.network_diagnostics._probe_tcp",
            return_value={"target": "ok", "reachable": True, "latency_ms": 20.0, "error": None},
        ),
    ):
        res_a = run_connectivity_check([adapter], ["192.168.1.1"])
    assert res_a.classification == "Connected (ICMP Potentially Blocked)"

    # Case B: TCP to 1.1.1.1 succeeds, DNS fails -> DNS Resolution Failure
    dns_bad = SimpleNamespace(
        hostname="www.microsoft.com",
        success=False,
        ipv4_addresses=[],
        ipv6_addresses=[],
        latency_ms=None,
        error="DNS resolution failed",
        executed_at="2026-11-25 07:00:00",
    )
    with (
        patch("src.services.network_diagnostics.run_ping", return_value=gw_blocked),
        patch("src.services.network_diagnostics.resolve_dns", return_value=dns_bad),
        patch(
            "src.services.network_diagnostics._probe_tcp",
            return_value={"target": "1.1.1.1:443", "reachable": True, "latency_ms": 18.0, "error": None},
        ),
    ):
        res_b = run_connectivity_check([adapter], ["192.168.1.1"])
    assert res_b.classification == "DNS Resolution Failure"

    # Case C: No active adapter -> No Active Network Adapter
    res_c = run_connectivity_check([], [])
    assert res_c.classification == "No Active Network Adapter"


def test_generate_network_recommendations_flags_weak_wifi_and_missing_adapters() -> None:
    weak_wifi = WifiInfo(
        available=True,
        interface_name="WiFi",
        state="Connected",
        ssid="Office",
        bssid="00:11:22:33:44:55",
        radio_type="802.11ac",
        authentication="WPA2",
        cipher="CCMP",
        band="5 GHz",
        channel="36",
        signal_percent=28,
        receive_rate_mbps="100",
        transmit_rate_mbps="100",
        status="Critical",
    )
    recs = generate_network_recommendations(
        adapters=[],
        default_gateways=[],
        dns_servers=[],
        wifi=weak_wifi,
    )
    titles = [r.title for r in recs]
    assert any("No Active Network Adapter" in t for t in titles)
    assert any("Weak Wi-Fi Signal" in t for t in titles)


def test_collect_network_snapshot_live_smoke() -> None:
    snap = collect_network_snapshot()
    assert snap.collected_at
    assert isinstance(snap.adapters, list)
    assert len(snap.adapters) >= 1
