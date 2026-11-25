# User Guide — Enterprise IT Support & Network Diagnostics Toolkit

This guide explains how to operate each module of the toolkit safely in a standard-user Windows environment.

---

## 1. Overview Dashboard

- Displays live endpoint KPIs: **CPU Utilization**, **Memory Utilization**, **Primary Storage**, and **System Uptime**.
- Includes a passive **Network & Security Baseline Summary** (active adapters, Wi-Fi signal, firewall profile count, antivirus/UAC status) and **Help Desk & Asset Management Summary** from local SQLite.
- Click **Refresh Telemetry** to re-sample live counters. No active external network probes run on page load.

---

## 2. Hardware Diagnostics

Organized into four tabs:
- **CPU & Processor**: View overall and per-core utilization charts, clock speeds, L2/L3 cache, and processor architecture.
- **Memory (RAM)**: Inspect virtual memory, pagefile/swap usage, and physical DIMM slot metadata (`Win32_PhysicalMemory`).
- **Storage & Disks**: View logical volume capacity bars, free/used space, and physical drive models/interfaces (`Win32_DiskDrive`).
- **Battery & System Specs**: View battery charge and runtime on laptops (reports `Unavailable` on desktops/VMs), plus manufacturer, model, BIOS, and baseboard specs.

---

## 3. System Administration

- **OS & Uptime**: Displays Windows edition, build, architecture, hostname/FQDN, active user/domain, boot timestamp, and uptime.
- **Running Processes**: Filter by name/user, sort by memory, CPU, name, or PID, and inspect the Top 10 Memory Consumers chart. Protected OS processes inaccessible to standard users are skipped safely.
- **Windows Services**: Filter registered Windows services by status (`All`, `Running`, `Stopped`) or name in read-only mode.
- **Installed Software**: Queries Windows Uninstall registry hives (64-bit, 32-bit WOW6432Node, and current user) without invoking `Win32_Product`.

---

## 4. Network Diagnostics

- **Adapters & Routing**: Passive view of network interfaces, link status, speed, MAC addresses, IPv4/IPv6, gateways, DNS servers, and cumulative TX/RX traffic.
- **Wi-Fi Details**: Displays SSID, BSSID, signal %, band, channel, radio type, and security cipher when a wireless adapter is present (`Unavailable` otherwise).
- **Connectivity & Probe Tools** (User-Triggered Only):
  - **Run Connectivity Check**: Tests active adapters, gateway ICMP, DNS resolution, and outbound TCP/443 to separate DNS failures from blocked ICMP.
  - **Run Ping Test**: Enter a valid IP or hostname and packet count (1–6); pre-resolves DNS before ICMP echo.
  - **Resolve Hostname**: Timed `socket.getaddrinfo` lookup returning IPv4/IPv6 addresses.
  - **Run Traceroute**: Bounded `tracert -d` (max 15s timeout).
- **Troubleshooting Recommendations**: Dynamically evaluates passive state and your latest probe results.

---

## 5. Information Security

- **Baseline Disclaimer**: Review the top notice—checks inspect local indicators only and do not guarantee full patch currency or threat immunity.
- **Findings & Recommendations**: Rule-based observations across Firewall, Antivirus, Access Control (UAC), Encryption (BitLocker), and Patching.
- **Firewall & Antivirus**: Inspect Domain/Private/Public firewall profiles, Microsoft Defender real-time/signature status, and `SecurityCenter2` registered antivirus products.
- **Windows Updates / HotFixes**: Search installed KB updates by ID or description.
- **UAC & BitLocker**: Inspect UAC policy keys and BitLocker volume status (reports `Unavailable` if restricted without Administrator elevation).

---

## 6. IT Help Desk

- **Ticket Queue & Search**: Search by ID/title/requester/department/technician, filter by Category, Priority, Status, or Type, sort, and export filtered CSV (`formula-safe`).
- **Create New Ticket**: Submit Incidents or Service Requests with automatic sequential ID generation (`INC-YYYYMMDD-XXXX` / `REQ-YYYYMMDD-XXXX`).
- **Update & Activity History**: Transition ticket status (`Open` → `In Progress` → `Resolved` → `Closed`; `Resolved` requires resolution notes), append work notes, review the activity log, or delete a ticket (requires confirmation checkbox).
- **Summary & Demo Controls**: View category distribution and optionally load or clear clearly labeled `[DEMO]` fictional financial-services tickets.

---

## 7. IT Asset Management

- **Asset Registry**: Search, filter, sort, and export managed hardware assets to CSV.
- **Register / Update Asset**: Add new assets (auto-generated `AST-<CAT>-XXXX` or custom unique ID), update lifecycle status (`Available`, `Assigned`, `Under Maintenance`, `Retired`), or delete with confirmation.
- **Import Local Diagnostics**: Click **Preview Local System Telemetry**, inspect detected hardware and optional installed software, choose whether to opt into storing the BIOS serial number, and check confirmation to persist into SQLite.
- **Asset Software Inventory**: View and export per-asset linked software versions.
- **Software Licenses**: Track seat counts, license types, and expiration dates (never stores license keys).

---

## 8. Troubleshooting Assistant

- Choose **Full Endpoint Assessment** or **Single Category** (`Hardware`, `System`, `Network`, `Security`), optionally opt into running an active Connectivity Check, and click **Run Assessment**.
- Review severity summary cards (`Critical`, `High`, `Medium`, `Low`, `Informational`) and filter expandable findings.
- Each finding separates **Confirmed Diagnostic Evidence** from **Suspected Root Causes**, lists **Confidence & Limitations**, **Recommended Steps**, **Verification Steps**, and **Escalation Guidance**.
- Select any finding to preview and create an **IT Help Desk Incident** after explicit confirmation.

---

## 9. Technical Reporting

- Choose from 8 report types (Endpoint System Health, Hardware, Network, Security, Help Desk, Assets, Software Licenses, or Comprehensive).
- Keep **Privacy-Safe Redaction** enabled when sharing reports externally to scrub hostnames, usernames, emails, Windows profile paths, IP/MAC addresses, serial numbers, and employee names.
- Click **Generate Report** to preview executive summary, severity breakdown, findings, and tables, then download **CSV** or self-contained **HTML**.
