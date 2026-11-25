# Implementation Plan

This document outlines the phased delivery roadmap for the **Enterprise IT Support & Network Diagnostics Toolkit**.

---

## Phase 1 — Foundation, Hardware Diagnostics & System Information (Completed)

- Inspect workspace and Python runtime compatibility (Python 3.13 / Windows PowerShell 5.1+).
- Establish modular folder hierarchy (`src/config`, `src/utils`, `src/services`, `src/database`, `src/ui`, `tests`).
- Define `requirements.txt`, `.gitignore`, `.streamlit/config.toml`, and architectural documentation.
- Implement safe, timeout-bounded PowerShell/CIM utility (`src/utils/powershell.py`) and formatting helpers (`src/utils/formatting.py`).
- Implement **Hardware Diagnostics** (`src/services/hardware_diagnostics.py`):
  - CPU usage, per-core metrics, processor metadata
  - RAM & swap utilization + physical memory DIMMs
  - Logical disk partitions & physical storage devices
  - Battery telemetry with desktop/VM graceful fallback
  - Hardware, motherboard, and BIOS specifications
- Implement **System Administration / System Info** (`src/services/system_info.py`):
  - Operating system details and uptime calculation
  - Running processes table with safe `AccessDenied` handling
  - Windows services read-only status inventory
  - Installed software inventory via read-only Uninstall registry keys
- Build enterprise dark Streamlit shell (`app.py`), Overview Dashboard, Hardware Diagnostics page, and System Administration page.
- Create unit tests with `pytest` covering formatting, PowerShell runner, hardware diagnostics, and system info collectors.

---

## Phase 2 — Network Diagnostics & Information Security (Completed)

- **Network Diagnostics Service (`src/services/network_diagnostics.py`)**:
  - Local IPv4/IPv6 addresses, MAC addresses, adapter link speed & status (`psutil.net_if_addrs`, `psutil.net_if_stats`)
  - Default gateway & DNS server configuration (`Get-NetIPConfiguration` / `ipconfig` fallback)
  - Bounded Ping, DNS resolution (`socket.getaddrinfo`), Traceroute (`tracert -d -h 15`), and TCP connectivity checks
  - Wi-Fi SSID, signal strength, and radio details via `netsh wlan show interfaces` (graceful `Unavailable` on wired/VM hosts)
- **Information Security Service (`src/services/security_posture.py`)**:
  - Windows Firewall profile state (Domain, Private, Public) via `Get-NetFirewallProfile`
  - Microsoft Defender / SecurityCenter2 AV status via read-only CIM queries
  - Recent Windows Update / HotFix history via `Get-HotFix`
  - Read-only baseline posture checks (UAC, BitLocker status if readable without elevation, SMBv1 check) and remediation guidance
- Dedicated Streamlit pages for Network Diagnostics and Information Security, plus unit tests.

---

## Phase 3 — IT Help Desk & IT Asset Management (Completed)

- **Database Layer (`src/database/db.py`, `models.py`)**:
  - Local SQLite schema in `data/toolkit.db` (auto-initialized on demand)
  - Parameterized queries with context-managed connections
- **IT Help Desk (`src/services/helpdesk_service.py`)**:
  - Incident creation with category (Hardware, Network, Security, Software, Access), priority (Low, Medium, High, Critical), status (`Open`, `In Progress`, `Resolved`), and resolution notes
  - Search, filter, and status workflow updates
- **IT Asset Management (`src/services/asset_service.py`)**:
  - Auto-discovery snapshot import from Hardware/System modules
  - Hardware & software inventory tracking, assigned department, asset status (`Active`, `In Repair`, `Retired`, `Spare`)
  - CSV export to memory/download and `reports/`
- Dedicated Streamlit pages and CRUD unit tests using temporary SQLite databases.

---

## Phase 4 — Troubleshooting Assistant & Technical Reporting (Completed)

- **Troubleshooting Assistant (`src/services/troubleshooting_engine.py`)**:
  - Deterministic rule engine evaluating live CPU, RAM, disk saturation, high-memory processes, stopped critical services, DNS/gateway reachability, and security posture gaps
  - Clear root-cause explanation, severity classification, and non-destructive step-by-step troubleshooting playbooks
- **Technical Reporting (`src/services/reporting_service.py`)**:
  - Generate structured Diagnostic, Network, Security, and Incident reports
  - Export clean CSV datasets and self-contained styled HTML reports
- Dedicated Streamlit pages, end-to-end integration tests, and portfolio polish.
