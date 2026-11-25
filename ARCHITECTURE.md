# System Architecture

## Architectural Goals

The **Enterprise IT Support & Network Diagnostics Toolkit** follows a layered, modular architecture tailored to enterprise endpoint support in regulated financial environments:

1. **Strict Separation of Concerns**: Streamlit UI modules contain presentation logic only and never invoke PowerShell, `psutil`, or SQLite directly.
2. **Least-Privilege Read-Only Execution**: All system inspection runs without elevation requirements and strictly avoids mutating OS, firewall, AV, or network state.
3. **Resilient Degradation**: Every external telemetry call (CIM/WMI, Registry, `psutil` process inspection, battery sensors) wraps failures in structured fallbacks returning `"Unknown"` or `"Unavailable"`.
4. **Thread-Safe CIM Queries**: Instead of COM-bound Python WMI bindings that can encounter apartment-threading issues under Streamlit's execution model, Windows CIM queries are executed via short-lived, timeout-bounded `powershell.exe -NoProfile -NonInteractive` subprocesses returning structured JSON.

---

## Directory Structure

```text
IT-Support-Toolkit/
├── .streamlit/
│   └── config.toml                 # Enterprise dark theme & headless server defaults
├── .gitignore                      # Excludes caches, .venv, local SQLite DBs, and reports
├── app.py                          # Streamlit entry point & sidebar navigation router
├── requirements.txt                # Pinned compatible runtime & test dependencies
├── data/                           # Local SQLite database directory (git-ignored DB files)
├── reports/                        # Exported CSV/HTML diagnostic reports (git-ignored)
├── src/
│   ├── config/
│   │   └── settings.py             # Constants, thresholds, timeouts, app metadata
│   ├── utils/
│   │   ├── formatting.py           # Unit conversions, uptime formatting, safe fallbacks
│   │   └── powershell.py           # Timeout-bounded PowerShell & CIM JSON runner
│   ├── services/
│   │   ├── hardware_diagnostics.py # CPU, RAM, Disk, Battery, and System Spec collectors
│   │   ├── system_info.py          # OS, Uptime, Processes, Services, Installed Software
│   │   ├── network_diagnostics.py  # Adapter, IP/DNS, Wi-Fi, Ping, Traceroute & Connectivity
│   │   ├── security_posture.py     # Firewall, Defender/AV, HotFix, UAC & BitLocker checks
│   │   ├── helpdesk_service.py     # Ticket CRUD, status workflow, activity history & CSV
│   │   ├── asset_service.py        # Asset registry, diagnostic import, licenses & CSV
│   │   ├── troubleshooting_engine.py # Cross-module rule engine & incident escalation
│   │   └── reporting_service.py    # 8 report types with privacy redaction & CSV/HTML
│   ├── database/
│   │   └── db.py                   # Parameterized SQLite connection & schema migrations
│   └── ui/
│       ├── styles.py               # Minimal enterprise dark CSS & badge styling
│       ├── components.py           # KPI cards, status pills, Plotly dark charts
│       └── pages/
│           ├── overview.py         # Executive overview dashboard
│           ├── hardware.py         # Hardware Diagnostics view
│           ├── system_admin.py     # System Administration view
│           ├── network.py          # Network Diagnostics & probe tools view
│           ├── security.py         # Information Security baseline assessment view
│           ├── helpdesk.py         # IT Help Desk & Incident Management view
│           ├── assets.py           # IT Asset Management & Licenses view
│           ├── troubleshooter.py   # Rule-based Troubleshooting Assistant view
│           └── reports.py          # Technical Reporting CSV/HTML generator view
└── tests/                          # Pytest unit test suite with mocked OS/subprocess calls
```

---

## Layer Responsibilities

### 1. Configuration Layer (`src/config/`)
- Defines application metadata, navigation registry, warning/critical resource thresholds (CPU, RAM, Disk), and subprocess timeout limits (`POWERSHELL_TIMEOUT_SECONDS`).

### 2. Utility Layer (`src/utils/`)
- **`powershell.py`**: Executes read-only PowerShell commands with `-NoProfile -NonInteractive -ExecutionPolicy Bypass` (read-only script blocks only), enforced `timeout`, UTF-8 output encoding, and safe JSON deserialization. Handles single-object vs. array normalization from `ConvertTo-Json`.
- **`formatting.py`**: Pure helper functions for byte-to-GiB/MB conversions, seconds-to-human-readable uptime, safe text sanitization (`"Unknown"` / `"Unavailable"`), and health status classification (`Healthy`, `Warning`, `Critical`, `Unknown`).

### 3. Diagnostic Service Layer (`src/services/`)
- Returns plain Python dataclasses / typed dictionaries so services are 100% testable without Streamlit running.
- **`hardware_diagnostics.py`**:
  - **CPU & Processor**: Uses `psutil.cpu_percent`, `psutil.cpu_count`, `psutil.cpu_freq`, and `Get-CimInstance Win32_Processor`.
  - **Memory**: Uses `psutil.virtual_memory`, `psutil.swap_memory`, and `Get-CimInstance Win32_PhysicalMemory` for physical DIMM slot metadata.
  - **Storage**: Uses `psutil.disk_partitions`, `psutil.disk_usage`, and `Get-CimInstance Win32_DiskDrive` for physical drive models/interfaces.
  - **Battery**: Uses `psutil.sensors_battery()` with graceful `"Unavailable"` handling for desktops/VMs.
  - **System Specs**: Uses `Win32_ComputerSystem`, `Win32_BIOS`, and `Win32_BaseBoard` via CIM.
- **`system_info.py`**:
  - **OS & Uptime**: Uses `platform`, `psutil.boot_time()`, `os.getlogin()` / environment fallback, and `Win32_OperatingSystem`.
  - **Running Processes**: Uses `psutil.process_iter` with a bounded summary and explicit handling of `psutil.AccessDenied` / `psutil.NoSuchProcess`.
  - **Windows Services**: Uses `psutil.win_service_iter()` with fallback to `Get-CimInstance Win32_Service` (read-only).
  - **Installed Software**: Queries standard Windows Uninstall registry hives (`HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*` and `WOW6432Node`) rather than `Win32_Product`, avoiding unintended MSI consistency checks/repairs.
- **`network_diagnostics.py`**:
  - **Passive Configuration**: Collects local adapter status, IPv4/IPv6/MAC addresses, traffic counters (`psutil`), gateway/DNS configuration (`Get-NetIPConfiguration`), and Wi-Fi telemetry (`netsh wlan show interfaces`) without automatic scanning.
  - **User-Triggered Probes**: Validates targets against strict IP/hostname allowlists before running bounded `ping`, `socket.getaddrinfo`, `tracert -d`, or `socket.create_connection` checks. Differentiates DNS failures, unreachable destinations, blocked ICMP, and unavailable adapters.
- **`security_posture.py`**:
  - **Read-Only Baseline Checks**: Queries `Get-NetFirewallProfile`, `Get-MpComputerStatus`, `root/SecurityCenter2` (`AntiVirusProduct`), `Get-HotFix`, UAC registry keys, and BitLocker status (reporting `Unavailable` gracefully when elevation or the BitLocker module is absent). Includes an explicit baseline disclaimer.
- **`troubleshooting_engine.py`**:
  - **Cross-Module Correlation**: Reuses Hardware, System, Network, and Security services to evaluate 15 deterministic scenarios while separating confirmed evidence from suspected root causes and limitations. Supports confirmed incident creation via `helpdesk_service.py`.
- **`reporting_service.py`**:
  - **Audit-Ready Exports**: Generates 8 report types in CSV and self-contained HTML (escaped with `html.escape`, zero external scripts/tracking) with optional privacy-safe redaction of usernames, hostnames, IPs, MACs, serial numbers, and employee names.

### 4. Presentation Layer (`src/ui/`)
- Uses dark slate/navy enterprise palette (`#0B1120` background, `#111827` surface, `#3B82F6` primary accent, `#10B981`/`#F59E0B`/`#EF4444` semantic status colors).
- Renders clean, static-animation-free Plotly visualizations (`plotly_dark` customized to match dashboard surfaces).

---

## Security & Operational Guardrails

- **Localhost Binding**: `.streamlit/config.toml` binds the server to `127.0.0.1` by default.
- **No Credential Storage**: Zero hardcoded passwords, tokens, or connection strings.
- **No Destructive Commands**: No service start/stop, no registry writes, no firewall/AV modifications, no `Win32_Product` queries, and strict target validation to block shell/flag injection.
- **Sensitive Output Isolation**: `data/*.db` and `reports/*` are excluded in `.gitignore` so endpoint inventories and security posture snapshots are never accidentally committed.
