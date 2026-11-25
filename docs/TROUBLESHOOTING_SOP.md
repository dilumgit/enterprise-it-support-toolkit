# Troubleshooting Standard Operating Procedures (SOP)

These Standard Operating Procedures guide L1/L2 IT Support Analysts in financial services environments when triaging endpoint incidents using the **Enterprise IT Support & Network Diagnostics Toolkit**.

> **Operational Policy**: Perform read-only diagnostics first. Never disable Windows Firewall or endpoint antivirus, and never modify host network or registry settings without approved change/escalation procedures.

---

## SOP-01: Slow Computer Performance / High CPU or Memory

1. **Triage in Toolkit**:
   - Open **Overview Dashboard** and **Hardware Diagnostics** to record live CPU %, RAM %, swap usage, and disk free %.
   - Open **System Administration → Running Processes** and sort by `memory_mb` and `cpu_percent`.
   - Open **System Administration → OS & Uptime** to check if uptime exceeds 14 days.
2. **Analyze**:
   - Run **Troubleshooting Assistant** (`Full Endpoint Assessment`) to check for `TRB-XMOD-PERF`, `TRB-HW-CPU-*`, `TRB-HW-RAM-*`, or `TRB-SYS-PROC-HOG`.
3. **Non-Destructive Actions**:
   - Confirm with the user whether listed high-usage apps (browsers, spreadsheets, analytics tools) are running active tasks.
   - Ask the user to save work and close redundant sessions, or schedule a controlled workstation reboot if uptime is excessive or updates are pending.
4. **Verify & Escalate**:
   - Re-run Hardware Diagnostics to confirm CPU and RAM drop below 75%.
   - Escalate to **Desktop Engineering** via **IT Help Desk** if high utilization persists at idle or physical RAM is consistently insufficient.

---

## SOP-02: Low Disk Space on OS Volume

1. **Triage in Toolkit**:
   - Check **Hardware Diagnostics → Storage & Disks** for logical volumes ≥ 80% (`Warning`) or ≥ 90% (`Critical`).
2. **Non-Destructive Actions**:
   - Guide the user to empty the Recycle Bin, clear browser caches, and move approved work files to corporate OneDrive/network shares.
   - Do not delete unfamiliar system or application directories.
3. **Verify & Escalate**:
   - Confirm free space exceeds 20%.
   - Escalate to **Endpoint Operations** if `C:\` remains below 10% free (risks Windows Update and pagefile failures).

---

## SOP-03: Network Connectivity, DNS, or Wi-Fi Degradation

1. **Triage in Toolkit**:
   - Open **Network Diagnostics → Adapters & Routing** to verify at least one non-loopback adapter is `Up` with an IPv4 address, Default Gateway, and DNS server(s).
   - Check **Wi-Fi Details** for signal strength (< 40% indicates weak link).
   - Click **Run Connectivity Check** to classify `Connected`, `Connected (ICMP Potentially Blocked)`, `DNS Resolution Failure`, or `Local Network / Gateway Unreachable`.
   - Run **Ping Test** (gateway IP vs. `1.1.1.1`) and **Resolve Hostname** (internal FQDN vs. external domain).
2. **Interpret Results**:
   - **TCP/443 works, Ping times out**: ICMP is likely filtered by a firewall; do not treat as an internet outage.
   - **IP/TCP works, DNS fails**: DNS server/VPN split-DNS issue rather than physical link outage.
   - **Gateway unreachable**: Local cable, switch port/VLAN, Wi-Fi association, or DHCP failure (check for `169.254.x.x`).
3. **Verify & Escalate**:
   - Re-run Connectivity Check and confirm `Connected`.
   - Escalate to **Network Operations** with Ping, DNS, and Traceroute outputs (or a Privacy-Redacted Network Diagnostic Report).

---

## SOP-04: Endpoint Security Baseline Alerts (Firewall, AV, UAC, Encryption)

1. **Triage in Toolkit**:
   - Open **Information Security** and review **Findings & Recommendations**, **Firewall & Antivirus**, **Windows Updates / HotFixes**, and **UAC & BitLocker**.
2. **Interpret & Actions**:
   - **Disabled Firewall Profile (`TRB-SEC-FW-OFF`)**: Check whether an approved third-party endpoint firewall manages host filtering; otherwise escalate immediately to **Information Security / Endpoint Ops**.
   - **Disabled Real-Time AV (`TRB-SEC-AV-OFF`)**: Verify whether another `SecurityCenter2` AV/EDR product is `Enabled`. If none is active, disconnect sensitive shares per incident playbook and escalate immediately to **SOC**.
   - **Outdated AV Signatures (`TRB-SEC-AV-SIG`)**: Confirm network connectivity and trigger a definition update via the approved AV client.
   - **UAC Disabled or Silent (`TRB-SEC-UAC-*`)**: Report policy drift to **Desktop Engineering / InfoSec**.
   - **BitLocker Unavailable (`TRB-SEC-BL-UNAVAIL`)**: Expected under standard-user privileges when restricted; verify encryption compliance in the central MDM/Intune console.
3. **Document & Escalate**:
   - Use **Troubleshooting Assistant → Create IT Help Desk Incident** to log a Security incident with confirmed diagnostic evidence.
