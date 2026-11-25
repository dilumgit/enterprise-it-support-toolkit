# Test Cases & QA Verification Matrix

This document records functional, security, and regression test cases for the **Enterprise IT Support & Network Diagnostics Toolkit**. Only directly executed and observed outcomes are marked as verified.

---

## 1. Automated Regression Suite (`pytest`)

- **Command**: `python -m pytest -v`
- **Scope**: Formatting & CSV sanitization, PowerShell/CIM runner validation & timeouts, Hardware Diagnostics, System Administration, Network Diagnostics, Information Security, SQLite initialization & migrations, IT Help Desk CRUD/workflows, IT Asset Management & Licenses, Troubleshooting Engine rules, and Technical Reporting (HTML escaping & privacy redaction).

---

## 2. Manual & Functional QA Test Cases

| Test ID | Module | Test Scenario | Steps | Expected Result | Verification Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-01** | Startup & Navigation | Launch app bound to localhost and switch across all 9 pages | Start `streamlit run app.py` and select each sidebar radio item | All 9 pages render with dark theme and zero uncaught exceptions | Verified via Streamlit startup (`127.0.0.1:8509` health `ok`) and `AppTest` across all 9 pages (browser visual check blocked: Chrome DevTools unavailable) |
| **TC-02** | Hardware Diagnostics | Real local CPU, RAM, Disk, Battery, and BIOS telemetry | Open Hardware Diagnostics and inspect all 4 tabs | Live values render; absent battery shows `Unavailable`; mixed-type table columns serialize without Arrow errors | Verified via `pytest` live smoke test and Streamlit `AppTest` |
| **TC-03** | System Administration | OS info, processes, services, and Uninstall registry software | Open System Administration and inspect tabs & filters | OS uptime displays; protected processes skip without crashing; software queries registry safely | Verified via `pytest` and Streamlit `AppTest` |
| **TC-04** | Network Diagnostics | Passive adapters + user-triggered Ping/DNS/Connectivity | Open Network Diagnostics; validate invalid target `1.1.1.1; whoami` and valid target | Invalid targets rejected; DNS failures separated from blocked ICMP and unreachable destinations | Verified via `pytest` (unit + smoke) and Streamlit `AppTest` |
| **TC-05** | Information Security | Firewall, Defender/AV, HotFix, UAC, BitLocker graceful fallback | Open Information Security under standard-user permissions | Profiles, AV, UAC, HotFixes render; restricted BitLocker reports `Unavailable`; disclaimer shown | Verified via `pytest` (unit + smoke) and Streamlit `AppTest` |
| **TC-06** | IT Help Desk | Create ticket, invalid transition, resolve with notes, delete confirmation | Create ticket, try `Resolved` without notes, resolve with notes, try `Closed` -> `Resolved` | Validation blocks missing notes & invalid transitions; activity timeline logs updates; DB persists | Verified via `pytest` (`tmp_path` SQLite) and `AppTest` load |
| **TC-07** | IT Help Desk UI | Interactive form submission, filtering, and CSV download in browser | Submit form in browser, filter queue, open downloaded CSV in Excel | Ticket appears immediately; CSV opens without formula execution | Pending manual browser form & Excel verification |
| **TC-08** | IT Asset Management | Asset CRUD, duplicate ID rejection, diagnostic import opt-in, licenses | Register asset, attempt duplicate ID, preview diagnostic import (`include_serial=False`), add license | Duplicate ID rejected; serial omitted unless opted in; no license key fields exist | Verified via `pytest` (`tmp_path` SQLite) and `AppTest` load |
| **TC-09** | Troubleshooting Assistant | Run full assessment, filter findings, escalate finding to ticket | Click `Run Assessment`, inspect findings, preview & confirm incident creation | Evidence separated from suspected causes; confirmed incident persists to Help Desk | Verified via `pytest` and Streamlit `AppTest` (`Run Assessment` interactive click) |
| **TC-10** | Technical Reporting | Generate all 8 reports with privacy redaction & HTML escaping | Generate reports with `privacy_redacted=True` and XSS/CSV payloads | Host/user/IP/MAC/serial/email redacted; `<script>` escaped; `=SUM` prefixed with `'`; zero external URLs | Verified via `pytest` and Streamlit `AppTest` (`Generate Report` interactive click) |
| **TC-11** | Technical Reporting UI | Download and inspect exported `.csv` and `.html` files in desktop apps | Click Download CSV and Download HTML in browser and open locally | Files download cleanly and render offline without external network calls | Pending manual desktop download inspection |
