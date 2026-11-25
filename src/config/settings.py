"""Application configuration, thresholds, and navigation definitions."""

from dataclasses import dataclass
from pathlib import Path

APP_NAME: str = "Enterprise IT Support & Network Diagnostics Toolkit"
APP_SHORT_NAME: str = "Enterprise IT Toolkit"
APP_VERSION: str = "1.0.0"
APP_PHASE: str = "Enterprise Portfolio Release"
ORGANIZATION_CONTEXT: str = "Financial Services Endpoint & Infrastructure Support"

BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
DATA_DIR: Path = BASE_DIR / "data"
REPORTS_DIR: Path = BASE_DIR / "reports"
DEFAULT_DB_PATH: Path = DATA_DIR / "toolkit.db"

# Execution & telemetry guardrails
POWERSHELL_TIMEOUT_SECONDS: int = 8
SOFTWARE_QUERY_TIMEOUT_SECONDS: int = 12
HOTFIX_QUERY_TIMEOUT_SECONDS: int = 12
PING_TIMEOUT_SECONDS: int = 8
TRACEROUTE_TIMEOUT_SECONDS: int = 15
TCP_PROBE_TIMEOUT_SECONDS: int = 3
DEFAULT_PROCESS_LIMIT: int = 40

# Resource health thresholds (percent)
CPU_WARNING_THRESHOLD: float = 75.0
CPU_CRITICAL_THRESHOLD: float = 90.0
RAM_WARNING_THRESHOLD: float = 75.0
RAM_CRITICAL_THRESHOLD: float = 90.0
DISK_WARNING_THRESHOLD: float = 80.0
DISK_CRITICAL_THRESHOLD: float = 90.0

UNKNOWN_VALUE: str = "Unknown"
UNAVAILABLE_VALUE: str = "Unavailable"


@dataclass(frozen=True)
class NavItem:
    """Represents a navigation entry in the Streamlit sidebar."""

    key: str
    label: str
    phase: str
    implemented: bool
    summary: str


NAVIGATION_ITEMS: tuple[NavItem, ...] = (
    NavItem(
        key="overview",
        label="Overview Dashboard",
        phase="Phase 1",
        implemented=True,
        summary="Real-time endpoint health summary, KPI gauges, and module readiness.",
    ),
    NavItem(
        key="hardware",
        label="Hardware Diagnostics",
        phase="Phase 1",
        implemented=True,
        summary="CPU, memory, storage, battery, and BIOS/chassis hardware telemetry.",
    ),
    NavItem(
        key="system_admin",
        label="System Administration",
        phase="Phase 1",
        implemented=True,
        summary="OS details, uptime, running processes, Windows services, and software inventory.",
    ),
    NavItem(
        key="network",
        label="Network Diagnostics",
        phase="Phase 2",
        implemented=True,
        summary="IP configuration, adapters, gateway, DNS, ping, traceroute, and Wi-Fi telemetry.",
    ),
    NavItem(
        key="security",
        label="Information Security",
        phase="Phase 2",
        implemented=True,
        summary="Windows Firewall, Defender/AV posture, hotfix history, and security baseline checks.",
    ),
    NavItem(
        key="helpdesk",
        label="IT Help Desk",
        phase="Phase 3",
        implemented=True,
        summary="Incident ticketing, priority triage, lifecycle tracking, and SQLite persistence.",
    ),
    NavItem(
        key="assets",
        label="IT Asset Management",
        phase="Phase 3",
        implemented=True,
        summary="Hardware/software asset registry, license tracking, and CSV export.",
    ),
    NavItem(
        key="troubleshooter",
        label="Troubleshooting Assistant",
        phase="Phase 4",
        implemented=True,
        summary="Rule-based issue detection, severity scoring, and read-only remediation playbooks.",
    ),
    NavItem(
        key="reports",
        label="Technical Reporting",
        phase="Phase 4",
        implemented=True,
        summary="Diagnostic, network, security, and incident reports in CSV and HTML formats.",
    ),
)
