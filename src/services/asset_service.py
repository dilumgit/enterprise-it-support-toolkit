"""IT Asset Management & Software License Inventory service backed by SQLite."""

from __future__ import annotations

import csv
import io
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from src.config.settings import DEFAULT_DB_PATH, UNKNOWN_VALUE
from src.database.db import (
    DuplicateRecordError,
    RecordNotFoundError,
    ValidationError,
    get_connection,
    initialize_database,
    require_non_empty,
    utc_now_iso,
    validate_choice,
)
from src.services.hardware_diagnostics import HardwareSnapshot, collect_hardware_snapshot
from src.services.system_info import OsInfo, SoftwareItem, get_installed_software, get_os_info
from src.utils.formatting import format_bytes, sanitize_csv_cell

ASSET_CATEGORIES: tuple[str, ...] = (
    "Desktop",
    "Laptop",
    "Printer",
    "Network Device",
    "Server",
    "Other",
)
ASSET_STATUSES: tuple[str, ...] = (
    "Available",
    "Assigned",
    "Under Maintenance",
    "Retired",
)
LICENSE_TYPES: tuple[str, ...] = (
    "Subscription",
    "Perpetual",
    "Volume",
    "Named User",
    "Concurrent",
    "Open Source / Freeware",
    "Other",
)

_CATEGORY_PREFIXES: dict[str, str] = {
    "Desktop": "DSK",
    "Laptop": "LAP",
    "Printer": "PRT",
    "Network Device": "NET",
    "Server": "SRV",
    "Other": "OTH",
}

_ASSET_SORT_COLUMNS: dict[str, str] = {
    "updated_at": "updated_at",
    "asset_id": "asset_id",
    "asset_name": "asset_name",
    "category": "category",
    "status": "status",
    "department": "department",
}


@dataclass(frozen=True)
class Asset:
    """Represents a managed IT hardware/infrastructure asset."""

    asset_id: str
    asset_name: str
    category: str
    manufacturer: str
    model: str
    serial_number: str
    operating_system: str
    assigned_employee: str
    department: str
    location: str
    purchase_date: str
    warranty_expiration: str
    status: str
    hardware_summary: str
    notes: str
    is_demo: bool
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class AssetSoftwareRecord:
    """Software inventory item linked to a managed asset."""

    id: int
    asset_id: str
    software_name: str
    version: str
    publisher: str
    install_date: str
    source: str
    recorded_at: str


@dataclass(frozen=True)
class SoftwareLicense:
    """Software license entitlement record (never stores license keys)."""

    license_id: str
    software_name: str
    vendor: str
    license_type: str
    quantity: int
    assigned_count: int
    expiration_date: str
    department: str
    notes: str
    is_demo: bool
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class AssetSummary:
    """Aggregated asset and license counts for dashboards."""

    total_assets: int
    available_count: int
    assigned_count: int
    maintenance_count: int
    retired_count: int
    total_software_records: int
    total_licenses: int
    total_license_seats: int
    by_category: dict[str, int]
    by_department: dict[str, int]


@dataclass(frozen=True)
class DiagnosticImportPreview:
    """Read-only local telemetry preview awaiting explicit user confirmation."""

    suggested_asset_name: str
    suggested_category: str
    manufacturer: str
    model: str
    serial_number: str
    operating_system: str
    hardware_summary: str
    hardware_snapshot: HardwareSnapshot
    os_info: OsInfo
    software_items: list[SoftwareItem]


def _row_to_asset(row: sqlite3.Row) -> Asset:
    return Asset(
        asset_id=str(row["asset_id"]),
        asset_name=str(row["asset_name"]),
        category=str(row["category"]),
        manufacturer=str(row["manufacturer"]),
        model=str(row["model"]),
        serial_number=str(row["serial_number"]),
        operating_system=str(row["operating_system"]),
        assigned_employee=str(row["assigned_employee"]),
        department=str(row["department"]),
        location=str(row["location"]),
        purchase_date=str(row["purchase_date"]),
        warranty_expiration=str(row["warranty_expiration"]),
        status=str(row["status"]),
        hardware_summary=str(row["hardware_summary"]),
        notes=str(row["notes"]),
        is_demo=bool(row["is_demo"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def _row_to_license(row: sqlite3.Row) -> SoftwareLicense:
    return SoftwareLicense(
        license_id=str(row["license_id"]),
        software_name=str(row["software_name"]),
        vendor=str(row["vendor"]),
        license_type=str(row["license_type"]),
        quantity=int(row["quantity"]),
        assigned_count=int(row["assigned_count"]),
        expiration_date=str(row["expiration_date"]),
        department=str(row["department"]),
        notes=str(row["notes"]),
        is_demo=bool(row["is_demo"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def _validate_optional_date(value: str, label: str) -> str:
    cleaned = (value or "").strip()
    if not cleaned:
        return ""
    try:
        datetime.strptime(cleaned, "%Y-%m-%d")
    except ValueError as exc:
        raise ValidationError(f"{label} must use YYYY-MM-DD format.") from exc
    return cleaned


def generate_asset_id(category: str, db_path: Path | str = DEFAULT_DB_PATH) -> str:
    """Generate a unique sequential asset ID (e.g., AST-LAP-0001)."""
    initialize_database(db_path)
    clean_cat = validate_choice(category, ASSET_CATEGORIES, "asset category")
    prefix = f"AST-{_CATEGORY_PREFIXES[clean_cat]}"
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT asset_id FROM assets WHERE asset_id LIKE ?",
            (f"{prefix}-%",),
        ).fetchall()
        max_seq = 0
        for row in rows:
            parts = str(row["asset_id"]).rsplit("-", 1)
            if len(parts) == 2 and parts[1].isdigit():
                max_seq = max(max_seq, int(parts[1]))
        return f"{prefix}-{max_seq + 1:04d}"


def create_asset(
    *,
    asset_name: str,
    category: str,
    manufacturer: str,
    model: str,
    status: str = "Available",
    asset_id: str | None = None,
    serial_number: str = "",
    operating_system: str = "",
    assigned_employee: str = "",
    department: str = "",
    location: str = "",
    purchase_date: str = "",
    warranty_expiration: str = "",
    hardware_summary: str = "",
    notes: str = "",
    is_demo: bool = False,
    db_path: Path | str = DEFAULT_DB_PATH,
) -> Asset:
    """Register a new IT asset in SQLite with uniqueness and enum validation."""
    initialize_database(db_path)

    clean_name = require_non_empty(asset_name, "Asset name")
    clean_cat = validate_choice(category, ASSET_CATEGORIES, "asset category")
    clean_mfg = require_non_empty(manufacturer, "Manufacturer")
    clean_model = require_non_empty(model, "Model")
    clean_status = validate_choice(status, ASSET_STATUSES, "asset status")
    clean_purchase = _validate_optional_date(purchase_date, "Purchase date")
    clean_warranty = _validate_optional_date(warranty_expiration, "Warranty expiration")

    now = utc_now_iso()
    final_id = (asset_id or "").strip() or generate_asset_id(clean_cat, db_path=db_path)

    with get_connection(db_path) as conn:
        existing = conn.execute(
            "SELECT 1 FROM assets WHERE asset_id = ?",
            (final_id,),
        ).fetchone()
        if existing is not None:
            raise DuplicateRecordError(f"Asset ID '{final_id}' already exists.")

        conn.execute(
            """
            INSERT INTO assets (
                asset_id, asset_name, category, manufacturer, model, serial_number,
                operating_system, assigned_employee, department, location,
                purchase_date, warranty_expiration, status, hardware_summary,
                notes, is_demo, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                final_id,
                clean_name,
                clean_cat,
                clean_mfg,
                clean_model,
                (serial_number or "").strip(),
                (operating_system or "").strip(),
                (assigned_employee or "").strip(),
                (department or "").strip(),
                (location or "").strip(),
                clean_purchase,
                clean_warranty,
                clean_status,
                (hardware_summary or "").strip(),
                (notes or "").strip(),
                1 if is_demo else 0,
                now,
                now,
            ),
        )
        row = conn.execute("SELECT * FROM assets WHERE asset_id = ?", (final_id,)).fetchone()
        return _row_to_asset(row)


def get_asset(asset_id: str, db_path: Path | str = DEFAULT_DB_PATH) -> Asset:
    """Retrieve a single asset by unique asset_id."""
    initialize_database(db_path)
    clean_id = require_non_empty(asset_id, "Asset ID")
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM assets WHERE asset_id = ?", (clean_id,)).fetchone()
        if row is None:
            raise RecordNotFoundError(f"Asset '{clean_id}' was not found.")
        return _row_to_asset(row)


def list_assets(
    *,
    search: str = "",
    category: str = "All",
    status: str = "All",
    department: str = "All",
    sort_by: str = "updated_at",
    sort_desc: bool = True,
    db_path: Path | str = DEFAULT_DB_PATH,
) -> list[Asset]:
    """Query IT assets with safe parameterized filtering and sorting."""
    initialize_database(db_path)
    clauses: list[str] = []
    params: list[str] = []

    cleaned_search = (search or "").strip()
    if cleaned_search:
        like_term = f"%{cleaned_search}%"
        clauses.append(
            "(asset_id LIKE ? OR asset_name LIKE ? OR manufacturer LIKE ? OR model LIKE ? "
            "OR serial_number LIKE ? OR assigned_employee LIKE ? OR department LIKE ? OR location LIKE ?)"
        )
        params.extend([like_term] * 8)

    for col, val in (("category", category), ("status", status), ("department", department)):
        if val and val != "All":
            clauses.append(f"{col} = ?")
            params.append(val)

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sort_col = _ASSET_SORT_COLUMNS.get(sort_by, "updated_at")
    direction = "DESC" if sort_desc else "ASC"

    with get_connection(db_path) as conn:
        rows = conn.execute(
            f"SELECT * FROM assets {where_sql} ORDER BY {sort_col} {direction}, asset_id ASC",
            tuple(params),
        ).fetchall()
        return [_row_to_asset(r) for r in rows]


def update_asset(
    asset_id: str,
    *,
    asset_name: str | None = None,
    category: str | None = None,
    status: str | None = None,
    assigned_employee: str | None = None,
    department: str | None = None,
    location: str | None = None,
    operating_system: str | None = None,
    purchase_date: str | None = None,
    warranty_expiration: str | None = None,
    notes: str | None = None,
    db_path: Path | str = DEFAULT_DB_PATH,
) -> Asset:
    """Update an existing asset record safely."""
    initialize_database(db_path)
    clean_id = require_non_empty(asset_id, "Asset ID")

    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM assets WHERE asset_id = ?", (clean_id,)).fetchone()
        if row is None:
            raise RecordNotFoundError(f"Asset '{clean_id}' was not found.")
        current = _row_to_asset(row)

        new_name = require_non_empty(asset_name, "Asset name") if asset_name is not None else current.asset_name
        new_cat = validate_choice(category, ASSET_CATEGORIES, "asset category") if category is not None else current.category
        new_status = validate_choice(status, ASSET_STATUSES, "asset status") if status is not None else current.status
        new_purchase = (
            _validate_optional_date(purchase_date, "Purchase date")
            if purchase_date is not None
            else current.purchase_date
        )
        new_warranty = (
            _validate_optional_date(warranty_expiration, "Warranty expiration")
            if warranty_expiration is not None
            else current.warranty_expiration
        )

        now = utc_now_iso()
        conn.execute(
            """
            UPDATE assets
            SET asset_name = ?,
                category = ?,
                status = ?,
                assigned_employee = ?,
                department = ?,
                location = ?,
                operating_system = ?,
                purchase_date = ?,
                warranty_expiration = ?,
                notes = ?,
                updated_at = ?
            WHERE asset_id = ?
            """,
            (
                new_name,
                new_cat,
                new_status,
                assigned_employee.strip() if assigned_employee is not None else current.assigned_employee,
                department.strip() if department is not None else current.department,
                location.strip() if location is not None else current.location,
                operating_system.strip() if operating_system is not None else current.operating_system,
                new_purchase,
                new_warranty,
                notes.strip() if notes is not None else current.notes,
                now,
                clean_id,
            ),
        )
        updated = conn.execute("SELECT * FROM assets WHERE asset_id = ?", (clean_id,)).fetchone()
        return _row_to_asset(updated)


def delete_asset(asset_id: str, db_path: Path | str = DEFAULT_DB_PATH) -> None:
    """Permanently delete an asset and its linked software inventory records."""
    initialize_database(db_path)
    clean_id = require_non_empty(asset_id, "Asset ID")
    with get_connection(db_path) as conn:
        cursor = conn.execute("DELETE FROM assets WHERE asset_id = ?", (clean_id,))
        if cursor.rowcount == 0:
            raise RecordNotFoundError(f"Asset '{clean_id}' was not found.")


def add_asset_software(
    asset_id: str,
    software_items: list[dict[str, str]] | list[SoftwareItem],
    db_path: Path | str = DEFAULT_DB_PATH,
) -> int:
    """Attach software inventory items to an asset without duplicating existing versions."""
    initialize_database(db_path)
    clean_id = require_non_empty(asset_id, "Asset ID")
    now = utc_now_iso()
    inserted = 0

    with get_connection(db_path) as conn:
        exists = conn.execute("SELECT 1 FROM assets WHERE asset_id = ?", (clean_id,)).fetchone()
        if exists is None:
            raise RecordNotFoundError(f"Asset '{clean_id}' was not found.")

        for item in software_items:
            if isinstance(item, SoftwareItem):
                sw_name = item.name.strip()
                sw_ver = item.version.strip()
                sw_pub = item.publisher.strip()
                sw_date = item.install_date.strip()
                sw_src = item.source.strip() or "Diagnostic Import"
            else:
                sw_name = (item.get("software_name") or item.get("name") or "").strip()
                sw_ver = (item.get("version") or "").strip()
                sw_pub = (item.get("publisher") or "").strip()
                sw_date = (item.get("install_date") or "").strip()
                sw_src = (item.get("source") or "Manual").strip()

            if not sw_name:
                continue

            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO asset_software_inventory (
                    asset_id, software_name, version, publisher, install_date, source, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (clean_id, sw_name, sw_ver, sw_pub, sw_date, sw_src, now),
            )
            inserted += cursor.rowcount

    return inserted


def list_asset_software(
    asset_id: str | None = None,
    search: str = "",
    db_path: Path | str = DEFAULT_DB_PATH,
) -> list[AssetSoftwareRecord]:
    """List software inventory entries for a specific asset or across all assets."""
    initialize_database(db_path)
    clauses: list[str] = []
    params: list[str] = []

    if asset_id and asset_id != "All":
        clauses.append("asset_id = ?")
        params.append(asset_id)

    cleaned_search = (search or "").strip()
    if cleaned_search:
        like_term = f"%{cleaned_search}%"
        clauses.append("(software_name LIKE ? OR publisher LIKE ? OR asset_id LIKE ?)")
        params.extend([like_term] * 3)

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with get_connection(db_path) as conn:
        rows = conn.execute(
            f"""
            SELECT id, asset_id, software_name, version, publisher, install_date, source, recorded_at
            FROM asset_software_inventory
            {where_sql}
            ORDER BY software_name ASC, asset_id ASC
            """,
            tuple(params),
        ).fetchall()
        return [
            AssetSoftwareRecord(
                id=int(r["id"]),
                asset_id=str(r["asset_id"]),
                software_name=str(r["software_name"]),
                version=str(r["version"]),
                publisher=str(r["publisher"]),
                install_date=str(r["install_date"]),
                source=str(r["source"]),
                recorded_at=str(r["recorded_at"]),
            )
            for r in rows
        ]


def prepare_local_diagnostic_import(include_software: bool = False) -> DiagnosticImportPreview:
    """Collect read-only local hardware/OS/software telemetry for user review prior to import."""
    hw = collect_hardware_snapshot()
    os_info = get_os_info()
    software = get_installed_software() if include_software else []

    suggested_cat = "Laptop" if hw.battery.present else "Desktop"
    ram_total = format_bytes(hw.memory.total_bytes, fallback=UNKNOWN_VALUE)
    primary_disk = hw.logical_disks[0] if hw.logical_disks else None
    disk_total = format_bytes(primary_disk.total_bytes, fallback=UNKNOWN_VALUE) if primary_disk else UNKNOWN_VALUE
    hw_summary = (
        f"CPU: {hw.cpu.processor_name} ({hw.cpu.logical_cores or UNKNOWN_VALUE} threads) | "
        f"RAM: {ram_total} | Primary Disk: {disk_total}"
    )

    return DiagnosticImportPreview(
        suggested_asset_name=os_info.hostname,
        suggested_category=suggested_cat,
        manufacturer=hw.system_specs.manufacturer,
        model=hw.system_specs.model,
        serial_number=hw.system_specs.serial_number,
        operating_system=f"{os_info.os_name} (Build {os_info.os_build})",
        hardware_summary=hw_summary,
        hardware_snapshot=hw,
        os_info=os_info,
        software_items=software,
    )


def import_asset_from_diagnostics(
    *,
    preview: DiagnosticImportPreview,
    asset_name: str | None = None,
    category: str | None = None,
    asset_id: str | None = None,
    assigned_employee: str = "",
    department: str = "",
    location: str = "",
    status: str = "Assigned",
    include_serial: bool = False,
    selected_software: list[SoftwareItem] | None = None,
    db_path: Path | str = DEFAULT_DB_PATH,
) -> tuple[Asset, int]:
    """Persist user-confirmed local diagnostic hardware and software into IT Asset Management."""
    serial = preview.serial_number if include_serial else ""
    asset = create_asset(
        asset_id=asset_id,
        asset_name=(asset_name or "").strip() or preview.suggested_asset_name,
        category=category or preview.suggested_category,
        manufacturer=preview.manufacturer,
        model=preview.model,
        serial_number=serial,
        operating_system=preview.operating_system,
        assigned_employee=assigned_employee,
        department=department,
        location=location,
        status=status,
        hardware_summary=preview.hardware_summary,
        notes="Imported from local endpoint diagnostics after user confirmation.",
        db_path=db_path,
    )

    imported_sw_count = 0
    if selected_software:
        imported_sw_count = add_asset_software(asset.asset_id, selected_software, db_path=db_path)

    return asset, imported_sw_count


def _generate_license_id(conn: sqlite3.Connection) -> str:
    rows = conn.execute("SELECT license_id FROM software_licenses WHERE license_id LIKE 'LIC-%'").fetchall()
    max_seq = 0
    for row in rows:
        parts = str(row["license_id"]).rsplit("-", 1)
        if len(parts) == 2 and parts[1].isdigit():
            max_seq = max(max_seq, int(parts[1]))
    return f"LIC-{max_seq + 1:04d}"


def create_software_license(
    *,
    software_name: str,
    vendor: str,
    license_type: str,
    quantity: int,
    assigned_count: int = 0,
    expiration_date: str = "",
    department: str = "",
    notes: str = "",
    license_id: str | None = None,
    is_demo: bool = False,
    db_path: Path | str = DEFAULT_DB_PATH,
) -> SoftwareLicense:
    """Register a software license entitlement without storing license keys."""
    initialize_database(db_path)

    clean_sw = require_non_empty(software_name, "Software name")
    clean_vendor = require_non_empty(vendor, "Vendor")
    clean_type = validate_choice(license_type, LICENSE_TYPES, "license type")
    if quantity < 1:
        raise ValidationError("License quantity must be at least 1.")
    if assigned_count < 0 or assigned_count > quantity:
        raise ValidationError("Assigned count must be between 0 and total quantity.")
    clean_exp = _validate_optional_date(expiration_date, "Expiration date")

    now = utc_now_iso()
    with get_connection(db_path) as conn:
        final_id = (license_id or "").strip() or _generate_license_id(conn)
        existing = conn.execute(
            "SELECT 1 FROM software_licenses WHERE license_id = ?",
            (final_id,),
        ).fetchone()
        if existing is not None:
            raise DuplicateRecordError(f"License ID '{final_id}' already exists.")

        conn.execute(
            """
            INSERT INTO software_licenses (
                license_id, software_name, vendor, license_type, quantity, assigned_count,
                expiration_date, department, notes, is_demo, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                final_id,
                clean_sw,
                clean_vendor,
                clean_type,
                int(quantity),
                int(assigned_count),
                clean_exp,
                (department or "").strip(),
                (notes or "").strip(),
                1 if is_demo else 0,
                now,
                now,
            ),
        )
        row = conn.execute(
            "SELECT * FROM software_licenses WHERE license_id = ?",
            (final_id,),
        ).fetchone()
        return _row_to_license(row)


def list_software_licenses(
    *,
    search: str = "",
    license_type: str = "All",
    db_path: Path | str = DEFAULT_DB_PATH,
) -> list[SoftwareLicense]:
    """List persisted software license entitlements."""
    initialize_database(db_path)
    clauses: list[str] = []
    params: list[str] = []

    cleaned_search = (search or "").strip()
    if cleaned_search:
        like_term = f"%{cleaned_search}%"
        clauses.append("(license_id LIKE ? OR software_name LIKE ? OR vendor LIKE ? OR department LIKE ?)")
        params.extend([like_term] * 4)

    if license_type and license_type != "All":
        clauses.append("license_type = ?")
        params.append(license_type)

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with get_connection(db_path) as conn:
        rows = conn.execute(
            f"SELECT * FROM software_licenses {where_sql} ORDER BY software_name ASC, license_id ASC",
            tuple(params),
        ).fetchall()
        return [_row_to_license(r) for r in rows]


def update_software_license(
    license_id: str,
    *,
    quantity: int | None = None,
    assigned_count: int | None = None,
    expiration_date: str | None = None,
    department: str | None = None,
    notes: str | None = None,
    db_path: Path | str = DEFAULT_DB_PATH,
) -> SoftwareLicense:
    """Update seat counts, expiration, or department for an existing license record."""
    initialize_database(db_path)
    clean_id = require_non_empty(license_id, "License ID")

    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM software_licenses WHERE license_id = ?", (clean_id,)).fetchone()
        if row is None:
            raise RecordNotFoundError(f"License '{clean_id}' was not found.")
        current = _row_to_license(row)

        new_qty = int(quantity) if quantity is not None else current.quantity
        new_assigned = int(assigned_count) if assigned_count is not None else current.assigned_count
        if new_qty < 1:
            raise ValidationError("License quantity must be at least 1.")
        if new_assigned < 0 or new_assigned > new_qty:
            raise ValidationError("Assigned count must be between 0 and total quantity.")

        new_exp = (
            _validate_optional_date(expiration_date, "Expiration date")
            if expiration_date is not None
            else current.expiration_date
        )
        now = utc_now_iso()
        conn.execute(
            """
            UPDATE software_licenses
            SET quantity = ?,
                assigned_count = ?,
                expiration_date = ?,
                department = ?,
                notes = ?,
                updated_at = ?
            WHERE license_id = ?
            """,
            (
                new_qty,
                new_assigned,
                new_exp,
                department.strip() if department is not None else current.department,
                notes.strip() if notes is not None else current.notes,
                now,
                clean_id,
            ),
        )
        updated = conn.execute(
            "SELECT * FROM software_licenses WHERE license_id = ?",
            (clean_id,),
        ).fetchone()
        return _row_to_license(updated)


def delete_software_license(license_id: str, db_path: Path | str = DEFAULT_DB_PATH) -> None:
    """Delete a software license entitlement record."""
    initialize_database(db_path)
    clean_id = require_non_empty(license_id, "License ID")
    with get_connection(db_path) as conn:
        cursor = conn.execute("DELETE FROM software_licenses WHERE license_id = ?", (clean_id,))
        if cursor.rowcount == 0:
            raise RecordNotFoundError(f"License '{clean_id}' was not found.")


def get_asset_summary(db_path: Path | str = DEFAULT_DB_PATH) -> AssetSummary:
    """Compute aggregated asset, software, and license KPIs."""
    assets = list_assets(db_path=db_path)
    software_records = list_asset_software(db_path=db_path)
    licenses = list_software_licenses(db_path=db_path)

    by_category: dict[str, int] = {cat: 0 for cat in ASSET_CATEGORIES}
    by_department: dict[str, int] = {}
    available = assigned = maintenance = retired = 0

    for a in assets:
        by_category[a.category] = by_category.get(a.category, 0) + 1
        dept_label = a.department or "Unassigned"
        by_department[dept_label] = by_department.get(dept_label, 0) + 1
        if a.status == "Available":
            available += 1
        elif a.status == "Assigned":
            assigned += 1
        elif a.status == "Under Maintenance":
            maintenance += 1
        elif a.status == "Retired":
            retired += 1

    return AssetSummary(
        total_assets=len(assets),
        available_count=available,
        assigned_count=assigned,
        maintenance_count=maintenance,
        retired_count=retired,
        total_software_records=len(software_records),
        total_licenses=len(licenses),
        total_license_seats=sum(lic.quantity for lic in licenses),
        by_category=by_category,
        by_department=by_department,
    )


def export_assets_csv(assets: list[Asset]) -> str:
    """Serialize IT assets into a CSV string."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "Asset ID",
            "Asset Name",
            "Category",
            "Manufacturer",
            "Model",
            "Serial Number",
            "Operating System",
            "Assigned Employee",
            "Department",
            "Location",
            "Purchase Date",
            "Warranty Expiration",
            "Status",
            "Hardware Summary",
            "Notes",
            "Demo Record",
            "Created At",
            "Updated At",
        ]
    )
    for a in assets:
        writer.writerow(
            [
                sanitize_csv_cell(v)
                for v in (
                    a.asset_id,
                    a.asset_name,
                    a.category,
                    a.manufacturer,
                    a.model,
                    a.serial_number,
                    a.operating_system,
                    a.assigned_employee,
                    a.department,
                    a.location,
                    a.purchase_date,
                    a.warranty_expiration,
                    a.status,
                    a.hardware_summary,
                    a.notes,
                    "Yes" if a.is_demo else "No",
                    a.created_at,
                    a.updated_at,
                )
            ]
        )
    return buffer.getvalue()


def export_licenses_csv(licenses: list[SoftwareLicense]) -> str:
    """Serialize software license entitlements into a CSV string (no license keys)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "License ID",
            "Software Name",
            "Vendor",
            "License Type",
            "Quantity",
            "Assigned",
            "Available",
            "Expiration Date",
            "Department",
            "Notes",
            "Demo Record",
            "Updated At",
        ]
    )
    for lic in licenses:
        writer.writerow(
            [
                sanitize_csv_cell(v)
                for v in (
                    lic.license_id,
                    lic.software_name,
                    lic.vendor,
                    lic.license_type,
                    lic.quantity,
                    lic.assigned_count,
                    max(0, lic.quantity - lic.assigned_count),
                    lic.expiration_date,
                    lic.department,
                    lic.notes,
                    "Yes" if lic.is_demo else "No",
                    lic.updated_at,
                )
            ]
        )
    return buffer.getvalue()


def export_asset_software_csv(records: list[AssetSoftwareRecord]) -> str:
    """Serialize linked asset software inventory records into CSV."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["Asset ID", "Software Name", "Version", "Publisher", "Install Date", "Source", "Recorded At"]
    )
    for r in records:
        writer.writerow(
            [
                sanitize_csv_cell(v)
                for v in (
                    r.asset_id,
                    r.software_name,
                    r.version,
                    r.publisher,
                    r.install_date,
                    r.source,
                    r.recorded_at,
                )
            ]
        )
    return buffer.getvalue()


def load_demo_assets_and_licenses(db_path: Path | str = DEFAULT_DB_PATH) -> tuple[int, int]:
    """
    Insert clearly labeled fictional demonstration assets and licenses if absent.

    Never overwrites existing records; returns (assets_inserted, licenses_inserted).
    """
    initialize_database(db_path)
    demo_assets: list[dict[str, Any]] = [
        {
            "asset_id": "AST-LAP-DEMO1",
            "asset_name": "[DEMO] FIN-TRD-LAP01",
            "category": "Laptop",
            "manufacturer": "Lenovo (Demo)",
            "model": "ThinkPad T14 Gen 4",
            "serial_number": "DEMO-SN-001",
            "operating_system": "Windows 11 Enterprise",
            "assigned_employee": "Jordan Blake (Demo)",
            "department": "Equities Desk (Demo)",
            "location": "NY-HQ Floor 14",
            "purchase_date": "2025-04-15",
            "warranty_expiration": "2028-04-15",
            "status": "Assigned",
            "hardware_summary": "16 threads | 32 GB RAM | 512 GB NVMe",
        },
        {
            "asset_id": "AST-SRV-DEMO2",
            "asset_name": "[DEMO] FIN-APP-SRV02",
            "category": "Server",
            "manufacturer": "Dell (Demo)",
            "model": "PowerEdge R650",
            "serial_number": "DEMO-SN-002",
            "operating_system": "Windows Server 2022",
            "assigned_employee": "Infrastructure Ops (Demo)",
            "department": "Core Infrastructure (Demo)",
            "location": "DC-East Rack B04",
            "purchase_date": "2024-09-01",
            "warranty_expiration": "2029-09-01",
            "status": "Assigned",
            "hardware_summary": "32 threads | 128 GB ECC RAM | 4 TB RAID",
        },
        {
            "asset_id": "AST-NET-DEMO3",
            "asset_name": "[DEMO] FIN-CORE-SW03",
            "category": "Network Device",
            "manufacturer": "Cisco (Demo)",
            "model": "Catalyst 9300-48P",
            "serial_number": "DEMO-SN-003",
            "operating_system": "IOS XE 17.x",
            "assigned_employee": "",
            "department": "Network Engineering (Demo)",
            "location": "IDF-14B",
            "purchase_date": "2024-02-10",
            "warranty_expiration": "2029-02-10",
            "status": "Available",
            "hardware_summary": "48-Port PoE+ Access Switch",
        },
    ]

    demo_licenses: list[dict[str, Any]] = [
        {
            "license_id": "LIC-DEMO-001",
            "software_name": "[DEMO] Microsoft 365 E5",
            "vendor": "Microsoft (Demo)",
            "license_type": "Subscription",
            "quantity": 50,
            "assigned_count": 42,
            "expiration_date": "2027-06-30",
            "department": "Enterprise Wide (Demo)",
            "notes": "Fictional demonstration entitlement record (no key stored).",
        },
        {
            "license_id": "LIC-DEMO-002",
            "software_name": "[DEMO] Endpoint Security EDR Agent",
            "vendor": "CyberShield (Demo)",
            "license_type": "Named User",
            "quantity": 100,
            "assigned_count": 88,
            "expiration_date": "2027-12-31",
            "department": "Information Security (Demo)",
            "notes": "Fictional demonstration entitlement record (no key stored).",
        },
    ]

    assets_added = 0
    for spec in demo_assets:
        try:
            create_asset(**spec, is_demo=True, db_path=db_path)
            assets_added += 1
        except DuplicateRecordError:
            continue

    licenses_added = 0
    for spec in demo_licenses:
        try:
            create_software_license(**spec, is_demo=True, db_path=db_path)
            licenses_added += 1
        except DuplicateRecordError:
            continue

    return assets_added, licenses_added


def clear_demo_assets_and_licenses(db_path: Path | str = DEFAULT_DB_PATH) -> tuple[int, int]:
    """Delete only records explicitly marked as fictional demo assets/licenses."""
    initialize_database(db_path)
    with get_connection(db_path) as conn:
        a_cur = conn.execute("DELETE FROM assets WHERE is_demo = 1")
        l_cur = conn.execute("DELETE FROM software_licenses WHERE is_demo = 1")
        return int(a_cur.rowcount), int(l_cur.rowcount)
