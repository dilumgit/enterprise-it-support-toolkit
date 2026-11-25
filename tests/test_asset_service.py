"""Unit tests for IT Asset Management and Software License Inventory."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from src.database.db import DuplicateRecordError, RecordNotFoundError, ValidationError
from src.services.asset_service import (
    DiagnosticImportPreview,
    clear_demo_assets_and_licenses,
    create_asset,
    create_software_license,
    delete_asset,
    delete_software_license,
    export_asset_software_csv,
    export_assets_csv,
    export_licenses_csv,
    get_asset,
    get_asset_summary,
    import_asset_from_diagnostics,
    list_asset_software,
    list_assets,
    list_software_licenses,
    load_demo_assets_and_licenses,
    update_asset,
    update_software_license,
)
from src.services.system_info import SoftwareItem


def test_create_update_filter_and_delete_asset(tmp_path: Path) -> None:
    db = tmp_path / "assets.db"
    a1 = create_asset(
        asset_name="FIN-WS-01",
        category="Laptop",
        manufacturer="Dell",
        model="Latitude 5440",
        status="Assigned",
        assigned_employee="Analyst A",
        department="Risk",
        location="HQ-10",
        purchase_date="2025-01-15",
        warranty_expiration="2028-01-15",
        db_path=db,
    )
    a2 = create_asset(
        asset_name="FIN-PRT-02",
        category="Printer",
        manufacturer="HP",
        model="LaserJet Enterprise",
        status="Available",
        department="Operations",
        db_path=db,
    )

    assert a1.asset_id.startswith("AST-LAP-")
    assert a2.asset_id.startswith("AST-PRT-")

    fetched = get_asset(a1.asset_id, db_path=db)
    assert fetched.manufacturer == "Dell"

    updated = update_asset(
        a1.asset_id,
        status="Under Maintenance",
        notes="Fan replacement scheduled",
        db_path=db,
    )
    assert updated.status == "Under Maintenance"

    filtered = list_assets(search="Latitude", category="Laptop", db_path=db)
    assert len(filtered) == 1
    assert filtered[0].asset_id == a1.asset_id

    csv_out = export_assets_csv(list_assets(db_path=db))
    assert "FIN-WS-01" in csv_out
    assert "FIN-PRT-02" in csv_out

    delete_asset(a2.asset_id, db_path=db)
    with pytest.raises(RecordNotFoundError):
        get_asset(a2.asset_id, db_path=db)


def test_asset_validation_and_duplicate_id_rejected(tmp_path: Path) -> None:
    db = tmp_path / "assets_val.db"
    with pytest.raises(ValidationError):
        create_asset(
            asset_name="Bad Date Asset",
            category="Desktop",
            manufacturer="HP",
            model="ProDesk",
            purchase_date="15/01/2025",
            db_path=db,
        )

    create_asset(
        asset_id="AST-UNIQ-1",
        asset_name="Host 1",
        category="Server",
        manufacturer="Dell",
        model="R650",
        db_path=db,
    )
    with pytest.raises(DuplicateRecordError):
        create_asset(
            asset_id="AST-UNIQ-1",
            asset_name="Host 2",
            category="Server",
            manufacturer="Dell",
            model="R650",
            db_path=db,
        )


def test_import_asset_from_diagnostics_respects_serial_opt_in_and_dedups_software(tmp_path: Path) -> None:
    db = tmp_path / "assets_import.db"
    preview = DiagnosticImportPreview(
        suggested_asset_name="LOCAL-FIN-HOST",
        suggested_category="Laptop",
        manufacturer="Lenovo",
        model="ThinkPad X1",
        serial_number="SECRET-SERIAL-999",
        operating_system="Windows 11 Enterprise (Build 22621)",
        hardware_summary="CPU: Intel i7 | RAM: 32.00 GB",
        hardware_snapshot=SimpleNamespace(),  # type: ignore[arg-type]
        os_info=SimpleNamespace(),  # type: ignore[arg-type]
        software_items=[
            SoftwareItem("Python 3.13.2", "3.13.2", "PSF", "2025-02-05", "HKCU"),
            SoftwareItem("Python 3.13.2", "3.13.2", "PSF", "2025-02-05", "HKLM"),
            SoftwareItem("Git", "2.47.0", "Git", "2025-01-10", "HKLM"),
        ],
    )

    asset, sw_count = import_asset_from_diagnostics(
        preview=preview,
        assigned_employee="Desk Analyst",
        department="Trading Support",
        location="NY-14",
        include_serial=False,
        selected_software=preview.software_items,
        db_path=db,
    )

    assert asset.serial_number == ""
    assert asset.asset_name == "LOCAL-FIN-HOST"
    assert sw_count == 2

    sw_records = list_asset_software(asset_id=asset.asset_id, db_path=db)
    assert len(sw_records) == 2
    sw_csv = export_asset_software_csv(sw_records)
    assert "Python 3.13.2" in sw_csv


def test_software_license_crud_and_seat_validation(tmp_path: Path) -> None:
    db = tmp_path / "licenses.db"
    with pytest.raises(ValidationError):
        create_software_license(
            software_name="App",
            vendor="Vendor",
            license_type="Subscription",
            quantity=5,
            assigned_count=6,
            db_path=db,
        )

    lic = create_software_license(
        software_name="Enterprise VPN Client",
        vendor="NetVendor",
        license_type="Named User",
        quantity=25,
        assigned_count=10,
        expiration_date="2027-12-31",
        department="Infrastructure",
        db_path=db,
    )
    assert lic.license_id.startswith("LIC-")

    updated = update_software_license(lic.license_id, assigned_count=15, db_path=db)
    assert updated.assigned_count == 15

    licenses = list_software_licenses(search="VPN", db_path=db)
    assert len(licenses) == 1
    assert "Enterprise VPN Client" in export_licenses_csv(licenses)

    delete_software_license(lic.license_id, db_path=db)
    assert list_software_licenses(db_path=db) == []


def test_asset_summary_and_demo_seed_clear(tmp_path: Path) -> None:
    db = tmp_path / "assets_demo.db"
    a_cnt, l_cnt = load_demo_assets_and_licenses(db_path=db)
    assert a_cnt == 3
    assert l_cnt == 2
    assert load_demo_assets_and_licenses(db_path=db) == (0, 0)

    summary = get_asset_summary(db_path=db)
    assert summary.total_assets == 3
    assert summary.total_licenses == 2
    assert summary.total_license_seats == 150

    a_del, l_del = clear_demo_assets_and_licenses(db_path=db)
    assert (a_del, l_del) == (3, 2)
