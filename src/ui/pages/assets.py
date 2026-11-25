"""IT Asset Management & Software License Inventory dedicated page."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from src.database.db import DatabaseError, DuplicateRecordError, RecordNotFoundError, ValidationError
from src.services.asset_service import (
    ASSET_CATEGORIES,
    ASSET_STATUSES,
    LICENSE_TYPES,
    clear_demo_assets_and_licenses,
    create_asset,
    create_software_license,
    delete_asset,
    delete_software_license,
    export_asset_software_csv,
    export_assets_csv,
    export_licenses_csv,
    get_asset_summary,
    import_asset_from_diagnostics,
    list_asset_software,
    list_assets,
    list_software_licenses,
    load_demo_assets_and_licenses,
    prepare_local_diagnostic_import,
    update_asset,
    update_software_license,
)
from src.ui.components import (
    PLOTLY_CONFIG,
    build_count_bar_chart,
    render_kpi_card,
    render_page_header,
    render_section_title,
)


def render() -> None:
    """Render the IT Asset Management & Software License Inventory page."""
    render_page_header(
        title="IT Asset Management",
        subtitle="Hardware asset lifecycle, local diagnostic inventory import, software inventory, and license tracking.",
        badge_text="Implemented",
    )

    try:
        summary = get_asset_summary()
    except DatabaseError as exc:
        st.error(f"Database error loading Asset Management summary: {exc}")
        return

    k1, k2, k3, k4 = st.columns(4)
    with k1:
        render_kpi_card("Managed Assets", str(summary.total_assets), f"Assigned: {summary.assigned_count} | Available: {summary.available_count}")
    with k2:
        render_kpi_card(
            "Maintenance / Retired",
            f"{summary.maintenance_count} / {summary.retired_count}",
            "Lifecycle states",
            status="Under Maintenance" if summary.maintenance_count > 0 else "Healthy",
        )
    with k3:
        render_kpi_card("Linked Software Records", str(summary.total_software_records), "Per-asset software inventory")
    with k4:
        render_kpi_card("License Entitlements", str(summary.total_licenses), f"Total seats: {summary.total_license_seats} (no keys stored)")

    st.write("")

    tab_assets, tab_register, tab_import, tab_software, tab_licenses, tab_summary = st.tabs(
        [
            "Asset Registry",
            "Register / Update Asset",
            "Import Local Diagnostics",
            "Asset Software Inventory",
            "Software Licenses",
            "Summary & Demo Controls",
        ]
    )

    with tab_assets:
        f1, f2, f3, f4 = st.columns([2.2, 1, 1, 1.2])
        with f1:
            search = st.text_input("Search assets", placeholder="ID, name, model, employee, department, location", key="am_search")
        with f2:
            cat_filter = st.selectbox("Category", ["All", *ASSET_CATEGORIES], key="am_cat_filter")
        with f3:
            stat_filter = st.selectbox("Status", ["All", *ASSET_STATUSES], key="am_stat_filter")
        with f4:
            sort_by = st.selectbox("Sort by", ["updated_at", "asset_id", "asset_name", "category", "status", "department"], key="am_sort_by")

        assets = list_assets(search=search, category=cat_filter, status=stat_filter, sort_by=sort_by)
        col_cnt, col_csv = st.columns([3, 1.2])
        with col_cnt:
            st.caption(f"Showing **{len(assets)}** asset record(s).")
        with col_csv:
            st.download_button(
                label=f"Export Assets CSV ({len(assets)})",
                data=export_assets_csv(assets),
                file_name="it_assets.csv",
                mime="text/csv",
                width="stretch",
                disabled=not assets,
            )

        if assets:
            rows = [
                {
                    "Asset ID": a.asset_id,
                    "Asset Name": a.asset_name,
                    "Category": a.category,
                    "Manufacturer": a.manufacturer,
                    "Model": a.model,
                    "OS": a.operating_system or "N/A",
                    "Employee": a.assigned_employee or "Unassigned",
                    "Department": a.department or "Unassigned",
                    "Location": a.location or "N/A",
                    "Status": a.status,
                    "Warranty": a.warranty_expiration or "N/A",
                    "Demo": "Yes" if a.is_demo else "No",
                }
                for a in assets
            ]
            st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
        else:
            st.info("No assets match the current filter.")

    with tab_register:
        col_new, col_edit = st.columns(2)
        with col_new:
            render_section_title("Register New Asset")
            with st.form("create_asset_form", clear_on_submit=True):
                custom_id = st.text_input("Asset ID (optional — auto-generated if blank)", placeholder="e.g., AST-LAP-0010")
                asset_name = st.text_input("Asset Name *", placeholder="e.g., FIN-WS-1042")
                c1, c2 = st.columns(2)
                with c1:
                    category = st.selectbox("Category *", ASSET_CATEGORIES)
                    manufacturer = st.text_input("Manufacturer *", placeholder="e.g., Dell, Lenovo")
                    operating_system = st.text_input("Operating System", placeholder="e.g., Windows 11 Enterprise")
                    assigned_employee = st.text_input("Assigned Employee")
                    purchase_date = st.text_input("Purchase Date (YYYY-MM-DD)")
                with c2:
                    status = st.selectbox("Status *", ASSET_STATUSES)
                    model = st.text_input("Model *", placeholder="e.g., Latitude 5440")
                    serial_number = st.text_input("Serial Number (Optional)")
                    department = st.text_input("Department")
                    warranty_expiration = st.text_input("Warranty Expiration (YYYY-MM-DD)")
                location = st.text_input("Location", placeholder="e.g., HQ Floor 8")
                notes = st.text_area("Notes")
                if st.form_submit_button("Register Asset", type="primary"):
                    try:
                        created = create_asset(
                            asset_id=custom_id or None,
                            asset_name=asset_name,
                            category=category,
                            manufacturer=manufacturer,
                            model=model,
                            serial_number=serial_number,
                            operating_system=operating_system,
                            assigned_employee=assigned_employee,
                            department=department,
                            location=location,
                            purchase_date=purchase_date,
                            warranty_expiration=warranty_expiration,
                            status=status,
                            notes=notes,
                        )
                        st.success(f"Asset `{created.asset_id}` registered.")
                        st.rerun()
                    except (ValidationError, DuplicateRecordError, DatabaseError) as exc:
                        st.error(str(exc))

        with col_edit:
            render_section_title("Update or Delete Asset")
            all_assets = list_assets()
            if not all_assets:
                st.info("Register an asset first to edit or delete.")
            else:
                asset_opts = {f"{a.asset_id} — {a.asset_name} [{a.status}]": a.asset_id for a in all_assets}
                sel_label = st.selectbox("Select Asset", list(asset_opts.keys()), key="am_edit_select")
                sel_asset = next(a for a in all_assets if a.asset_id == asset_opts[sel_label])

                with st.form("edit_asset_form"):
                    u_name = st.text_input("Asset Name *", value=sel_asset.asset_name)
                    u1, u2 = st.columns(2)
                    with u1:
                        u_cat = st.selectbox("Category", ASSET_CATEGORIES, index=ASSET_CATEGORIES.index(sel_asset.category))
                        u_emp = st.text_input("Assigned Employee", value=sel_asset.assigned_employee)
                        u_loc = st.text_input("Location", value=sel_asset.location)
                    with u2:
                        u_stat = st.selectbox("Status", ASSET_STATUSES, index=ASSET_STATUSES.index(sel_asset.status))
                        u_dept = st.text_input("Department", value=sel_asset.department)
                        u_warr = st.text_input("Warranty (YYYY-MM-DD)", value=sel_asset.warranty_expiration)
                    u_notes = st.text_area("Notes", value=sel_asset.notes)
                    if st.form_submit_button("Save Asset Changes", type="primary"):
                        try:
                            update_asset(
                                sel_asset.asset_id,
                                asset_name=u_name,
                                category=u_cat,
                                status=u_stat,
                                assigned_employee=u_emp,
                                department=u_dept,
                                location=u_loc,
                                warranty_expiration=u_warr,
                                notes=u_notes,
                            )
                            st.success(f"Asset `{sel_asset.asset_id}` updated.")
                            st.rerun()
                        except (ValidationError, RecordNotFoundError, DatabaseError) as exc:
                            st.error(str(exc))

                confirm_del_asset = st.checkbox(
                    f"Confirm permanent deletion of asset {sel_asset.asset_id}",
                    key="am_confirm_del_asset",
                )
                if st.button("Delete Selected Asset", disabled=not confirm_del_asset):
                    try:
                        delete_asset(sel_asset.asset_id)
                        st.success(f"Deleted `{sel_asset.asset_id}`.")
                        st.rerun()
                    except (RecordNotFoundError, DatabaseError) as exc:
                        st.error(str(exc))

    with tab_import:
        render_section_title("Import Local Endpoint Diagnostics (Confirmation Required)")
        st.caption(
            "Reads local hardware and optional software inventory from Phase 1 diagnostic modules. "
            "Nothing is written to SQLite until you review the preview and confirm."
        )
        include_sw_scan = st.checkbox("Include installed Windows software inventory in preview", value=False)
        if st.button("Preview Local System Telemetry", key="am_preview_diag"):
            with st.spinner("Collecting read-only hardware/OS telemetry..."):
                st.session_state["am_diag_preview"] = prepare_local_diagnostic_import(include_software=include_sw_scan)

        preview = st.session_state.get("am_diag_preview")
        if preview is not None:
            st.info(
                f"**Detected Host:** `{preview.suggested_asset_name}` | "
                f"**Hardware:** `{preview.manufacturer} {preview.model}` | "
                f"**OS:** `{preview.operating_system}`"
            )
            st.caption(f"Hardware Summary: {preview.hardware_summary}")

            with st.form("confirm_diag_import_form"):
                i1, i2 = st.columns(2)
                with i1:
                    imp_id = st.text_input("Asset ID (blank to auto-generate)")
                    imp_name = st.text_input("Asset Name *", value=preview.suggested_asset_name)
                    imp_cat = st.selectbox(
                        "Category",
                        ASSET_CATEGORIES,
                        index=ASSET_CATEGORIES.index(preview.suggested_category),
                    )
                with i2:
                    imp_emp = st.text_input("Assigned Employee")
                    imp_dept = st.text_input("Department")
                    imp_loc = st.text_input("Location")
                imp_status = st.selectbox("Asset Status", ASSET_STATUSES, index=1)
                include_serial = st.checkbox(
                    f"Include BIOS Serial Number ({preview.serial_number}) — leave unchecked to omit hardware identifier",
                    value=False,
                )
                import_sw_count = len(preview.software_items)
                import_sw_flag = st.checkbox(
                    f"Import {import_sw_count} discovered software item(s) into asset inventory",
                    value=import_sw_count > 0,
                    disabled=import_sw_count == 0,
                )
                confirm_import = st.checkbox("I confirm saving this diagnostic snapshot to the local Asset DB")
                if st.form_submit_button("Confirm & Import Asset", type="primary"):
                    if not confirm_import:
                        st.warning("Please check the confirmation box before importing.")
                    else:
                        try:
                            imported_asset, sw_added = import_asset_from_diagnostics(
                                preview=preview,
                                asset_id=imp_id or None,
                                asset_name=imp_name,
                                category=imp_cat,
                                assigned_employee=imp_emp,
                                department=imp_dept,
                                location=imp_loc,
                                status=imp_status,
                                include_serial=include_serial,
                                selected_software=preview.software_items if import_sw_flag else None,
                            )
                            st.success(
                                f"Imported asset `{imported_asset.asset_id}` with {sw_added} software record(s)."
                            )
                            st.session_state.pop("am_diag_preview", None)
                            st.rerun()
                        except (ValidationError, DuplicateRecordError, DatabaseError) as exc:
                            st.error(str(exc))

    with tab_software:
        render_section_title("Per-Asset Software Inventory")
        all_assets_sw = list_assets()
        asset_filter_opts = ["All", *[a.asset_id for a in all_assets_sw]]
        s1, s2, s3 = st.columns([1.2, 2, 1.2])
        with s1:
            sw_asset_filter = st.selectbox("Filter by Asset ID", asset_filter_opts, key="am_sw_asset_filter")
        with s2:
            sw_search = st.text_input("Search linked software", placeholder="Application or publisher", key="am_sw_search")

        sw_records = list_asset_software(asset_id=sw_asset_filter, search=sw_search)
        with s3:
            st.write("")
            st.download_button(
                label=f"Export Software CSV ({len(sw_records)})",
                data=export_asset_software_csv(sw_records),
                file_name="asset_software_inventory.csv",
                mime="text/csv",
                width="stretch",
                disabled=not sw_records,
            )

        if sw_records:
            sw_rows = [
                {
                    "Asset ID": r.asset_id,
                    "Software": r.software_name,
                    "Version": r.version,
                    "Publisher": r.publisher,
                    "Install Date": r.install_date,
                    "Source": r.source,
                    "Recorded At": r.recorded_at,
                }
                for r in sw_records
            ]
            st.dataframe(pd.DataFrame(sw_rows), width="stretch", hide_index=True)
        else:
            st.info("No linked software records yet. Import local diagnostics with software enabled to populate.")

    with tab_licenses:
        render_section_title("Software License Inventory (Entitlement Metadata Only — No License Keys Stored)")
        l_search = st.text_input("Search licenses", placeholder="Software, vendor, department", key="am_lic_search")
        l_type_filter = st.selectbox("License Type", ["All", *LICENSE_TYPES], key="am_lic_type_filter")
        licenses = list_software_licenses(search=l_search, license_type=l_type_filter)

        st.download_button(
            label=f"Export Licenses CSV ({len(licenses)})",
            data=export_licenses_csv(licenses),
            file_name="software_licenses.csv",
            mime="text/csv",
            disabled=not licenses,
        )

        if licenses:
            lic_rows = [
                {
                    "License ID": lic.license_id,
                    "Software": lic.software_name,
                    "Vendor": lic.vendor,
                    "Type": lic.license_type,
                    "Quantity": lic.quantity,
                    "Assigned": lic.assigned_count,
                    "Available": max(0, lic.quantity - lic.assigned_count),
                    "Expiration": lic.expiration_date or "Perpetual / N/A",
                    "Department": lic.department or "Enterprise",
                    "Demo": "Yes" if lic.is_demo else "No",
                }
                for lic in licenses
            ]
            st.dataframe(pd.DataFrame(lic_rows), width="stretch", hide_index=True)
        else:
            st.info("No software license records registered.")

        col_lnew, col_ledit = st.columns(2)
        with col_lnew:
            render_section_title("Add Software License")
            with st.form("create_license_form", clear_on_submit=True):
                lic_sw = st.text_input("Software Name *")
                lic_vendor = st.text_input("Vendor *")
                lic_type = st.selectbox("License Type *", LICENSE_TYPES)
                q1, q2 = st.columns(2)
                with q1:
                    lic_qty = st.number_input("Total Quantity *", min_value=1, value=10, step=1)
                with q2:
                    lic_assigned = st.number_input("Assigned Seats", min_value=0, value=0, step=1)
                lic_exp = st.text_input("Expiration Date (YYYY-MM-DD, optional)")
                lic_dept = st.text_input("Department")
                lic_notes = st.text_input("Notes (Do not enter license keys)")
                if st.form_submit_button("Add License Record", type="primary"):
                    try:
                        created_lic = create_software_license(
                            software_name=lic_sw,
                            vendor=lic_vendor,
                            license_type=lic_type,
                            quantity=int(lic_qty),
                            assigned_count=int(lic_assigned),
                            expiration_date=lic_exp,
                            department=lic_dept,
                            notes=lic_notes,
                        )
                        st.success(f"License `{created_lic.license_id}` added.")
                        st.rerun()
                    except (ValidationError, DuplicateRecordError, DatabaseError) as exc:
                        st.error(str(exc))

        with col_ledit:
            render_section_title("Update or Delete License")
            if licenses:
                lic_opts = {f"{l.license_id} — {l.software_name}": l.license_id for l in licenses}
                sel_lic_lbl = st.selectbox("Select License", list(lic_opts.keys()), key="am_lic_edit_select")
                sel_lic = next(l for l in licenses if l.license_id == lic_opts[sel_lic_lbl])
                with st.form("edit_license_form"):
                    el_qty = st.number_input("Total Quantity", min_value=1, value=sel_lic.quantity, step=1)
                    el_assigned = st.number_input("Assigned Seats", min_value=0, value=sel_lic.assigned_count, step=1)
                    el_exp = st.text_input("Expiration Date (YYYY-MM-DD)", value=sel_lic.expiration_date)
                    el_dept = st.text_input("Department", value=sel_lic.department)
                    if st.form_submit_button("Update License"):
                        try:
                            update_software_license(
                                sel_lic.license_id,
                                quantity=int(el_qty),
                                assigned_count=int(el_assigned),
                                expiration_date=el_exp,
                                department=el_dept,
                            )
                            st.success(f"Updated `{sel_lic.license_id}`.")
                            st.rerun()
                        except (ValidationError, RecordNotFoundError, DatabaseError) as exc:
                            st.error(str(exc))

                confirm_del_lic = st.checkbox(
                    f"Confirm deletion of license {sel_lic.license_id}",
                    key="am_confirm_del_lic",
                )
                if st.button("Delete Selected License", disabled=not confirm_del_lic):
                    try:
                        delete_software_license(sel_lic.license_id)
                        st.success(f"Deleted `{sel_lic.license_id}`.")
                        st.rerun()
                    except (RecordNotFoundError, DatabaseError) as exc:
                        st.error(str(exc))

    with tab_summary:
        if summary.total_assets > 0:
            st.plotly_chart(
                build_count_bar_chart("Hardware Assets by Category", summary.by_category, color="#38BDF8"),
                width="stretch",
                config=PLOTLY_CONFIG,
            )
        else:
            st.info("No assets registered yet to chart.")

        render_section_title("Fictional Demonstration Data (Optional)")
        st.caption(
            "Demonstration assets and licenses use clearly labeled fictional records (`[DEMO]` prefix, no license keys). "
            "Loading demo data never overwrites existing records."
        )
        d1, d2 = st.columns(2)
        with d1:
            if st.button("Load Fictional Demo Assets & Licenses", width="stretch"):
                a_cnt, l_cnt = load_demo_assets_and_licenses()
                st.success(f"Inserted {a_cnt} demo asset(s) and {l_cnt} demo license(s).")
                st.rerun()
        with d2:
            confirm_clear_demo = st.checkbox("Confirm clearing [DEMO] assets & licenses only", key="am_confirm_clear_demo")
            if st.button("Clear Demo Assets & Licenses", disabled=not confirm_clear_demo, width="stretch"):
                a_del, l_del = clear_demo_assets_and_licenses()
                st.success(f"Removed {a_del} demo asset(s) and {l_del} demo license(s).")
                st.rerun()
