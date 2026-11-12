"""
repositories/devices.py

All SQL touching the `devices` table lives here — nowhere else.
Every function takes a SQLAlchemy Connection and returns plain Python
values (dicts, primitives, ids) — never business logic, never scoring.

Transactions are NOT committed here. The caller (database.db.get_db()
or database.db.get_test_db(), depending on context) owns the
transaction boundary. This keeps commit/rollback centralized in one
place per the project's "Centralized Enforcement" principle.
"""

from sqlalchemy import text
from sqlalchemy.engine import Connection


def insert_device(
    db: Connection,
    organization_id: int,
    site_id: int,
    fingerprint_hash: str,
    primary_mac: str | None,
    vendor_name: str | None,
    device_type: str,
    classification_source: str,
    identity_strength: int,
    is_authorized: bool,
    missing_threshold_hours: int,
) -> int:
    """
    Inserts a new device row. If a device with the same
    (organization_id, site_id, fingerprint_hash) already exists, the
    insert is skipped and the existing device's id is returned instead.

    This is the PostgreSQL equivalent of SQLite's INSERT OR IGNORE,
    using ON CONFLICT against the named unique constraint from the
    schema (uq_devices_fingerprint_per_site).
    """
    row = db.execute(text("""
        INSERT INTO devices (
            organization_id, site_id, fingerprint_hash, primary_mac,
            vendor_name, device_type, classification_source,
            last_seen, seen_count, missing_threshold_hours,
            identity_strength, is_authorized
        ) VALUES (
            :organization_id, :site_id, :fingerprint_hash, :primary_mac,
            :vendor_name, :device_type, :classification_source,
            NOW(), 0, :missing_threshold_hours,
            :identity_strength, :is_authorized
        )
        ON CONFLICT ON CONSTRAINT uq_devices_fingerprint_per_site
        DO NOTHING
        RETURNING id
    """), {
        "organization_id": organization_id,
        "site_id": site_id,
        "fingerprint_hash": fingerprint_hash,
        "primary_mac": primary_mac,
        "vendor_name": vendor_name,
        "device_type": device_type,
        "classification_source": classification_source,
        "missing_threshold_hours": missing_threshold_hours,
        "identity_strength": identity_strength,
        "is_authorized": is_authorized,
    }).fetchone()

    if row is not None:
        return row.id

    # ON CONFLICT fired — the device already exists. Fetch its id.
    existing = fetch_by_fingerprint(db, organization_id, site_id, fingerprint_hash)
    return existing["id"]


def fetch_by_fingerprint(
    db: Connection, organization_id: int, site_id: int, fingerprint_hash: str
) -> dict | None:
    row = db.execute(text("""
        SELECT id FROM devices
        WHERE organization_id = :organization_id
          AND site_id = :site_id
          AND fingerprint_hash = :fingerprint_hash
    """), {
        "organization_id": organization_id,
        "site_id": site_id,
        "fingerprint_hash": fingerprint_hash,
    }).fetchone()
    return dict(row._mapping) if row else None


def get_device(db: Connection, device_id: int) -> dict | None:
    row = db.execute(text("""
        SELECT * FROM devices WHERE id = :device_id
    """), {"device_id": device_id}).fetchone()
    return dict(row._mapping) if row else None


def update_identity(db: Connection, device_id: int, identity_strength: int) -> None:
    """
    Updates identity_strength and last_seen, increments seen_count.
    Called after signal reconciliation determines a new strength score.

    updated_at is maintained automatically by the fn_set_updated_at
    trigger on this table — do not set it here.
    """
    db.execute(text("""
        UPDATE devices
        SET identity_strength = :identity_strength,
            last_seen = NOW(),
            seen_count = seen_count + 1
        WHERE id = :device_id
    """), {
        "identity_strength": identity_strength,
        "device_id": device_id,
    })


# ─────────────────────────────────────────────────────────────────────
# The two functions below are NOT part of the identity engine.
# They are included as a worked example of how audit logging hooks in
# for the human-initiated mutations (rename, delete) that Sam's API
# layer will need. See services/devices.py (not yet built) for the
# service-layer function that would call these and then write an
# AuditEvent via repositories/audit.py.
# ─────────────────────────────────────────────────────────────────────

def rename_device(db: Connection, device_id: int, new_name: str) -> dict:
    """
    Updates friendly_name. Returns {'before': ..., 'after': ...} so the
    calling service function has everything it needs to build an
    AuditEvent — this repository function does not write audit logs
    itself. SQL stays confined to repositories/; audit event
    construction stays in services/.
    """
    before = get_device(db, device_id)
    db.execute(text("""
        UPDATE devices SET friendly_name = :new_name WHERE id = :device_id
    """), {"new_name": new_name, "device_id": device_id})
    after = get_device(db, device_id)
    return {"before": before, "after": after}


def delete_device(db: Connection, device_id: int) -> dict:
    before = get_device(db, device_id)
    db.execute(text("DELETE FROM devices WHERE id = :device_id"), {"device_id": device_id})
    return {"before": before, "after": None}
