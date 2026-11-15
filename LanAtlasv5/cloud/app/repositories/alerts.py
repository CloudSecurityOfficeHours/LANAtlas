
"""
repositories/alerts.py
 
All SQL touching the `alerts` table lives here — nowhere else.
Every function takes a SQLAlchemy Connection and returns plain Python
values (dicts, primitives, ids) — never business logic, never scoring.
 
Transactions are NOT committed here. The caller owns the transaction
boundary, per the project's "Centralized Enforcement" principle.
"""
 
from sqlalchemy import text
from sqlalchemy.engine import Connection
 
 
def has_open_alert(db: Connection, device_id: int, alert_type_name: str) -> bool:
    """Return True if the device already has an unresolved alert of this type."""
    row = db.execute(
        text("""
            SELECT 1
            FROM alerts a
            JOIN alert_type t ON t.id = a.alert_type_id
            WHERE a.device_id = :device_id
              AND t.alert_type_name = :alert_type_name
              AND a.resolved_at IS NULL
            LIMIT 1
        """),
        {"device_id": device_id, "alert_type_name": alert_type_name},
    ).fetchone()
    return row is not None
 
 
def create(
    db: Connection,
    organization_id: int,
    site_id: int,
    alert_type_name: str,
    alert_message: str,
    device_id: int | None = None,
    observation_id: int | None = None,
    severity: str | None = None,
    metadata: str | None = None,
) -> int:
    """Insert an open alert and return its id.
 
    If severity is None, the alert_type's default_severity is used.
    """
    row = db.execute(
        text("""
            INSERT INTO alerts (
                organization_id, site_id, device_id, observation_id,
                alert_type_id, metadata, severity, alert_message
            )
            SELECT
                :organization_id, :site_id, :device_id, :observation_id,
                t.id, :metadata, COALESCE(:severity, t.default_severity),
                :alert_message
            FROM alert_type t
            WHERE t.alert_type_name = :alert_type_name
            RETURNING id
        """),
        {
            "organization_id": organization_id,
            "site_id": site_id,
            "device_id": device_id,
            "observation_id": observation_id,
            "alert_type_name": alert_type_name,
            "metadata": metadata,
            "severity": severity,
            "alert_message": alert_message,
        },
    ).fetchone()
    if row is None:
        raise ValueError(f"Unknown alert type: {alert_type_name!r}")
    return int(row[0])
 
