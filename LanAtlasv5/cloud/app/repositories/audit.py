"""

All SQL touching the `audit_log` table lives here — nowhere else.

audit_log rows are immutable: the schema enforces this with triggers
(fn_prevent_audit_log_mutation) that raise on UPDATE or DELETE. This
repository therefore only ever INSERTs and SELECTs — there is
deliberately no update_audit_log() or delete_audit_log() function,
because none should ever exist.
"""

import json
from sqlalchemy import text
from sqlalchemy.engine import Connection

from database.audit import AuditEvent


def insert_audit_log(db: Connection, event: AuditEvent) -> None:
    """
    Persists a single audit event. Called by service-layer functions
    immediately after a mutation succeeds — never before, so a failed
    mutation never produces a misleading audit entry.
    """
    db.execute(text("""
        INSERT INTO audit_log (
            organization_id, user_id, action, entity_type, entity_id,
            before_value, after_value, ip_address, created_at
        ) VALUES (
            :organization_id, :user_id, :action, :entity_type, :entity_id,
            :before_value, :after_value, :ip_address, :occurred_at
        )
    """), {
        "organization_id": event.organization_id,
        "user_id": event.user_id,
        "action": event.action,
        "entity_type": event.entity_type,
        "entity_id": event.entity_id,
        "before_value": json.dumps(event.before) if event.before is not None else None,
        "after_value": json.dumps(event.after) if event.after is not None else None,
        "ip_address": event.ip_address,
        "occurred_at": event.occurred_at,
    })


def fetch_for_entity(db: Connection, entity_type: str, entity_id: int) -> list[dict]:
    """Returns the full audit trail for a single entity, newest first."""
    rows = db.execute(text("""
        SELECT * FROM audit_log
        WHERE entity_type = :entity_type AND entity_id = :entity_id
        ORDER BY created_at DESC
    """), {"entity_type": entity_type, "entity_id": entity_id}).fetchall()
    return [dict(r._mapping) for r in rows]


def fetch_for_organization(db: Connection, organization_id: int, limit: int = 100) -> list[dict]:
    """Returns the most recent audit events for a tenant — dashboard 'activity log' view."""
    rows = db.execute(text("""
        SELECT * FROM audit_log
        WHERE organization_id = :organization_id
        ORDER BY created_at DESC
        LIMIT :limit
    """), {"organization_id": organization_id, "limit": limit}).fetchall()
    return [dict(r._mapping) for r in rows]
