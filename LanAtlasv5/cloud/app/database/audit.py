"""
Cross-cutting audit logging mechanism, used by every repository that
mutates tenant-owned data (devices, alerts, sites, users, agents).

This file defines WHAT an audit event looks like and how to build one
safely. The actual SQL INSERT into audit_log lives in
repositories/audit.py — consistent with the project rule that all SQL
is confined to repositories/. database/ owns shapes and mechanisms
(mirrors database/exceptions.py owning typed exceptions), not queries.

Scope: audit_log is specifically for human-initiated, user-attributable
actions taken through the dashboard (rename a device, resolve an alert,
change a role, rotate an agent key). Machine-initiated changes — the
identity engine creating a device from an observation, the alert worker
firing a missing_device alert — are already covered by observations,
alerts, and analyst_notes, and are NOT written to audit_log. Mixing the
two would make audit_log noisy and defeat its purpose as a clean trail
of "what did a human do."
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class AuditAction:
    """
    Known audit action names. Extend this list as new mutations are
    added — every user-facing mutation should have exactly one entry
    here, used consistently by the service function that performs it.
    """
    DEVICE_RENAMED       = "device.rename"
    DEVICE_DELETED       = "device.delete"
    DEVICE_AUTHORIZED    = "device.authorize"
    DEVICE_DEAUTHORIZED  = "device.deauthorize"
    ALERT_ACKNOWLEDGED   = "alert.acknowledge"
    ALERT_RESOLVED       = "alert.resolve"
    USER_ROLE_CHANGED    = "user.role_change"
    USER_DEACTIVATED     = "user.deactivate"
    AGENT_KEY_ROTATED    = "agent.key_rotate"
    AGENT_DEACTIVATED    = "agent.deactivate"
    SITE_HOURS_CHANGED   = "site.business_hours_change"


@dataclass(frozen=True)
class AuditEvent:
    """
    Immutable record of a single tenant-scoped, human-initiated
    mutation. before/after must be plain, JSON-serializable dicts —
    always pass them through redact() first if the source record could
    contain hashed secrets (api_key_hash, token_hash).
    """
    organization_id: int
    user_id: int | None          # the authenticated user who made the change
    action: str                  # one of AuditAction.*
    entity_type: str             # 'device' | 'alert' | 'user' | 'site' | 'agent'
    entity_id: int | None
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    ip_address: str | None = None
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# Fields that must never be written to audit_log, even hashed —
# the audit trail is retained long-term and read by more people
# (any admin, potentially auditors) than the systems that produce
# these values.
_ALWAYS_REDACT: set[str] = {
    "api_key_hash",
    "token_hash",
    "password_hash",   # defensive — should not exist in schema, but redact if it ever does
}


def redact(record: dict | None, extra_fields: set[str] | None = None) -> dict | None:
    """
    Strips sensitive fields from a before/after snapshot before it is
    handed to an AuditEvent. Always removes the fields in
    _ALWAYS_REDACT; pass extra_fields for anything additional specific
    to the entity being audited.

    Usage:
        before = device_repo.get_device(db, device_id)
        event = AuditEvent(..., before=redact(before), after=redact(after), ...)
    """
    if record is None:
        return None
    drop = _ALWAYS_REDACT | (extra_fields or set())
    return {k: v for k, v in record.items() if k not in drop}