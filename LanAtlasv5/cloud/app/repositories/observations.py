"""
repositories/observations.py

All SQL touching the `observations` table lives here — nowhere else.

IMPORTANT DESIGN NOTE (discovered during the PostgreSQL migration):
observations.payload_hash now has a UNIQUE constraint at the schema
level (uq_observations_payload_hash) — this did not exist in the
original SQLite schema. That changes where duplicate-submission
handling should happen:

  - insert_observation_if_new() is the authoritative dedup check.
    A retried agent submission with an identical payload_hash is
    rejected by the database itself before any application code runs.
    This should be what the API layer calls when an agent submits an
    observation.

  - is_duplicate() / get_resolved_by_hash() remain useful as a
    secondary safety net inside services.identity.resolve_observation()
    — e.g. if a background worker (workers/identity_worker.py) picks
    up the same already-linked observation row twice, this check makes
    re-resolution a safe no-op instead of reprocessing it.

Both layers matter: the UNIQUE constraint prevents duplicate ROWS,
this secondary check prevents duplicate RESOLUTION WORK on a row that
already exists.
"""

from sqlalchemy import text
from sqlalchemy.engine import Connection


def insert_observation_if_new(db: Connection, observation: dict) -> int | None:
    """
    Inserts a new observations row. Returns None if a row with this
    payload_hash already exists — the UNIQUE constraint makes this the
    authoritative duplicate-submission check. Callers should treat a
    None return as "already processed, do not resolve again" and call
    get_resolved_by_hash() instead of calling resolve_observation().
    """
    row = db.execute(text("""
        INSERT INTO observations (
            organization_id, site_id, agent_id, mac_address, ip_address,
            hostname, payload_hash, protocol_used, scan_tier, observed_at
        ) VALUES (
            :organization_id, :site_id, :agent_id, :mac_address, :ip_address,
            :hostname, :payload_hash, :protocol_used, :scan_tier, :observed_at
        )
        ON CONFLICT (payload_hash) DO NOTHING
        RETURNING id
    """), observation).fetchone()
    return row.id if row else None


def is_duplicate(db: Connection, payload_hash: str) -> bool:
    """
    True if an observation with this hash exists AND has already been
    resolved (device_id is set). An observation that exists but has
    device_id = NULL is unprocessed, not a duplicate — it's simply
    waiting for the identity engine to resolve it.
    """
    row = db.execute(text("""
        SELECT id FROM observations
        WHERE payload_hash = :payload_hash AND device_id IS NOT NULL
    """), {"payload_hash": payload_hash}).fetchone()
    return row is not None


def get_resolved_by_hash(db: Connection, payload_hash: str) -> dict | None:
    row = db.execute(text("""
        SELECT device_id, match_confidence, match_method
        FROM observations WHERE payload_hash = :payload_hash
    """), {"payload_hash": payload_hash}).fetchone()
    return dict(row._mapping) if row else None


def link(
    db: Connection,
    observation_id: int,
    device_id: int,
    match_confidence: int,
    match_method: str,
) -> None:
    """Writes the resolved device_id, confidence, and method back onto the observation."""
    db.execute(text("""
        UPDATE observations
        SET device_id = :device_id,
            match_confidence = :match_confidence,
            match_method = :match_method
        WHERE id = :observation_id
    """), {
        "device_id": device_id,
        "match_confidence": match_confidence,
        "match_method": match_method,
        "observation_id": observation_id,
    })


def get_unresolved(db: Connection, limit: int = 100) -> list[dict]:
    """
    Returns unresolved observations (device_id IS NULL), oldest first.
    Used by workers/identity_worker.py to batch-process the backlog.
    """
    rows = db.execute(text("""
        SELECT * FROM observations
        WHERE device_id IS NULL
        ORDER BY observed_at ASC
        LIMIT :limit
    """), {"limit": limit}).fetchall()
    return [dict(r._mapping) for r in rows]
