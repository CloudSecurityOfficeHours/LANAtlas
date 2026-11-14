"""
repositories/signals.py

All SQL touching the `device_fingerprint_signals` table lives here —
nowhere else. This is the repository the identity engine relies on
most heavily: candidate lookup, signal loading, and signal reconciliation.
"""

from sqlalchemy import text
from sqlalchemy.engine import Connection


def find_candidates(db: Connection, incoming_signals: dict[str, str]) -> list[dict]:
    """
    Finds any device that shares at least one signal with the incoming
    observation. Broad net — services.identity.score_candidate() does
    the actual narrowing. Deduplicates by device_id.
    """
    seen_ids: set[int] = set()
    candidates: list[dict] = []

    for signal_type, signal_value in incoming_signals.items():
        rows = db.execute(text("""
            SELECT DISTINCT device_id FROM device_fingerprint_signals
            WHERE signal_type = :signal_type AND signal_value = :signal_value
        """), {"signal_type": signal_type, "signal_value": signal_value}).fetchall()

        for row in rows:
            if row.device_id not in seen_ids:
                candidates.append({"device_id": row.device_id})
                seen_ids.add(row.device_id)

    return candidates


def load_signals(db: Connection, device_id: int) -> dict[str, list[str]]:
    """
    Loads all known signals for a device.

    Returns {signal_type: [signal_value, ...]} — a device can have
    multiple known MACs, hostnames, etc. over its lifetime, so values
    are returned as lists rather than a single value per type.
    """
    rows = db.execute(text("""
        SELECT signal_type, signal_value
        FROM device_fingerprint_signals
        WHERE device_id = :device_id
        ORDER BY last_seen DESC
    """), {"device_id": device_id}).fetchall()

    signals: dict[str, list[str]] = {}
    for row in rows:
        signals.setdefault(row.signal_type, []).append(row.signal_value)
    return signals


def get_signal_types(db: Connection, device_id: int) -> list[str]:
    """
    Returns the distinct signal types on record for a device — used by
    services.identity.calculate_identity_strength() to recompute the
    aggregate score after a reconciliation.
    """
    rows = db.execute(text("""
        SELECT DISTINCT signal_type FROM device_fingerprint_signals
        WHERE device_id = :device_id
    """), {"device_id": device_id}).fetchall()
    return [row.signal_type for row in rows]


def get_existing_signal(
    db: Connection, device_id: int, signal_type: str, signal_value: str
) -> dict | None:
    row = db.execute(text("""
        SELECT id FROM device_fingerprint_signals
        WHERE device_id = :device_id
          AND signal_type = :signal_type
          AND signal_value = :signal_value
    """), {
        "device_id": device_id,
        "signal_type": signal_type,
        "signal_value": signal_value,
    }).fetchone()
    return dict(row._mapping) if row else None


def touch_signal(db: Connection, signal_id: int) -> None:
    """Refreshes last_seen on an already-known signal — no new row created."""
    db.execute(text("""
        UPDATE device_fingerprint_signals SET last_seen = NOW() WHERE id = :signal_id
    """), {"signal_id": signal_id})


def insert_signal(
    db: Connection,
    device_id: int,
    observation_id: int | None,
    signal_type: str,
    signal_value: str,
    confidence: int,
    source: str,
) -> None:
    """
    Inserts a newly discovered signal for a device. There is no UNIQUE
    constraint on (device_id, signal_type, signal_value) in the
    current schema, so callers must check get_existing_signal() first
    (see services.identity.update_signals / create_device) to avoid
    duplicate rows — this mirrors the check-then-act pattern from the
    original engine rather than relying on ON CONFLICT here.
    """
    db.execute(text("""
        INSERT INTO device_fingerprint_signals (
            device_id, observation_id, signal_type, signal_value,
            confidence, source
        ) VALUES (
            :device_id, :observation_id, :signal_type, :signal_value,
            :confidence, :source
        )
    """), {
        "device_id": device_id,
        "observation_id": observation_id,
        "signal_type": signal_type,
        "signal_value": signal_value,
        "confidence": confidence,
        "source": source,
    })
