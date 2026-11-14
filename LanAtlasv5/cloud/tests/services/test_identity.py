"""
tests/services/test_identity.py

Successor to the original test_identity_engine.py. Same five
scenarios, adapted for PostgreSQL:

1. Real foreign keys now exist (organization -> sites -> agents ->
   observations -> devices), so every test seeds a minimal parent
   chain via seed_org_site_agent() before it can insert an observation.

2. Scores are integers (0-100) throughout, not floats (0.0-1.0).

3. observations.payload_hash now has a UNIQUE constraint at the
   schema level. Scenario 5 (duplicate observation) was rewritten to
   test the REAL production dedup path — a second INSERT with the
   same payload_hash is rejected by the database itself via
   ON CONFLICT DO NOTHING, rather than relying only on application
   logic to detect the duplicate. This is a stronger guarantee than
   the original SQLite version had.
"""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import text

from services import identity as identity_service
from services.deduplication import compute_payload_hash
from repositories import devices as device_repo
from repositories import signals as signal_repo
from repositories import observations as observation_repo


# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────

def seed_org_site_agent(db) -> dict:
    """
    Creates the minimum parent rows required by FK constraints on
    observations and devices: one organization, one site, one agent.
    Returns their ids so a test can build observations against them.
    """
    org_id = db.execute(text("""
        INSERT INTO organization (slug) VALUES (:slug) RETURNING id
    """), {"slug": f"test-org-{uuid.uuid4().hex[:8]}"}).fetchone().id

    site_id = db.execute(text("""
        INSERT INTO sites (organization_id, site_name)
        VALUES (:org_id, :name) RETURNING id
    """), {"org_id": org_id, "name": "Test Site"}).fetchone().id

    agent_id = db.execute(text("""
        INSERT INTO agents (site_id, agent_name, api_key_hash)
        VALUES (:site_id, 'test-agent', :key_hash) RETURNING id
    """), {"site_id": site_id, "key_hash": "x" * 64}).fetchone().id

    return {"organization_id": org_id, "site_id": site_id, "agent_id": agent_id}


def seed_observation(db, ctx: dict, overrides: dict | None = None) -> dict:
    """
    Inserts a real observations row (schema requires it — payload_hash,
    org/site/agent FKs are all NOT NULL) and returns it as a dict the
    identity service can consume, including its assigned id.
    """
    overrides = overrides or {}
    defaults = {
        "organization_id": ctx["organization_id"],
        "site_id":         ctx["site_id"],
        "agent_id":        ctx["agent_id"],
        "mac_address":     "AA:BB:CC:DD:EE:FF",
        "ip_address":      "192.168.1.100",
        "hostname":        None,
        "hardware_uuid":   None,
        "serial":          None,
        "open_ports":      None,
        "protocol_used":   "ARP",
        "scan_tier":       "UNAUTHENTICATED",
        "observed_at":     datetime.now(timezone.utc),
    }
    obs = {**defaults, **overrides}
    obs["payload_hash"] = compute_payload_hash(obs)

    row = db.execute(text("""
        INSERT INTO observations (
            organization_id, site_id, agent_id, mac_address, ip_address,
            hostname, payload_hash, protocol_used, scan_tier, observed_at
        ) VALUES (
            :organization_id, :site_id, :agent_id, :mac_address, :ip_address,
            :hostname, :payload_hash, :protocol_used, :scan_tier, :observed_at
        ) RETURNING id
    """), obs).fetchone()
    obs["id"] = row.id
    return obs


# ─────────────────────────────────────────────────────────────────────
# Scenario 1 — New device, no match
# ─────────────────────────────────────────────────────────────────────

def test_new_device_created(db):
    ctx = seed_org_site_agent(db)
    obs = seed_observation(db, ctx, {"mac_address": "AA:BB:CC:DD:EE:FF", "scan_tier": "UNAUTHENTICATED"})

    result = identity_service.resolve_observation(db, obs)
    device = device_repo.get_device(db, result["device_id"])
    signals = signal_repo.load_signals(db, result["device_id"])

    assert result["action"] == "created"
    assert device is not None
    assert "MAC" in signals
    assert device["identity_strength"] > 0
    assert device["is_authorized"] is False


# ─────────────────────────────────────────────────────────────────────
# Scenario 2 — Hardware anchor auto-links
# ─────────────────────────────────────────────────────────────────────

def test_hardware_anchor_autolinks(db):
    ctx = seed_org_site_agent(db)

    obs1 = seed_observation(db, ctx, {
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "hostname":    "main-switch-01",
        "scan_tier":   "UNAUTHENTICATED",
    })
    result1 = identity_service.resolve_observation(db, obs1)
    original_device_id = result1["device_id"]

    obs2 = seed_observation(db, ctx, {
        "mac_address":   "AA:BB:CC:DD:EE:FF",
        "hostname":      "main-switch-01",
        "hardware_uuid": "UUID-1234-5678-ABCD",
        "scan_tier":     "WMI",
        "protocol_used": "WMI",
    })
    result2 = identity_service.resolve_observation(db, obs2)

    device_count = db.execute(text("SELECT COUNT(*) FROM devices")).scalar()
    signals = signal_repo.load_signals(db, result2["device_id"])

    assert result2["action"] == "linked"
    assert result2["device_id"] == original_device_id
    assert device_count == 1
    assert result2["match_confidence"] >= 70
    assert "HARDWARE_UUID" in signals


# ─────────────────────────────────────────────────────────────────────
# Scenario 3 — High score, no anchor -> review
# ─────────────────────────────────────────────────────────────────────

def test_high_score_no_anchor_goes_to_review(db):
    ctx = seed_org_site_agent(db)

    obs1 = seed_observation(db, ctx, {
        "mac_address": "BB:CC:DD:EE:FF:AA",
        "hostname":    "workstation-07",
        "scan_tier":   "UNAUTHENTICATED",
    })
    identity_service.resolve_observation(db, obs1)

    # same MAC + HOSTNAME, still UNAUTHENTICATED
    # raw score = 75 (MAC 50 + HOSTNAME 25), ceiling = 65 (UNAUTHENTICATED)
    # effective = 65 -> MEDIUM -> review
    obs2 = seed_observation(db, ctx, {
        "mac_address": "BB:CC:DD:EE:FF:AA",
        "hostname":    "workstation-07",
        "scan_tier":   "UNAUTHENTICATED",
    })
    result2 = identity_service.resolve_observation(db, obs2)

    assert result2["action"] == "review"
    assert result2["match_confidence"] <= 65


# ─────────────────────────────────────────────────────────────────────
# Scenario 4 — Signal accumulation
# ─────────────────────────────────────────────────────────────────────

def test_signal_accumulation(db):
    ctx = seed_org_site_agent(db)

    obs1 = seed_observation(db, ctx, {"mac_address": "CC:DD:EE:FF:AA:BB", "scan_tier": "UNAUTHENTICATED"})
    result1 = identity_service.resolve_observation(db, obs1)
    device_id = result1["device_id"]
    strength_before = device_repo.get_device(db, device_id)["identity_strength"]

    obs2 = seed_observation(db, ctx, {
        "mac_address": "CC:DD:EE:FF:AA:BB",
        "hostname":    "printer-lab-01",
        "scan_tier":   "UNAUTHENTICATED",
    })
    identity_service.resolve_observation(db, obs2)
    strength_after = device_repo.get_device(db, device_id)["identity_strength"]

    signals = signal_repo.load_signals(db, device_id)

    assert strength_after > strength_before
    assert "HOSTNAME" in signals
    assert "MAC" in signals


# ─────────────────────────────────────────────────────────────────────
# Scenario 5 — Duplicate observation (agent retry)
#
# Rewritten for the schema-level UNIQUE constraint on payload_hash.
# The original SQLite version tested application-layer dedup logic;
# this version tests the actual production path: a second INSERT with
# the same payload_hash is rejected by PostgreSQL itself before
# resolve_observation is ever called a second time.
# ─────────────────────────────────────────────────────────────────────

def test_duplicate_observation_idempotent(db):
    ctx = seed_org_site_agent(db)
    fixed_time = datetime.now(timezone.utc)

    obs1 = seed_observation(db, ctx, {
        "mac_address": "DD:EE:FF:AA:BB:CC",
        "hostname":    "server-rack-02",
        "scan_tier":   "UNAUTHENTICATED",
        "observed_at": fixed_time,
    })
    result1 = identity_service.resolve_observation(db, obs1)

    # simulate an agent retry: same logical observation, same payload_hash
    retry_id = observation_repo.insert_observation_if_new(db, obs1)
    assert retry_id is None  # DB rejected the duplicate row outright

    # correct production behavior on a None insert: look up the
    # already-resolved result rather than re-running resolve_observation
    existing = observation_repo.get_resolved_by_hash(db, obs1["payload_hash"])

    device_count = db.execute(text("SELECT COUNT(*) FROM devices")).scalar()
    duplicate_signal_rows = db.execute(text("""
        SELECT COUNT(*) FROM (
            SELECT device_id, signal_type, signal_value, COUNT(*) AS c
            FROM device_fingerprint_signals
            GROUP BY device_id, signal_type, signal_value
            HAVING COUNT(*) > 1
        ) dupes
    """)).scalar()

    assert existing["device_id"] == result1["device_id"]
    assert device_count == 1
    assert duplicate_signal_rows == 0