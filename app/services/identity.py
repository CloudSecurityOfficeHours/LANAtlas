"""
services/identity.py

Business logic for device identity resolution. This is the direct
successor to the original identity_engine.py — same algorithm, same
decision logic, but with all SQL moved out to repositories/devices.py,
repositories/signals.py, and repositories/observations.py.

This file must never contain a raw SQL string. If a new function here
needs data from the database, add a function to the appropriate
repository and call it — do not reach for db.execute() directly.

Two behavioral changes from the original engine, both intentional:

1. All scores (identity_strength, match_confidence, signal confidence)
   are now integers on a 0-100 scale instead of floats on 0.0-1.0.
   This matches the SMALLINT columns in the PostgreSQL schema and
   eliminates float comparison drift.

2. update_signals() now threads the observation's actual protocol_used
   through to the stored signal's `source` column, instead of the
   original engine's hardcoded "ARP" — a bug fix uncovered while
   splitting the function apart.

3. Transaction commits are no longer called from within this module.
   The original engine called db.commit() inline; that responsibility
   now belongs entirely to database.db.get_db() / get_test_db(), per
   the project's Centralized Enforcement principle. Every function
   below assumes it is running inside a transaction the caller owns.
"""

import hashlib

from config.identity import (
    SIGNAL_WEIGHTS,
    CONFIDENCE_THRESHOLDS,
    TIER_CONFIDENCE_CEILING,
    HARDWARE_ANCHORED_SIGNALS,
)
from services.deduplication import compute_payload_hash
from services.classification import get_classification_source
from services.thresholds import get_missing_threshold
from repositories import devices as device_repo
from repositories import signals as signal_repo
from repositories import observations as observation_repo


# ─────────────────────────────────────────────────────────────────────
# Pure computation — no database access
# ─────────────────────────────────────────────────────────────────────

def extract_signals(observation: dict) -> dict[str, str]:
    """
    Pulls recognizable identity signals out of a raw observation
    payload. Extend this as the agent gains new scan capabilities.
    """
    signals: dict[str, str] = {}
    if observation.get("mac_address"):
        signals["MAC"] = observation["mac_address"].upper()
    if observation.get("hostname"):
        signals["HOSTNAME"] = observation["hostname"].lower()
    if observation.get("hardware_uuid"):
        signals["HARDWARE_UUID"] = observation["hardware_uuid"]
    if observation.get("serial"):
        signals["SERIAL"] = observation["serial"]
    if observation.get("open_ports"):
        signals["OPEN_PORTS"] = ",".join(str(p) for p in sorted(observation["open_ports"]))
    return signals


def is_hardware_anchored(signal_types: list[str]) -> bool:
    """
    True if at least one of the given signal types is hardware-anchored.
    Auto-linking requires this — a high score built entirely from
    network-observable signals (MAC, HOSTNAME) is not trustworthy
    enough to merge device records without human review.
    """
    return any(s in HARDWARE_ANCHORED_SIGNALS for s in signal_types)


def get_confidence_ceiling(observation: dict) -> int:
    """
    Returns the maximum allowable confidence score for this
    observation, based on its scan tier. Prevents UNAUTHENTICATED
    scans from auto-linking even if their raw score clears the
    HIGH threshold.
    """
    tier = observation.get("scan_tier", "UNAUTHENTICATED")
    return TIER_CONFIDENCE_CEILING.get(tier, 65)


def score_candidate(incoming_signals: dict[str, str], candidate_signals: dict[str, list[str]]) -> int:
    """
    Scores how likely an incoming observation matches a candidate
    device, on a 0-100 scale.
    """
    score = 0
    for signal_type, incoming_value in incoming_signals.items():
        if incoming_value in candidate_signals.get(signal_type, []):
            score += SIGNAL_WEIGHTS.get(signal_type, 0)
    return min(score, 100)


def calculate_identity_strength(signal_types: list[str]) -> int:
    """
    Aggregates a device's known signal types into a single
    identity_strength score (0-100). The strongest signal gets full
    weight; each additional corroborating signal contributes half its
    weight. Capped at 100.

    Examples:
        HARDWARE_UUID only             -> 70
        MAC + HOSTNAME                 -> 50 + (25 * 0.5) = 62
        HARDWARE_UUID + MAC + HOSTNAME -> 70 + 25 + 12     = 100 (capped)
    """
    if not signal_types:
        return 0

    unique_types = sorted(set(signal_types), key=lambda s: SIGNAL_WEIGHTS.get(s, 0), reverse=True)
    strength = SIGNAL_WEIGHTS.get(unique_types[0], 0)
    for signal_type in unique_types[1:]:
        strength += SIGNAL_WEIGHTS.get(signal_type, 0) * 0.5

    return min(round(strength), 100)


def build_fingerprint_hash(incoming_signals: dict[str, str]) -> str:
    """
    Builds the device's fingerprint_hash from its normalized identity
    signals, sorted by key for stability. Used as the UNIQUE constraint
    target when inserting a new device.
    """
    fingerprint_input = "|".join(
        f"{k}:{incoming_signals[k]}" for k in sorted(incoming_signals.keys())
    )
    return hashlib.sha256(fingerprint_input.encode()).hexdigest()


# ─────────────────────────────────────────────────────────────────────
# Orchestration — calls repositories/, never contains SQL itself
# ─────────────────────────────────────────────────────────────────────

def create_device(
    db, observation: dict, incoming_signals: dict[str, str], authorized: bool = False
) -> int:
    """
    Creates a new device from an observation's signals and stores the
    initial signal set. Returns the new (or, on conflict, existing)
    device_id.
    """
    signal_types = list(incoming_signals.keys())
    identity_strength = calculate_identity_strength(signal_types)
    fingerprint_hash = build_fingerprint_hash(incoming_signals)
    scan_tier = observation.get("scan_tier", "UNAUTHENTICATED")
    classification_source = get_classification_source(scan_tier)
    device_type = observation.get("device_type", "unknown")
    missing_threshold_hours = get_missing_threshold(device_type)

    device_id = device_repo.insert_device(
        db,
        organization_id=observation["organization_id"],
        site_id=observation["site_id"],
        fingerprint_hash=fingerprint_hash,
        primary_mac=incoming_signals.get("MAC"),
        vendor_name=observation.get("vendor_name"),
        device_type=device_type,
        classification_source=classification_source,
        identity_strength=identity_strength,
        is_authorized=authorized,
        missing_threshold_hours=missing_threshold_hours,
    )

    observation_id = observation.get("id")
    source = observation.get("protocol_used") or "MANUAL"
    for signal_type, signal_value in incoming_signals.items():
        confidence = SIGNAL_WEIGHTS.get(signal_type, 0)
        signal_repo.insert_signal(
            db, device_id, observation_id, signal_type, signal_value, confidence, source
        )

    return device_id


def update_signals(db, device_id: int, observation: dict, incoming_signals: dict[str, str]) -> int:
    """
    Reconciles incoming signals against what's already known for this
    device, then recomputes and persists identity_strength.

    - Known signal -> refresh last_seen
    - New signal   -> insert it (device has gained a new identifier)

    Returns the updated identity_strength.
    """
    observation_id = observation.get("id")
    source = observation.get("protocol_used") or "MANUAL"

    for signal_type, signal_value in incoming_signals.items():
        existing = signal_repo.get_existing_signal(db, device_id, signal_type, signal_value)
        if existing is not None:
            signal_repo.touch_signal(db, existing["id"])
        else:
            confidence = SIGNAL_WEIGHTS.get(signal_type, 0)
            signal_repo.insert_signal(
                db, device_id, observation_id, signal_type, signal_value, confidence, source
            )

    signal_types = signal_repo.get_signal_types(db, device_id)
    strength = calculate_identity_strength(signal_types)
    device_repo.update_identity(db, device_id, strength)
    return strength


def resolve_observation(db, observation: dict) -> dict:
    """
    Given an observation, finds the best matching device or creates a
    new one. This is the top-level orchestrator — every other function
    in this module exists to support this one.

    Returns:
        {
            "device_id":        int | None,
            "match_confidence": int,
            "match_method":     str,
            "action":           "linked" | "review" | "created" | "duplicate"
        }
    """
    if not observation.get("payload_hash"):
        observation["payload_hash"] = compute_payload_hash(observation)

    if observation_repo.is_duplicate(db, observation["payload_hash"]):
        existing = observation_repo.get_resolved_by_hash(db, observation["payload_hash"])
        return {
            "device_id":        existing["device_id"] if existing else None,
            "match_confidence": existing["match_confidence"] if existing else 0,
            "match_method":     existing["match_method"] if existing else "NONE",
            "action":           "duplicate",
        }

    incoming_signals = extract_signals(observation)
    candidates = signal_repo.find_candidates(db, incoming_signals)
    confidence_ceiling = get_confidence_ceiling(observation)
    incoming_has_anchor = is_hardware_anchored(list(incoming_signals.keys()))

    best_match: dict | None = None
    best_score = 0
    best_method: list[str] = []

    for candidate in candidates:
        candidate_signals = signal_repo.load_signals(db, candidate["device_id"])
        raw_score = score_candidate(incoming_signals, candidate_signals)
        score = min(raw_score, confidence_ceiling)

        matched_types = [
            s for s in incoming_signals
            if incoming_signals[s] in candidate_signals.get(s, [])
        ]
        if score > best_score:
            best_score = score
            best_match = candidate
            best_method = matched_types

    # If the incoming observation carries a hardware anchor not yet
    # stored on the candidate, add its weight — it is new evidence of
    # identity even though the candidate hasn't confirmed it before.
    if incoming_has_anchor and best_match is not None:
        anchor_bonus = max(
            SIGNAL_WEIGHTS[s] for s in incoming_signals if s in HARDWARE_ANCHORED_SIGNALS
        )
        best_score = min(best_score + anchor_bonus, 100)

    match_method = "+".join(best_method) if best_method else "NONE"

    # HIGH confidence + hardware anchor in the incoming observation -> auto-link
    if best_score >= CONFIDENCE_THRESHOLDS["HIGH"] and incoming_has_anchor:
        observation_repo.link(db, observation["id"], best_match["device_id"], best_score, match_method)
        update_signals(db, best_match["device_id"], observation, incoming_signals)
        return {
            "device_id":        best_match["device_id"],
            "match_confidence": best_score,
            "match_method":     match_method,
            "action":           "linked",
        }

    elif best_score >= CONFIDENCE_THRESHOLDS["MEDIUM"]:
        if best_match is not None:
            update_signals(db, best_match["device_id"], observation, incoming_signals)
            device_id = best_match["device_id"]
        else:
            device_id = create_device(db, observation, incoming_signals, authorized=False)
        observation_repo.link(db, observation["id"], device_id, best_score, match_method)
        return {
            "device_id":        device_id,
            "match_confidence": best_score,
            "match_method":     match_method,
            "action":           "review",
        }

    else:
        device_id = create_device(db, observation, incoming_signals, authorized=False)
        observation_repo.link(db, observation["id"], device_id, 0, "NONE")
        return {
            "device_id":        device_id,
            "match_confidence": 0,
            "match_method":     "NONE",
            "action":           "created",
        }
