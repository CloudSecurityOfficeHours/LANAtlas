"""
services/deduplication.py

Pure computation only — no database access. Builds the stable hash
used to detect duplicate observation submissions (see
repositories/observations.py for how that hash is enforced at the
schema level via a UNIQUE constraint).
"""

import hashlib
import json


def compute_payload_hash(observation: dict) -> str:
    """
    Computes a stable hash from an observation's identifying fields.
    Two observations with identical values for these fields produce
    the same hash — used for deduplication when an agent retries a
    submission after a network failure.

    Fields included: organization_id, site_id, agent_id, mac_address,
    ip_address, scan_tier, observed_at.
    """
    payload = {
        "organization_id": observation.get("organization_id"),
        "site_id":         observation.get("site_id"),
        "agent_id":        observation.get("agent_id"),
        "mac_address":     observation["mac_address"].upper() if observation.get("mac_address") else None,
        "ip_address":      observation.get("ip_address"),
        "scan_tier":       observation.get("scan_tier", "UNAUTHENTICATED"),
        "observed_at":     str(observation.get("observed_at")),
    }
    stable_string = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(stable_string.encode()).hexdigest()



