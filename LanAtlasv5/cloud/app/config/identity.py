"""
config/identity.py

Central tuning constants for the identity resolution engine.
Changing these values changes engine behavior without touching any
code in services/identity.py.

All scores in this module are integers on a 0-100 scale, matching the
SMALLINT columns devices.identity_strength, device_fingerprint_signals
.confidence, and observations.match_confidence in the PostgreSQL
schema. This replaced the original 0.0-1.0 REAL scale during the
PostgreSQL migration to eliminate float comparison drift.

See docs/schema-reference.md §4.8 for the rationale behind each weight.
"""

SIGNAL_WEIGHTS: dict[str, int] = {
    "HARDWARE_UUID": 70,   # motherboard UUID — survives reimaging, gold standard
    "SERIAL":        65,   # hardware serial — very stable, not always retrievable
    "MAC":           50,   # reliable short-term, can be spoofed or reassigned
    "NETBIOS":       30,   # stable on Windows, recyclable
    "HOSTNAME":      25,   # useful corroboration, not a primary identifier
    "SNMP_SYSDESCR": 20,   # good for network equipment
    "TTL_PROFILE":   15,   # OS class hint only
    "OPEN_PORTS":    10,   # changes frequently, weak alone
}

CONFIDENCE_THRESHOLDS: dict[str, int] = {
    "HIGH":   70,   # auto-link to existing device (requires hardware anchor too)
    "MEDIUM": 40,   # create device, flag for review
    # below 40 -> new device, no meaningful match
}

# Documents which signal types a given scan tier is capable of producing.
# Not enforced programmatically today — kept for reference and future
# validation (e.g. rejecting a WMI-tier observation with no hardware signals
# as a possible misconfiguration).
SCAN_TIERS: dict[str, list[str]] = {
    "UNAUTHENTICATED": ["MAC", "HOSTNAME", "OPEN_PORTS", "TTL_PROFILE"],
    "SNMP":            ["SNMP_SYSDESCR", "MAC", "HOSTNAME"],
    "WMI":             ["HARDWARE_UUID", "SERIAL", "MAC", "HOSTNAME"],
    "SSH":             ["HARDWARE_UUID", "SERIAL", "MAC", "HOSTNAME"],
}

# Caps the maximum confidence score achievable per scan tier.
# An UNAUTHENTICATED scan can never produce hardware-anchored signals,
# so auto-linking is never appropriate regardless of raw score.
TIER_CONFIDENCE_CEILING: dict[str, int] = {
    "UNAUTHENTICATED": 65,
    "SNMP":            80,
    "WMI":             100,
    "SSH":             100,
}

# Auto-linking requires at least one signal from this set in the INCOMING
# observation. Network-observable signals (MAC, HOSTNAME) can be recycled
# or spoofed; hardware-anchored signals survive reimaging and replacement.
HARDWARE_ANCHORED_SIGNALS: set[str] = {"HARDWARE_UUID", "SERIAL", "SNMP_SYSDESCR"}

# Maps scan tier to the classification_source written to devices.
TIER_CLASSIFICATION_SOURCE: dict[str, str] = {
    "UNAUTHENTICATED": "OUI",
    "SNMP":            "SNMP",
    "WMI":             "WMI",
    "SSH":             "WMI",   # SSH gives the same hardware-level data as WMI
}
ENDOFFILE
