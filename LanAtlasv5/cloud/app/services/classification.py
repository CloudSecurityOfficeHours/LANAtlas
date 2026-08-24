"""
services/classification.py

Determines how a device's device_type was decided
(classification_source) based on the quality of scan that produced it.
Pure computation — no database access.
"""

from config.identity import TIER_CLASSIFICATION_SOURCE


def get_classification_source(scan_tier: str) -> str:
    """
    Maps a scan tier to the classification_source written to devices.
    Falls back to 'OUI' — the weakest evidence tier — for any unknown
    scan_tier value rather than raising, since this runs on data that
    already passed schema-level CHECK validation.
    """
    return TIER_CLASSIFICATION_SOURCE.get(scan_tier, "OUI")