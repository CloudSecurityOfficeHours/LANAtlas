"""
services/thresholds.py

Determines the default missing-device alert threshold for a newly
created device, based on its device_type. Pure computation — no
database access.
"""

from config.alerts import MISSING_THRESHOLD_BY_TYPE


def get_missing_threshold(device_type: str) -> int:
    """Returns the default missing_threshold_hours for a device_type."""
    return MISSING_THRESHOLD_BY_TYPE.get(device_type, 24)
