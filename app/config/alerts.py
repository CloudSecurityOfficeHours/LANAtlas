"""
config/alerts.py

Default missing-device thresholds by device type, in hours.
Used by services/thresholds.py when a new device is first created —
each device gets its own missing_threshold_hours column seeded from
this map, which can then be overridden per-device by an operator.
"""

MISSING_THRESHOLD_BY_TYPE: dict[str, int] = {
    "router":        2,    # infrastructure — must always be present
    "switch":        2,
    "access_point":  2,
    "server":        2,
    "iot":           8,    # usually always on but may have sleep cycles
    "workstation":   16,   # expected during business hours only
    "printer":       16,
    "mobile":        72,   # comes and goes with its owner
    "unknown":       24,   # conservative default until classified
}
