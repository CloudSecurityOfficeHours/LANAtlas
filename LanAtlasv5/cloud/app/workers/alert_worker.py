# cloud/app/workers/alert_worker.py
from sqlalchemy.engine import Connection

from repositories import alerts as alert_repo
from repositories import devices as device_repo


def check_missing_devices(db: Connection) -> int:
    """Open a missing_device alert for each overdue device that lacks one.

    Returns the number of alerts created. The caller owns the transaction.
    Duplicate prevention is atomic in alerts.create() (partial unique index +
    ON CONFLICT DO NOTHING), so overlapping runs cannot double-alert.
    """
    created = 0
    for device in device_repo.find_overdue(db, business_hours_only=True):
        alert_id = alert_repo.create(
            db,
            organization_id=device["organization_id"],
            site_id=device["site_id"],
            device_id=device["id"],
            alert_type_name="missing_device",
            alert_message=(
                f"Device {device['id']} has not been seen since {device['last_seen']}"
            ),
            severity="high",
        )
        if alert_id is not None:
            created += 1
    return created
 
