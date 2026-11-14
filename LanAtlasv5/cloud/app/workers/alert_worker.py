# cloud/app/workers/alert_worker.py
def check_missing_devices():
    devices = device_repo.find_overdue(business_hours_only=True)
    for device in devices:
        if not alert_repo.has_open_alert(device.id, "missing_device"):
            alert_repo.create(
                device_id=device.id,
                alert_type="missing_device",
                severity="high",
            )