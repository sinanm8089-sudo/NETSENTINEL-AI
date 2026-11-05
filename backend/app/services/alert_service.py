"""Deduplicated Alerts and Notifications Engine (PRD Module 8)."""
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session
from app.core.websocket_hub import ws_hub
from app.models.entities import Alert


def trigger_deduplicated_alert(
    db: Session,
    category: str,
    severity: str,
    title: str,
    message: str,
    asset_ip: Optional[str],
    dedup_key: str,
) -> Alert:
    """
    Creates or deduplicates an alert based on `dedup_key` to prevent SOC alert fatigue.
    """
    existing = db.query(Alert).filter(Alert.dedup_fingerprint == dedup_key).first()
    if existing:
        existing.occurrence_count += 1
        existing.last_triggered_at = datetime.now(timezone.utc)
        existing.severity = severity
        existing.message = message
        existing.acknowledged = False
        db.flush()
        return existing

    alert = Alert(
        category=category,
        severity=severity,
        title=title,
        message=message,
        asset_ip=asset_ip,
        dedup_fingerprint=dedup_key,
        occurrence_count=1,
        channels_notified=["DASHBOARD_STREAM", "AUDIT_LOG"],
        acknowledged=False,
    )
    db.add(alert)
    db.flush()

    ws_hub.publish_event_sync(
        "alert.triggered",
        {
            "alert_id": alert.alert_id,
            "category": alert.category,
            "severity": alert.severity,
            "title": alert.title,
            "asset_ip": alert.asset_ip,
        },
    )
    return alert

