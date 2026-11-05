"""Autonomous Exposure Investigator (PRD Section 15 — Innovation 2)."""
from sqlalchemy.orm import Session
from app.models.entities import Asset, Finding, InvestigationRecord, Port


def create_autonomous_investigation(
    db: Session,
    finding: Finding,
    asset: Asset,
    port: Port,
    was_previously_present: bool,
) -> InvestigationRecord:
    """
    Automatically generates an non-intrusive 7-step investigation record when a new
    or high-risk port exposure is identified.
    Strictly obeys PRD constraint: "It must not attempt exploitation or automatically disable services."
    """
    existing = (
        db.query(InvestigationRecord)
        .filter(InvestigationRecord.finding_id == finding.finding_id)
        .first()
    )
    if existing:
        return existing

    steps = [
        {
            "step": 1,
            "action": "Confirm Observation & Protocol State",
            "status": "COMPLETED",
            "detail": (
                f"Confirmed port {port.port_number}/{port.protocol} is in state '{port.state}' "
                f"on host {asset.ip_address} ({asset.hostname or 'unlabeled'})."
            ),
        },
        {
            "step": 2,
            "action": "Identify Detected Service vs. Conventional Assignment",
            "status": "COMPLETED",
            "detail": (
                f"Nmap service probe identified '{port.detected_service}' "
                f"({port.product or 'product unspecified'} {port.version or ''}). "
                f"Conventional port expectation: '{port.conventional_service}'. "
                f"Service Mismatch: {'YES' if port.service_mismatch else 'NO'}."
            ),
        },
        {
            "step": 3,
            "action": "Verify Historical Baseline Presence",
            "status": "COMPLETED",
            "detail": (
                "Service was NOT present in the previous baseline scan (Newly Exposed Endpoint)."
                if not was_previously_present
                else "Service was present in baseline but triggered high-priority exposure threshold."
            ),
        },
        {
            "step": 4,
            "action": "Correlate Asset Criticality & Business Service Context",
            "status": "COMPLETED",
            "detail": (
                f"Asset criticality is '{asset.criticality}'. Mapped Business Service: "
                f"'{asset.business_service or 'Unassigned'}' owned by '{asset.owner_team or 'IT Operations'}' "
                f"in subnet {asset.subnet}."
            ),
        },
        {
            "step": 5,
            "action": "Compute Statistical Risk Breakdown",
            "status": "COMPLETED",
            "detail": (
                f"Calculated Risk Score: {finding.risk_score}/100 ({finding.severity}). "
                f"Factors: {finding.score_breakdown_json}"
            ),
        },
        {
            "step": 6,
            "action": "Synthesize Non-Intrusive Defensive Review Plan",
            "status": "COMPLETED",
            "detail": finding.recommendation,
        },
        {
            "step": 7,
            "action": "Queue Responsible Administrator Notification",
            "status": "COMPLETED",
            "detail": f"Notification routed to owner team '{asset.owner_team or 'SecOps'}' (Zero active exploitation or automated service disruption performed).",
        },
    ]

    checklist = [
        f"Verify change ticket or maintenance window for {asset.ip_address}:{port.port_number}/{port.protocol}.",
        f"Confirm with '{asset.owner_team}' whether '{port.detected_service}' is required for '{asset.business_service}'.",
        f"Inspect host firewall (iptables/nftables/ufw/Windows Firewall) and VLAN ACLs on subnet {asset.subnet}.",
        port.recommended_action,
    ]

    record = InvestigationRecord(
        finding_id=finding.finding_id,
        asset_id=asset.asset_id,
        trigger_reason=(
            f"Autonomous trigger: {finding.category} on {asset.ip_address}:{port.port_number}/{port.protocol} "
            f"(Risk Score {finding.risk_score}/100)"
        ),
        steps_completed_json=steps,
        historical_context=(
            f"Endpoint {asset.ip_address}:{port.port_number}/{port.protocol} appeared as a new exposure "
            f"with service '{port.detected_service}'."
            if not was_previously_present
            else f"Endpoint {asset.ip_address}:{port.port_number}/{port.protocol} evaluated under continuous exposure monitoring."
        ),
        business_impact_summary=(
            f"Exposes '{ asset.business_service }' ({asset.criticality} criticality) to potential unauthorized "
            f"network interaction via {port.exposure_class}."
        ),
        defensive_review_checklist=checklist,
        notified_owner=asset.owner_team or "SecOps",
    )
    db.add(record)
    db.flush()
    return record

