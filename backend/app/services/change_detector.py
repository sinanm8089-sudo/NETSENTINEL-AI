"""Autonomous Change Detection & Volatility Risk Predictor (PRD Module 4 & Innovation 5)."""
from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Tuple
from sqlalchemy.orm import Session
from app.models.entities import Asset, NetworkChange, Port
from app.services.nmap_parser import ParsedHostObservation
from app.services.risk_engine import classify_risk_score


def detect_and_record_network_changes(
    db: Session,
    scan_id: str,
    scan_profile: str,
    previous_assets: Dict[str, Asset],
    previous_ports_by_ip: Dict[str, Dict[Tuple[int, str], Dict[str, Any]]],
    observed_hosts: List[ParsedHostObservation],
) -> Tuple[List[NetworkChange], Dict[str, Set[Tuple[int, str]]], Dict[str, Set[Tuple[int, str]]]]:
    """
    Compares current scan observations against previous inventory snapshot.
    Strictly distinguishes between 'closed', 'filtered', 'unreachable', and 'not_observed' (PRD Module 4).
    Returns:
      - created_changes: List[NetworkChange]
      - newly_opened_ports_by_ip: {ip: {(port, proto)}}
      - version_changed_ports_by_ip: {ip: {(port, proto)}}
    """
    created_changes: List[NetworkChange] = []
    newly_opened_by_ip: Dict[str, Set[Tuple[int, str]]] = {}
    version_changed_by_ip: Dict[str, Set[Tuple[int, str]]] = {}

    observed_ips: Set[str] = {h.ip_address for h in observed_hosts if h.status == "ACTIVE"}
    unreachable_ips: Set[str] = {h.ip_address for h in observed_hosts if h.status != "ACTIVE"}

    for host_obs in observed_hosts:
        ip = host_obs.ip_address
        newly_opened_by_ip[ip] = set()
        version_changed_by_ip[ip] = set()

        prev_asset = previous_assets.get(ip)

        # 1. New device discovered
        if prev_asset is None and host_obs.status == "ACTIVE":
            # Asset record will be linked after flush or we create it first
            continue

        if prev_asset is not None:
            # Check if device was previously ACTIVE and is now UNREACHABLE in host observation
            if host_obs.status != "ACTIVE" and prev_asset.asset_status == "ACTIVE":
                chg = NetworkChange(
                    scan_id=scan_id,
                    asset_id=prev_asset.asset_id,
                    change_type="MISSING_DEVICE",
                    severity="High" if prev_asset.criticality in ("HIGH", "CRITICAL") else "Medium",
                    summary=f"Asset {ip} ({prev_asset.hostname or 'unknown'}) did not respond during scan (marked UNREACHABLE; ports are not assumed closed).",
                    previous_value={"asset_status": prev_asset.asset_status},
                    current_value={"asset_status": "UNREACHABLE"},
                    significance_score=78.0 if prev_asset.criticality in ("HIGH", "CRITICAL") else 55.0,
                )
                db.add(chg)
                created_changes.append(chg)
                continue

            # Check OS fingerprint change
            if (
                host_obs.operating_system
                and host_obs.operating_system != "Unknown OS"
                and prev_asset.operating_system
                and prev_asset.operating_system != "Unknown OS"
                and host_obs.operating_system != prev_asset.operating_system
            ):
                chg = NetworkChange(
                    scan_id=scan_id,
                    asset_id=prev_asset.asset_id,
                    change_type="OS_FINGERPRINT_CHANGED",
                    severity="Medium",
                    summary=f"OS fingerprint on {ip} changed from '{prev_asset.operating_system}' to '{host_obs.operating_system}'.",
                    previous_value={"operating_system": prev_asset.operating_system},
                    current_value={"operating_system": host_obs.operating_system},
                    significance_score=60.0,
                )
                db.add(chg)
                created_changes.append(chg)

            # Compare port & protocol combinations
            prev_port_map = previous_ports_by_ip.get(ip, {})
            current_port_map = {(p.port_number, p.protocol.upper()): p for p in host_obs.ports}

            for (p_num, proto), p_obs in current_port_map.items():
                prev_p = prev_port_map.get((p_num, proto))
                if prev_p is None:
                    if p_obs.state in ("open", "open|filtered"):
                        newly_opened_by_ip[ip].add((p_num, proto))
                        is_sensitive = p_num in (22, 23, 445, 1433, 2375, 3306, 3389, 5432, 6379, 9200, 27017)
                        chg = NetworkChange(
                            scan_id=scan_id,
                            asset_id=prev_asset.asset_id,
                            change_type="NEW_OPEN_PORT",
                            severity="Critical" if is_sensitive else "High",
                            summary=(
                                f"Newly exposed port {p_num}/{proto} ({p_obs.service_name}) detected in state '{p_obs.state}' "
                                f"on {ip} ({prev_asset.business_service})."
                            ),
                            previous_value={"state": "not_observed"},
                            current_value={
                                "port": p_num,
                                "protocol": proto,
                                "state": p_obs.state,
                                "service": p_obs.service_name,
                                "product": p_obs.product,
                                "version": p_obs.version,
                            },
                            significance_score=90.0 if is_sensitive else 72.0,
                        )
                        db.add(chg)
                        created_changes.append(chg)
                else:
                    # Port existed previously; compare state and version
                    old_state = prev_p.get("state", "open")
                    if old_state != p_obs.state:
                        if p_obs.state in ("open", "open|filtered") and old_state not in ("open", "open|filtered"):
                            newly_opened_by_ip[ip].add((p_num, proto))
                        chg = NetworkChange(
                            scan_id=scan_id,
                            asset_id=prev_asset.asset_id,
                            change_type="PORT_STATE_CHANGED",
                            severity="High" if p_obs.state == "open" else "Low",
                            summary=(
                                f"Port {p_num}/{proto} on {ip} transitioned from '{old_state}' to '{p_obs.state}' "
                                f"(reason: {p_obs.reason})."
                            ),
                            previous_value={"port": p_num, "protocol": proto, "state": old_state},
                            current_value={"port": p_num, "protocol": proto, "state": p_obs.state, "reason": p_obs.reason},
                            significance_score=70.0 if p_obs.state == "open" else 35.0,
                        )
                        db.add(chg)
                        created_changes.append(chg)

                    old_ver = f"{prev_p.get('product') or ''} {prev_p.get('version') or ''}".strip()
                    new_ver = f"{p_obs.product or ''} {p_obs.version or ''}".strip()
                    if old_ver and new_ver and old_ver != new_ver:
                        version_changed_by_ip[ip].add((p_num, proto))
                        chg = NetworkChange(
                            scan_id=scan_id,
                            asset_id=prev_asset.asset_id,
                            change_type="SERVICE_VERSION_CHANGED",
                            severity="Medium",
                            summary=f"Service version on {ip}:{p_num}/{proto} changed from '{old_ver}' to '{new_ver}'.",
                            previous_value={"port": p_num, "protocol": proto, "version": old_ver},
                            current_value={"port": p_num, "protocol": proto, "version": new_ver},
                            significance_score=65.0,
                        )
                        db.add(chg)
                        created_changes.append(chg)

            # Check ports previously open that were NOT in current scan output
            # PRD Module 4: "A missing result must not automatically be described as a confirmed closed port."
            if scan_profile != "DISCOVERY_ONLY":
                for (p_num, proto), prev_p in prev_port_map.items():
                    if (p_num, proto) not in current_port_map and prev_p.get("state") in ("open", "open|filtered"):
                        chg = NetworkChange(
                            scan_id=scan_id,
                            asset_id=prev_asset.asset_id,
                            change_type="PORT_NO_LONGER_OBSERVED",
                            severity="Informational",
                            summary=(
                                f"Port {p_num}/{proto} ({prev_p.get('detected_service')}) on {ip} was not observed in "
                                f"profile '{scan_profile}' (marked 'not_observed', not confirmed closed unless RST received)."
                            ),
                            previous_value={"port": p_num, "protocol": proto, "state": prev_p.get("state")},
                            current_value={"port": p_num, "protocol": proto, "state": "not_observed"},
                            significance_score=30.0,
                        )
                        db.add(chg)
                        created_changes.append(chg)

    # Check previously ACTIVE assets in target scope that did not appear in scan output at all
    for ip, prev_asset in previous_assets.items():
        if ip not in observed_ips and ip not in unreachable_ips and prev_asset.asset_status == "ACTIVE":
            prev_asset.asset_status = "MISSING"
            chg = NetworkChange(
                scan_id=scan_id,
                asset_id=prev_asset.asset_id,
                change_type="MISSING_DEVICE",
                severity="High" if prev_asset.criticality in ("HIGH", "CRITICAL") else "Medium",
                summary=(
                    f"Previously active asset {ip} ({prev_asset.hostname or 'unlabeled'}) was not observed in scan "
                    f"(marked MISSING; may be powered down, filtered, or disconnected)."
                ),
                previous_value={"asset_status": "ACTIVE"},
                current_value={"asset_status": "MISSING"},
                significance_score=80.0 if prev_asset.criticality in ("HIGH", "CRITICAL") else 50.0,
            )
            db.add(chg)
            created_changes.append(chg)

    return created_changes, newly_opened_by_ip, version_changed_by_ip


def compute_asset_volatility_predictions(db: Session) -> List[Dict[str, Any]]:
    """
    Innovation 5: Network Change Risk Prediction using statistical trend analysis.
    Evaluates historical change frequency, administrative/DB port churn, and asset criticality.
    """
    assets = db.query(Asset).all()
    predictions: List[Dict[str, Any]] = []

    for asset in assets:
        changes = db.query(NetworkChange).filter(NetworkChange.asset_id == asset.asset_id).all()
        change_count = len(changes)
        high_sig_changes = sum(1 for c in changes if c.significance_score >= 70.0)
        new_port_events = sum(1 for c in changes if c.change_type == "NEW_OPEN_PORT")
        version_events = sum(1 for c in changes if c.change_type == "SERVICE_VERSION_CHANGED")

        volatility = min(
            100.0,
            round(
                (change_count * 12.0)
                + (high_sig_changes * 18.0)
                + (new_port_events * 15.0)
                + (version_events * 8.0),
                1,
            ),
        )
        asset.volatility_score = volatility

        if volatility >= 60:
            trend_label = "HIGH_DRIFT_PROBABILITY"
            recommended_cadence = "15m Priority Polling"
        elif volatility >= 25:
            trend_label = "MODERATE_VARIANCE"
            recommended_cadence = "60m Standard Polling"
        else:
            trend_label = "STABLE_BASELINE"
            recommended_cadence = "240m Baseline Verification"

        predictions.append(
            {
                "asset_id": asset.asset_id,
                "ip_address": asset.ip_address,
                "hostname": asset.hostname,
                "business_service": asset.business_service,
                "volatility_score": volatility,
                "classification": classify_risk_score(volatility),
                "trend_label": trend_label,
                "total_historical_changes": change_count,
                "new_port_exposures": new_port_events,
                "version_drift_events": version_events,
                "recommended_scan_cadence": recommended_cadence,
                "statistical_rationale": (
                    f"Observed {change_count} change events ({new_port_events} newly opened port events, "
                    f"{version_events} version drift events) across scan history."
                ),
            }
        )

    db.commit()
    predictions.sort(key=lambda x: x["volatility_score"], reverse=True)
    return predictions

