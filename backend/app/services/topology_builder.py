"""Live Network Topology & Network Exposure Digital Twin Builder (PRD Module 3 & Innovation 1)."""
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from app.models.entities import Asset, Port, TopologySnapshot


def build_live_topology_graph(
    db: Session,
    subnet_filter: Optional[str] = None,
    min_risk_score: float = 0.0,
) -> Dict[str, Any]:
    """
    Constructs the hierarchical graph: Network -> Subnet -> Host -> Service -> Port.
    Strictly distinguishes INFERRED_SUBNET_GROUPING from VERIFIED_GATEWAY_LINK (PRD Section 3.4 & Module 3).
    """
    query = db.query(Asset)
    if subnet_filter:
        query = query.filter(Asset.subnet == subnet_filter)
    assets: List[Asset] = query.all()

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    # Root Enterprise Network Core Node
    root_id = "network:enterprise-core"
    nodes.append(
        {
            "id": root_id,
            "type": "NETWORK_CORE",
            "label": "NETSENTINEL Authorized Enterprise Network",
            "status": "ACTIVE",
            "risk_score": max((a.risk_score for a in assets), default=0.0),
            "metadata": {
                "total_assets": len(assets),
                "relationship_note": "Logical root of authorized CIDR enclaves",
            },
        }
    )

    subnets_seen = set()
    open_ports_count = 0
    high_risk_hosts = 0

    for asset in assets:
        if asset.risk_score < min_risk_score:
            continue

        if asset.risk_score >= 60.0:
            high_risk_hosts += 1

        subnet_id = f"subnet:{asset.subnet}"
        if asset.subnet not in subnets_seen:
            subnets_seen.add(asset.subnet)
            nodes.append(
                {
                    "id": subnet_id,
                    "type": "SUBNET",
                    "label": f"Subnet {asset.subnet}",
                    "subnet": asset.subnet,
                    "status": "ACTIVE",
                    "risk_score": 0.0,
                    "metadata": {
                        "grouping_type": "INFERRED_SUBNET_GROUPING",
                        "description": "Logical IPv4 /24 subnet grouping (Physical switch topology requires LLDP/SNMP verification).",
                    },
                }
            )
            edges.append(
                {
                    "id": f"edge:{root_id}->{subnet_id}",
                    "source": root_id,
                    "target": subnet_id,
                    "relationship_type": "AUTHORIZED_ENCLAVE",
                    "verified_physical": False,
                }
            )

        host_id = f"host:{asset.ip_address}"
        # PRD Module 3: "The gateway label must only be assigned when supported by route or infrastructure evidence."
        role_badge = "Verified Gateway" if asset.is_gateway_verified else asset.business_service or "Host"

        nodes.append(
            {
                "id": host_id,
                "asset_id": asset.asset_id,
                "type": "HOST",
                "label": f"{asset.hostname or asset.ip_address} ({asset.ip_address})",
                "ip_address": asset.ip_address,
                "hostname": asset.hostname,
                "subnet": asset.subnet,
                "operating_system": asset.operating_system,
                "status": asset.asset_status,
                "criticality": asset.criticality,
                "business_service": asset.business_service,
                "owner_team": asset.owner_team,
                "is_gateway_verified": asset.is_gateway_verified,
                "gateway_evidence": asset.gateway_evidence,
                "role_badge": role_badge,
                "risk_score": asset.risk_score,
                "risk_classification": asset.risk_classification,
                "volatility_score": asset.volatility_score,
                "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
            }
        )

        edges.append(
            {
                "id": f"edge:{subnet_id}->{host_id}",
                "source": subnet_id,
                "target": host_id,
                "relationship_type": "VERIFIED_GATEWAY_ROUTE" if asset.is_gateway_verified else "INFERRED_SUBNET_MEMBERSHIP",
                "verified_physical": bool(asset.is_gateway_verified),
            }
        )

        for port in asset.ports:
            if port.state not in ("open", "open|filtered"):
                continue
            open_ports_count += 1
            port_node_id = f"port:{asset.ip_address}:{port.port_number}/{port.protocol}"
            nodes.append(
                {
                    "id": port_node_id,
                    "port_id": port.port_id,
                    "asset_id": asset.asset_id,
                    "type": "SERVICE_PORT",
                    "label": f"{port.port_number}/{port.protocol} — {port.detected_service.upper()}",
                    "port_number": port.port_number,
                    "protocol": port.protocol,
                    "state": port.state,
                    "detected_service": port.detected_service,
                    "conventional_service": port.conventional_service,
                    "service_mismatch": port.service_mismatch,
                    "product": port.product,
                    "version": port.version,
                    "typical_purpose": port.typical_purpose,
                    "exposure_class": port.exposure_class,
                    "risk_score": port.risk_score,
                    "risk_classification": port.risk_classification,
                }
            )
            edges.append(
                {
                    "id": f"edge:{host_id}->{port_node_id}",
                    "source": host_id,
                    "target": port_node_id,
                    "relationship_type": "OBSERVED_OPEN_PORT",
                    "verified_physical": True,
                }
            )

    # Update subnet risk scores based on max host risk inside each subnet
    for node in nodes:
        if node["type"] == "SUBNET":
            sub = node["subnet"]
            sub_scores = [n["risk_score"] for n in nodes if n.get("type") == "HOST" and n.get("subnet") == sub]
            node["risk_score"] = max(sub_scores, default=0.0)

    stats = {
        "total_subnets": len(subnets_seen),
        "total_hosts": sum(1 for n in nodes if n["type"] == "HOST"),
        "active_hosts": sum(1 for n in nodes if n["type"] == "HOST" and n.get("status") == "ACTIVE"),
        "missing_or_unreachable_hosts": sum(1 for n in nodes if n["type"] == "HOST" and n.get("status") != "ACTIVE"),
        "open_service_ports": open_ports_count,
        "high_risk_hosts": high_risk_hosts,
    }

    return {
        "hierarchy": "Network -> Subnet -> Host -> Service/Port",
        "nodes": nodes,
        "edges": edges,
        "stats": stats,
    }


def record_topology_snapshot(
    db: Session,
    scan_id: str,
    label: str,
) -> TopologySnapshot:
    """Innovation 1: Saves a point-in-time Digital Twin snapshot of the entire network topology."""
    graph = build_live_topology_graph(db)
    snapshot = TopologySnapshot(
        scan_id=scan_id,
        label=label,
        nodes_json=graph["nodes"],
        edges_json=graph["edges"],
        stats_json=graph["stats"],
    )
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)
    return snapshot


def compare_topology_snapshots(
    db: Session,
    baseline_snapshot_id: str,
    target_snapshot_id: str,
) -> Dict[str, Any]:
    """
    Compares two historical TopologySnapshot records for the Network Exposure Digital Twin view.
    """
    snap_a = db.query(TopologySnapshot).filter(TopologySnapshot.snapshot_id == baseline_snapshot_id).first()
    snap_b = db.query(TopologySnapshot).filter(TopologySnapshot.snapshot_id == target_snapshot_id).first()
    if not snap_a or not snap_b:
        raise ValueError("One or both topology snapshots were not found.")

    hosts_a = {n["ip_address"]: n for n in snap_a.nodes_json if n.get("type") == "HOST"}
    hosts_b = {n["ip_address"]: n for n in snap_b.nodes_json if n.get("type") == "HOST"}

    ports_a = {n["id"]: n for n in snap_a.nodes_json if n.get("type") == "SERVICE_PORT"}
    ports_b = {n["id"]: n for n in snap_b.nodes_json if n.get("type") == "SERVICE_PORT"}

    added_hosts = [hosts_b[ip] for ip in hosts_b.keys() - hosts_a.keys()]
    removed_hosts = [hosts_a[ip] for ip in hosts_a.keys() - hosts_b.keys()]
    added_ports = [ports_b[pid] for pid in ports_b.keys() - ports_a.keys()]
    removed_ports = [ports_a[pid] for pid in ports_a.keys() - ports_b.keys()]

    risk_deltas = []
    for ip in hosts_a.keys() & hosts_b.keys():
        delta = round(hosts_b[ip].get("risk_score", 0.0) - hosts_a[ip].get("risk_score", 0.0), 1)
        if delta != 0 or hosts_a[ip].get("status") != hosts_b[ip].get("status"):
            risk_deltas.append(
                {
                    "ip_address": ip,
                    "hostname": hosts_b[ip].get("hostname"),
                    "previous_status": hosts_a[ip].get("status"),
                    "current_status": hosts_b[ip].get("status"),
                    "previous_risk": hosts_a[ip].get("risk_score", 0.0),
                    "current_risk": hosts_b[ip].get("risk_score", 0.0),
                    "risk_delta": delta,
                }
            )

    return {
        "baseline_snapshot": {
            "snapshot_id": snap_a.snapshot_id,
            "label": snap_a.label,
            "captured_at": snap_a.captured_at.isoformat(),
            "stats": snap_a.stats_json,
        },
        "target_snapshot": {
            "snapshot_id": snap_b.snapshot_id,
            "label": snap_b.label,
            "captured_at": snap_b.captured_at.isoformat(),
            "stats": snap_b.stats_json,
        },
        "added_hosts": added_hosts,
        "removed_hosts": removed_hosts,
        "added_service_ports": added_ports,
        "removed_service_ports": removed_ports,
        "host_risk_and_status_deltas": risk_deltas,
    }

