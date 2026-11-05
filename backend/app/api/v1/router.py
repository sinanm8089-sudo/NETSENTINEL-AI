"""Comprehensive FastAPI v1 Router for NETSENTINEL AI (PRD Section 10 & Modules 1–9)."""
from collections import Counter
import ipaddress
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy.orm import Session
from app.config import settings
from app.core.auth import (
    CurrentActor,
    ROLE_PERMISSIONS,
    get_current_actor,
    record_audit_event,
    require_permission,
)
from app.core.cidr_validator import get_active_cidr_list
from app.database import get_db
from app.models.entities import (
    Alert,
    Asset,
    AuditEvent,
    AuthorizedCIDR,
    Finding,
    InvestigationRecord,
    NetworkChange,
    Port,
    ScanJob,
    ScanSchedule,
    TopologySnapshot,
    User,
)
from app.schemas.api_schemas import (
    AIInvestigateRequest,
    AssetBusinessContextUpdate,
    AssetResponse,
    AuthorizedCIDRCreate,
    AuthorizedCIDRResponse,
    FindingResponse,
    InvestigationRecordResponse,
    NetworkChangeResponse,
    PortResponse,
    ScanCreateRequest,
    ScanJobResponse,
    TerminalCommandRequest,
    TerminalCommandResponse,
)
from app.services.ai_adapter import (
    answer_natural_language_investigation,
    generate_finding_explanation,
)
from app.services.change_detector import compute_asset_volatility_predictions
from app.services.report_service import (
    generate_csv_asset_export,
    generate_json_executive_audit_bundle,
    generate_printable_html_security_report,
)
from app.services.risk_engine import classify_risk_score, compute_port_risk_score
from app.services. port_intelligence import enrich_port_observation
from app.services.scan_optimizer import optimize_scan_schedules
from app.services.scanner_engine import execute_authorized_scan
from app.services.terminal_dispatcher import dispatch_terminal_command
from app.services.topology_builder import (
    build_live_topology_graph,
    compare_topology_snapshots,
)

api_router = APIRouter()


@api_router.get("/health")
def get_health(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Platform health check & independent engine status (PRD Section 10)."""
    asset_count = db.query(Asset).count()
    return {
        "status": "healthy",
        "product": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "creator": settings.CREATOR,
        "engines": {
            "discovery_engine": "ONLINE (Hybrid Real Nmap + Safe Lab Simulator)",
            "statistical_risk_engine": "ONLINE (100% Independent / Zero GPU Required)",
            "change_detection_engine": "ONLINE (State-Aware Diff + Volatility Predictor)",
            "hybrid_ai_layer": f"ONLINE (Mode: {settings.AI_PROVIDER_PREFERENCE} with Offline Fallback)",
        },
        "dashboard_refresh_seconds": settings.DASHBOARD_REFRESH_SECONDS,
        "inventoried_assets": asset_count,
    }


@api_router.get("/roles")
def list_roles_and_users(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Returns configured RBAC roles and demo accounts for testing role permissions."""
    users = db.query(User).all()
    return {
        "roles": ROLE_PERMISSIONS,
        "users": [
            {
                "user_id": u.user_id,
                "username": u.username,
                "full_name": u.full_name,
                "email": u.email,
                "role": u.role,
            }
            for u in users
        ],
    }


@api_router.get("/dashboard")
def get_soc_dashboard_overview(
    subnet: Optional[str] = Query(default=None),
    protocol: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Module 7: Live SOC Dashboard metrics, charts, and filtered operational telemetry."""
    asset_q = db.query(Asset)
    if subnet:
        asset_q = asset_q.filter(Asset.subnet == subnet)
    assets = asset_q.order_by(Asset.risk_score.desc()).all()
    asset_ids = {a.asset_id for a in assets}

    ports_q = db.query(Port).filter(Port.asset_id.in_(asset_ids)) if asset_ids else db.query(Port).filter(False)
    if protocol:
        ports_q = ports_q.filter(Port.protocol == protocol.upper())
    all_ports = ports_q.all()

    open_tcp = sum(1 for p in all_ports if p.protocol == "TCP" and p.state in ("open", "open|filtered"))
    open_udp = sum(1 for p in all_ports if p.protocol == "UDP" and p.state in ("open", "open|filtered"))
    mismatched_ports = sum(1 for p in all_ports if p.service_mismatch and p.state in ("open", "open|filtered"))

    findings_q = db.query(Finding).filter(Finding.asset_id.in_(asset_ids)) if asset_ids else db.query(Finding).filter(False)
    if severity:
        findings_q = findings_q.filter(Finding.severity.ilike(severity))
    findings = findings_q.order_by(Finding.risk_score.desc()).all()

    high_priority_findings = [f for f in findings if f.severity in ("Critical", "High") and f.status == "OPEN"]

    # Risk distribution bands
    bands = ["Critical", "High", "Medium", "Low", "Informational"]
    risk_distribution = [
        {
            "band": b,
            "assets": sum(1 for a in assets if a.risk_classification == b),
            "findings": sum(1 for f in findings if f.severity == b),
        }
        for b in bands
    ]

    # Top exposed services
    service_counter = Counter(
        p.detected_service for p in all_ports if p.state in ("open", "open|filtered")
    )
    top_services = [
        {"service": svc, "count": cnt}
        for svc, cnt in service_counter.most_common(8)
    ]

    recent_changes = (
        db.query(NetworkChange)
        .order_by(NetworkChange.observed_at.desc())
        .limit(12)
        .all()
    )
    recent_scans = (
        db.query(ScanJob)
        .order_by(ScanJob.start_time.desc())
        .limit(8)
        .all()
    )
    active_alerts = (
        db.query(Alert)
        .filter(Alert.acknowledged.is_(False))
        .order_by(Alert.last_triggered_at.desc())
        .limit(10)
        .all()
    )

    all_subnets = [r[0] for r in db.query(Asset.subnet).distinct().all()]

    return {
        "kpis": {
            "total_discovered_assets": len(assets),
            "active_hosts": sum(1 for a in assets if a.asset_status == "ACTIVE"),
            "missing_or_unreachable_hosts": sum(1 for a in assets if a.asset_status != "ACTIVE"),
            "open_tcp_ports": open_tcp,
            "open_udp_ports": open_udp,
            "service_mismatches": mismatched_ports,
            "high_priority_findings": len(high_priority_findings),
            "total_open_findings": sum(1 for f in findings if f.status == "OPEN"),
            "recent_changes_count": db.query(NetworkChange).count(),
            "unacknowledged_alerts": len(active_alerts),
            "latest_scan_status": recent_scans[0].status if recent_scans else "IDLE",
        },
        "risk_distribution": risk_distribution,
        "top_exposed_services": top_services,
        "available_subnets": all_subnets,
        "high_priority_findings": [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "risk_score": f.risk_score,
                "asset_ip": f.evidence_json.get("ip_address") if f.evidence_json else None,
                "port": f.evidence_json.get("port") if f.evidence_json else None,
                "protocol": f.evidence_json.get("protocol") if f.evidence_json else None,
                "recommendation": f.recommendation,
                "has_investigation": f.investigation is not None,
            }
            for f in findings[:8]
        ],
        "recent_changes": [
            {
                "change_id": c.change_id,
                "change_type": c.change_type,
                "severity": c.severity,
                "summary": c.summary,
                "significance_score": c.significance_score,
                "observed_at": c.observed_at.isoformat() if c.observed_at else None,
            }
            for c in recent_changes
        ],
        "recent_scans": [
            {
                "scan_id": s.scan_id,
                "target": s.target,
                "scan_profile": s.scan_profile,
                "execution_mode": s.execution_mode,
                "status": s.status,
                "summary": s.summary_json,
                "start_time": s.start_time.isoformat() if s.start_time else None,
            }
            for s in recent_scans
        ],
        "refresh_interval_seconds": settings.DASHBOARD_REFRESH_SECONDS,
    }


@api_router.get("/assets", response_model=List[AssetResponse])
def list_assets(
    subnet: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    criticality: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    """Module 1 & 2: Retrieve discovered asset inventory with open ports and intelligence."""
    q = db.query(Asset)
    if subnet:
        q = q.filter(Asset.subnet == subnet)
    if status_filter:
        q = q.filter(Asset.asset_status == status_filter.upper())
    if criticality:
        q = q.filter(Asset.criticality == criticality.upper())
    if search:
        like_term = f"%{search}%"
        q = q.filter(
            (Asset.ip_address.ilike(like_term))
            | (Asset.hostname.ilike(like_term))
            | (Asset.business_service.ilike(like_term))
            | (Asset.operating_system.ilike(like_term))
        )
    return q.order_by(Asset.risk_score.desc()).all()


@api_router.get("/assets/{asset_id}", response_model=AssetResponse)
def get_asset_detail(asset_id: str, db: Session = Depends(get_db)):
    """Retrieve single asset by ID or IP address."""
    asset = (
        db.query(Asset)
        .filter((Asset.asset_id == asset_id) | (Asset.ip_address == asset_id))
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")
    return asset


@api_router.patch("/assets/{asset_id}/business-context", response_model=AssetResponse)
def update_asset_business_context(
    asset_id: str,
    payload: AssetBusinessContextUpdate,
    actor: CurrentActor = Depends(require_permission("assets:manage")),
    db: Session = Depends(get_db),
):
    """
    Innovation 3: Port-to-Business-Service Mapping & Verified Gateway Configuration.
    Automatically recalculates statistical port & asset risk scores when criticality changes.
    """
    asset = (
        db.query(Asset)
        .filter((Asset.asset_id == asset_id) | (Asset.ip_address == asset_id))
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")

    if payload.criticality is not None:
        asset.criticality = payload.criticality.upper()
    if payload.business_service is not None:
        asset.business_service = payload.business_service
    if payload.owner_team is not None:
        asset.owner_team = payload.owner_team
    if payload.environment_tag is not None:
        asset.environment_tag = payload.environment_tag
    if payload.is_gateway_verified is not None:
        # PRD Module 3: Gateway label must only be assigned when supported by route or infrastructure evidence
        if payload.is_gateway_verified and not (payload.gateway_evidence or asset.gateway_evidence):
            raise HTTPException(
                status_code=400,
                detail="Gateway verification requires explicit route or infrastructure evidence (gateway_evidence).",
            )
        asset.is_gateway_verified = payload.is_gateway_verified
    if payload.gateway_evidence is not None:
        asset.gateway_evidence = payload.gateway_evidence

    # Recompute port risk scores with updated criticality
    max_risk = 0.0
    for port in asset.ports:
        intel = enrich_port_observation(
            port_number=port.port_number,
            protocol=port.protocol,
            detected_service=port.detected_service,
            product=port.product,
            version=port.version,
        )
        eval_res = compute_port_risk_score(
            port_number=port.port_number,
            protocol=port.protocol,
            state=port.state,
            intel=intel,
            asset_criticality=asset.criticality,
            product=port.product,
            version=port.version,
        )
        port.risk_score = eval_res.total_score
        port.risk_classification = eval_res.classification
        port.risk_factors_json = eval_res.factors
        max_risk = max(max_risk, eval_res.total_score)

    asset.risk_score = round(max_risk, 1)
    asset.risk_classification = classify_risk_score(asset.risk_score)
    db.commit()
    db.refresh(asset)

    record_audit_event(
        db=db,
        actor_id=actor.username,
        actor_role=actor.role,
        action="ASSET_BUSINESS_CONTEXT_UPDATED",
        resource=asset.ip_address,
        details=payload.model_dump(exclude_none=True),
        outcome="SUCCESS",
    )
    return asset


@api_router.get("/ports", response_model=List[PortResponse])
def list_ports(
    target: Optional[str] = Query(default=None),
    protocol: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    mismatch_only: bool = Query(default=False),
    db: Session = Depends(get_db),
):
    """Module 2: Port Intelligence inventory with conventional vs. detected service comparison."""
    q = db.query(Port).join(Asset)
    if target:
        q = q.filter((Asset.ip_address == target) | (Asset.asset_id == target))
    if protocol:
        q = q.filter(Port.protocol == protocol.upper())
    if state:
        q = q.filter(Port.state == state.lower())
    if mismatch_only:
        q = q.filter(Port.service_mismatch.is_(True))
    return q.order_by(Port.risk_score.desc()).all()


@api_router.get("/cidrs", response_model=List[AuthorizedCIDRResponse])
def list_authorized_cidrs(db: Session = Depends(get_db)):
    return db.query(AuthorizedCIDR).order_by(AuthorizedCIDR.created_at.asc()).all()


@api_router.post("/cidrs", response_model=AuthorizedCIDRResponse, status_code=status.HTTP_201_CREATED)
def add_authorized_cidr(
    payload: AuthorizedCIDRCreate,
    actor: CurrentActor = Depends(require_permission("cidr:manage")),
    db: Session = Depends(get_db),
):
    try:
        net = ipaddress.ip_network(payload.cidr_block.strip(), strict=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid CIDR block: {exc}") from exc

    norm_cidr = str(net)
    existing = db.query(AuthorizedCIDR).filter(AuthorizedCIDR.cidr_block == norm_cidr).first()
    if existing:
        existing.is_active = True
        existing.description = payload.description
        db.commit()
        db.refresh(existing)
        return existing

    cidr_obj = AuthorizedCIDR(
        cidr_block=norm_cidr,
        description=payload.description,
        environment=payload.environment,
        owner_team=payload.owner_team,
        is_active=True,
    )
    db.add(cidr_obj)
    db.commit()
    db.refresh(cidr_obj)

    record_audit_event(
        db=db,
        actor_id=actor.username,
        actor_role=actor.role,
        action="AUTHORIZED_CIDR_ADDED",
        resource=norm_cidr,
        details={"description": payload.description},
        outcome="SUCCESS",
    )
    return cidr_obj


@api_router.get("/scans", response_model=List[ScanJobResponse])
def list_scans(db: Session = Depends(get_db)):
    return db.query(ScanJob).order_by(ScanJob.start_time.desc()).limit(50).all()


@api_router.post("/scans", response_model=ScanJobResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanCreateRequest,
    actor: CurrentActor = Depends(require_permission("scan:execute")),
    db: Session = Depends(get_db),
):
    """Module 1: Initiates an authorized network scan after enforcing CIDR scope checks."""
    try:
        scan_job = execute_authorized_scan(
            db=db,
            target=payload.target,
            scan_profile=payload.scan_profile,
            initiated_by=actor.username,
            simulation_scenario=payload.simulation_scenario or "ENTERPRISE_DRIFT",
        )
        record_audit_event(
            db=db,
            actor_id=actor.username,
            actor_role=actor.role,
            action="SCAN_EXECUTED",
            resource=payload.target,
            details={"scan_id": scan_job.scan_id, "profile": payload.scan_profile},
            outcome="SUCCESS",
        )
        return scan_job
    except PermissionError as exc:
        record_audit_event(
            db=db,
            actor_id=actor.username,
            actor_role=actor.role,
            action="SCAN_REJECTED_UNAUTHORIZED_CIDR",
            resource=payload.target,
            details={"reason": str(exc)},
            outcome="DENIED",
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@api_router.get("/scans/{scan_id}")
def get_scan_detail(scan_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    scan = db.query(ScanJob).filter(ScanJob.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return {
        "scan_id": scan.scan_id,
        "target": scan.target,
        "scan_profile": scan.scan_profile,
        "nmap_command": scan.nmap_command,
        "execution_mode": scan.execution_mode,
        "status": scan.status,
        "progress_pct": scan.progress_pct,
        "summary_json": scan.summary_json,
        "raw_xml": scan.raw_xml,
        "error_message": scan.error_message,
        "initiated_by": scan.initiated_by,
        "start_time": scan.start_time.isoformat() if scan.start_time else None,
        "end_time": scan.end_time.isoformat() if scan.end_time else None,
    }


@api_router.post("/scans/{scan_id}/cancel")
def cancel_scan(
    scan_id: str,
    actor: CurrentActor = Depends(require_permission("scan:cancel")),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    scan = db.query(ScanJob).filter(ScanJob.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan job not found.")
    scan.status = "CANCELLED"
    db.commit()
    record_audit_event(
        db=db,
        actor_id=actor.username,
        actor_role=actor.role,
        action="SCAN_CANCELLED",
        resource=scan_id,
        outcome="SUCCESS",
    )
    return {"scan_id": scan.scan_id, "status": scan.status}


@api_router.get("/schedules")
def list_scan_schedules(db: Session = Depends(get_db)):
    schedules = db.query(ScanSchedule).all()
    return [
        {
            "schedule_id": s.schedule_id,
            "name": s.name,
            "target": s.target,
            "scan_profile": s.scan_profile,
            "interval_minutes": s.interval_minutes,
            "priority_tier": s.priority_tier,
            "optimization_reason": s.optimization_reason,
            "is_enabled": s.is_enabled,
            "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
            "next_run_at": s.next_run_at.isoformat() if s.next_run_at else None,
        }
        for s in schedules
    ]


@api_router.post("/schedules/optimize")
def trigger_scan_optimization(
    actor: CurrentActor = Depends(require_permission("scan:execute")),
    db: Session = Depends(get_db),
):
    """Innovation 6: Autonomous Scan Optimization based on asset volatility and UDP cost."""
    result = optimize_scan_schedules(db)
    record_audit_event(
        db=db,
        actor_id=actor.username,
        actor_role=actor.role,
        action="AUTONOMOUS_SCAN_OPTIMIZATION",
        resource="scan_schedules",
        outcome="SUCCESS",
    )
    return result


@api_router.get("/topology")
def get_network_topology(
    subnet: Optional[str] = Query(default=None),
    min_risk: float = Query(default=0.0),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Module 3: Live Network Topology Graph (`Network -> Subnet -> Host -> Service -> Port`)."""
    return build_live_topology_graph(db, subnet_filter=subnet, min_risk_score=min_risk)


@api_router.get("/topology/snapshots")
def list_topology_snapshots(db: Session = Depends(get_db)):
    """Innovation 1: Network Exposure Digital Twin Historical Snapshots."""
    snaps = db.query(TopologySnapshot).order_by(TopologySnapshot.captured_at.desc()).limit(25).all()
    return [
        {
            "snapshot_id": s.snapshot_id,
            "scan_id": s.scan_id,
            "label": s.label,
            "stats": s.stats_json,
            "captured_at": s.captured_at.isoformat() if s.captured_at else None,
        }
        for s in snaps
    ]


@api_router.get("/topology/compare")
def compare_digital_twin_snapshots(
    baseline_id: str = Query(...),
    target_id: str = Query(...),
    db: Session = Depends(get_db),
):
    """Innovation 1: Historical Topology Comparison between any two Digital Twin snapshots."""
    try:
        return compare_topology_snapshots(db, baseline_snapshot_id=baseline_id, target_snapshot_id=target_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@api_router.get("/changes", response_model=List[NetworkChangeResponse])
def list_network_changes(
    change_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    """Module 4: Autonomous Change Detection history."""
    q = db.query(NetworkChange)
    if change_type:
        q = q.filter(NetworkChange.change_type == change_type.upper())
    if severity:
        q = q.filter(NetworkChange.severity.ilike(severity))
    return q.order_by(NetworkChange.observed_at.desc()).limit(100).all()


@api_router.get("/changes/predictions")
def get_change_risk_predictions(db: Session = Depends(get_db)):
    """Innovation 5: Statistical Network Change Risk Prediction & Volatility Trends."""
    return compute_asset_volatility_predictions(db)


@api_router.get("/findings", response_model=List[FindingResponse])
def list_security_findings(
    severity: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    db: Session = Depends(get_db),
):
    """Module 5 & Section 8: Prioritized Security Findings with factor breakdown and AI explanations."""
    q = db.query(Finding)
    if severity:
        q = q.filter(Finding.severity.ilike(severity))
    if category:
        q = q.filter(Finding.category == category.upper())
    if status_filter:
        q = q.filter(Finding.status == status_filter.upper())
    return q.order_by(Finding.risk_score.desc()).all()


@api_router.patch("/findings/{finding_id}/status", response_model=FindingResponse)
def update_finding_status(
    finding_id: str,
    new_status: str = Query(..., pattern="^(OPEN|INVESTIGATING|ACKNOWLEDGED|RESOLVED)$"),
    actor: CurrentActor = Depends(require_permission("findings:manage")),
    db: Session = Depends(get_db),
):
    finding = db.query(Finding).filter(Finding.finding_id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    finding.status = new_status.upper()
    db.commit()
    db.refresh(finding)
    record_audit_event(
        db=db,
        actor_id=actor.username,
        actor_role=actor.role,
        action="FINDING_STATUS_UPDATED",
        resource=finding_id,
        details={"new_status": finding.status},
        outcome="SUCCESS",
    )
    return finding


@api_router.get("/investigations", response_model=List[InvestigationRecordResponse])
def list_autonomous_investigations(db: Session = Depends(get_db)):
    """Innovation 2: Autonomous Exposure Investigator records."""
    return db.query(InvestigationRecord).order_by(InvestigationRecord.created_at.desc()).all()


@api_router.post("/ai/investigate")
def run_hybrid_ai_investigation(
    payload: AIInvestigateRequest,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Module 5 & Innovation 4: Explainable AI Security Analyst.
    Supports both specific finding deep-dive re-evaluation and natural-language network investigation.
    """
    if payload.finding_id:
        finding = db.query(Finding).filter(Finding.finding_id == payload.finding_id).first()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found.")
        asset = finding.asset
        ev = finding.evidence_json or {}
        exp, provider, uncertainty = generate_finding_explanation(
            asset_ip=asset.ip_address if asset else ev.get("ip_address", "unknown"),
            hostname=asset.hostname if asset else ev.get("hostname"),
            business_service=asset.business_service if asset else "Enterprise Asset",
            criticality=asset.criticality if asset else "MEDIUM",
            port_number=int(ev.get("port", 0)),
            protocol=ev.get("protocol", "TCP"),
            state=ev.get("state", "open"),
            conventional_service=ev.get("conventional_service", "unknown"),
            detected_service=ev.get("detected_service", "unknown"),
            service_mismatch=bool(ev.get("service_mismatch", False)),
            product=ev.get("product"),
            version=ev.get("version"),
            banner=ev.get("banner"),
            risk_score=finding.risk_score,
            severity=finding.severity,
            score_breakdown=finding.score_breakdown_json or {},
            recommendation=finding.recommendation,
            preferred_provider=payload.preferred_provider,
        )
        finding.ai_explanation = exp
        finding.ai_provider_used = provider
        finding.uncertainty_note = uncertainty
        db.commit()
        return {
            "finding_id": finding.finding_id,
            "title": finding.title,
            "ai_explanation": exp,
            "provider_used": provider,
            "uncertainty_note": uncertainty,
            "evidence": finding.evidence_json,
            "score_breakdown": finding.score_breakdown_json,
        }

    # Natural language investigation across the inventory
    assets = db.query(Asset).all()
    findings = db.query(Finding).order_by(Finding.risk_score.desc()).limit(10).all()
    changes = db.query(NetworkChange).order_by(NetworkChange.observed_at.desc()).limit(10).all()

    ctx = {
        "total_assets": len(assets),
        "high_or_critical_findings": [
            {
                "title": f.title,
                "ip": f.evidence_json.get("ip_address") if f.evidence_json else "",
                "risk_score": f.risk_score,
                "severity": f.severity,
                "business_service": f.asset.business_service if f.asset else "Enterprise Host",
            }
            for f in findings
        ],
        "recent_changes": [
            {
                "change_type": c.change_type,
                "summary": c.summary,
                "significance_score": c.significance_score,
            }
            for c in changes
        ],
    }
    return answer_natural_language_investigation(
        question=payload.question or "Which findings should the SOC team investigate first and what changed recently?",
        context_summary=ctx,
        preferred_provider=payload.preferred_provider,
    )


@api_router.post("/terminal/command", response_model=TerminalCommandResponse)
def execute_terminal_command_endpoint(
    payload: TerminalCommandRequest,
    actor: CurrentActor = Depends(require_permission("terminal:execute")),
    db: Session = Depends(get_db),
):
    """Module 6: Hybrid Command Terminal API with strict allowlisting & injection prevention."""
    return dispatch_terminal_command(
        db=db,
        raw_command=payload.command,
        actor=actor,
        session_id=payload.session_id or "default",
    )


@api_router.get("/alerts")
def list_alerts(
    unacknowledged_only: bool = Query(default=False),
    db: Session = Depends(get_db),
):
    """Module 8: Deduplicated security alerts."""
    q = db.query(Alert)
    if unacknowledged_only:
        q = q.filter(Alert.acknowledged.is_(False))
    alerts = q.order_by(Alert.last_triggered_at.desc()).all()
    return [
        {
            "alert_id": a.alert_id,
            "category": a.category,
            "severity": a.severity,
            "title": a.title,
            "message": a.message,
            "asset_ip": a.asset_ip,
            "occurrence_count": a.occurrence_count,
            "channels_notified": a.channels_notified,
            "acknowledged": a.acknowledged,
            "acknowledged_by": a.acknowledged_by,
            "first_triggered_at": a.first_triggered_at.isoformat() if a.first_triggered_at else None,
            "last_triggered_at": a.last_triggered_at.isoformat() if a.last_triggered_at else None,
        }
        for a in alerts
    ]


@api_router.post("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: str,
    actor: CurrentActor = Depends(require_permission("findings:manage")),
    db: Session = Depends(get_db),
):
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")
    alert.acknowledged = True
    alert.acknowledged_by = actor.username
    db.commit()
    return {"alert_id": alert.alert_id, "acknowledged": True, "acknowledged_by": actor.username}


@api_router.get("/audit")
def list_audit_events(
    actor: CurrentActor = Depends(require_permission("reports:read")),
    db: Session = Depends(get_db),
):
    """Module 9: Administrator & security audit trail."""
    events = db.query(AuditEvent).order_by(AuditEvent.timestamp.desc()).limit(100).all()
    return [
        {
            "event_id": e.event_id,
            "actor_id": e.actor_id,
            "actor_role": e.actor_role,
            "action": e.action,
            "resource": e.resource,
            "details": e.details_json,
            "outcome": e.outcome,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        }
        for e in events
    ]


@api_router.get("/reports/csv")
def export_csv_report(
    actor: CurrentActor = Depends(require_permission("reports:read")),
    db: Session = Depends(get_db),
):
    """Module 9: Export CSV asset & port inventory."""
    csv_data = generate_csv_asset_export(db)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=netsentinel_assets_inventory.csv"},
    )


@api_router.get("/reports/json")
def export_json_report(
    actor: CurrentActor = Depends(require_permission("reports:read")),
    db: Session = Depends(get_db),
):
    """Module 9: Export JSON executive & technical audit bundle."""
    return generate_json_executive_audit_bundle(db)


@api_router.get("/reports/html", response_class=HTMLResponse)
def export_printable_security_report(
    actor: CurrentActor = Depends(require_permission("reports:read")),
    db: Session = Depends(get_db),
):
    """Module 9: Printable HTML/PDF Security Report."""
    return HTMLResponse(content=generate_printable_html_security_report(db))

