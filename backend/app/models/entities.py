"""SQLAlchemy 2.0 ORM Entities for NETSENTINEL AI."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def gen_uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    user_id = Column(String(36), primary_key=True, default=gen_uuid)
    username = Column(String(64), unique=True, nullable=False, index=True)
    full_name = Column(String(128), nullable=False)
    email = Column(String(128), unique=True, nullable=False)
    role = Column(String(32), nullable=False, default="SOC_ANALYST")
    # Roles: SUPER_ADMIN, SECURITY_ADMIN, SOC_ANALYST, NETWORK_ADMIN, AUDITOR
    api_token = Column(String(128), unique=True, nullable=True, index=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class AuthorizedCIDR(Base):
    __tablename__ = "authorized_cidrs"

    cidr_id = Column(String(36), primary_key=True, default=gen_uuid)
    cidr_block = Column(String(64), unique=True, nullable=False, index=True)
    description = Column(String(256), nullable=False)
    environment = Column(String(64), default="Enterprise Production")
    owner_team = Column(String(128), default="SecOps / NetEng")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class Asset(Base):
    __tablename__ = "assets"

    asset_id = Column(String(36), primary_key=True, default=gen_uuid)
    ip_address = Column(String(64), unique=True, nullable=False, index=True)
    hostname = Column(String(256), nullable=True)
    mac_address = Column(String(64), nullable=True)
    vendor = Column(String(128), nullable=True)
    operating_system = Column(String(256), nullable=True, default="Unknown OS")
    os_accuracy = Column(Float, default=0.0)
    subnet = Column(String(64), nullable=False, index=True)
    asset_status = Column(String(32), nullable=False, default="ACTIVE")
    # Statuses: ACTIVE, MISSING, UNREACHABLE
    criticality = Column(String(32), nullable=False, default="MEDIUM")
    # Criticality: LOW, MEDIUM, HIGH, CRITICAL
    business_service = Column(String(256), nullable=True, default="Unassigned Infrastructure")
    owner_team = Column(String(128), nullable=True, default="IT Operations")
    environment_tag = Column(String(64), nullable=True, default="Production")
    is_gateway_verified = Column(Boolean, default=False)
    gateway_evidence = Column(String(256), nullable=True)
    risk_score = Column(Float, default=0.0)
    risk_classification = Column(String(32), default="Informational")
    volatility_score = Column(Float, default=0.0)
    first_seen = Column(DateTime(timezone=True), default=utcnow)
    last_seen = Column(DateTime(timezone=True), default=utcnow)

    ports = relationship("Port", back_populates="asset", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")
    changes = relationship("NetworkChange", back_populates="asset", cascade="all, delete-orphan")


class Port(Base):
    __tablename__ = "ports"

    port_id = Column(String(36), primary_key=True, default=gen_uuid)
    asset_id = Column(String(36), ForeignKey("assets.asset_id", ondelete="CASCADE"), nullable=False, index=True)
    port_number = Column(Integer, nullable=False, index=True)
    protocol = Column(String(16), nullable=False, default="TCP")  # TCP | UDP
    state = Column(String(32), nullable=False, default="open")
    # States: open, closed, filtered, open|filtered, not_observed
    conventional_service = Column(String(128), nullable=False, default="unknown")
    detected_service = Column(String(128), nullable=False, default="unknown")
    service_mismatch = Column(Boolean, default=False)
    product = Column(String(256), nullable=True)
    version = Column(String(128), nullable=True)
    banner = Column(Text, nullable=True)
    typical_purpose = Column(String(512), nullable=False, default="General network communication")
    exposure_class = Column(String(64), nullable=False, default="INTERNAL_SERVICE")
    risk_score = Column(Float, default=0.0)
    risk_classification = Column(String(32), default="Informational")
    risk_factors_json = Column(JSON, default=dict)
    recommended_action = Column(Text, nullable=False, default="Verify service authorization and restrict network access.")
    first_observed = Column(DateTime(timezone=True), default=utcnow)
    last_observed = Column(DateTime(timezone=True), default=utcnow)

    asset = relationship("Asset", back_populates="ports")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    scan_id = Column(String(36), primary_key=True, default=gen_uuid)
    target = Column(String(128), nullable=False, index=True)
    scan_profile = Column(String(64), nullable=False, default="STANDARD_TCP_INTEL")
    # Profiles: QUICK_TCP, FULL_TCP, FULL_UDP, CONNECT_TCP, DISCOVERY_ONLY, LAB_SIMULATION_BASELINE, LAB_SIMULATION_DRIFT
    nmap_command = Column(String(512), nullable=False, default="")
    execution_mode = Column(String(32), nullable=False, default="SAFE_SIMULATION")
    # Modes: REAL_NMAP, SAFE_SIMULATION
    status = Column(String(32), nullable=False, default="QUEUED")
    # Statuses: QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED
    progress_pct = Column(Integer, default=0)
    raw_xml = Column(Text, nullable=True)
    summary_json = Column(JSON, default=dict)
    error_message = Column(Text, nullable=True)
    initiated_by = Column(String(128), default="system-autonomous")
    start_time = Column(DateTime(timezone=True), default=utcnow)
    end_time = Column(DateTime(timezone=True), nullable=True)


class Finding(Base):
    __tablename__ = "findings"

    finding_id = Column(String(36), primary_key=True, default=gen_uuid)
    asset_id = Column(String(36), ForeignKey("assets.asset_id", ondelete="CASCADE"), nullable=False, index=True)
    port_id = Column(String(36), ForeignKey("ports.port_id", ondelete="SET NULL"), nullable=True)
    scan_id = Column(String(36), ForeignKey("scan_jobs.scan_id", ondelete="SET NULL"), nullable=True)
    title = Column(String(256), nullable=False)
    category = Column(String(64), nullable=False)
    # Categories: EXPOSED_ADMIN, EXPOSED_DATABASE, UNENCRYPTED_PROTOCOL, SERVICE_PORT_MISMATCH, NEW_SERVICE_EXPOSURE, VERSION_CHANGE, ASSET_DISAPPEARED
    severity = Column(String(32), nullable=False, default="MEDIUM")
    # Severities: Informational, Low, Medium, High, Critical
    risk_score = Column(Float, nullable=False, default=0.0)
    score_breakdown_json = Column(JSON, default=dict)
    evidence_json = Column(JSON, default=dict)
    recommendation = Column(Text, nullable=False)
    ai_explanation = Column(Text, nullable=True)
    ai_provider_used = Column(String(64), default="STATISTICAL_OFFLINE")
    uncertainty_note = Column(Text, nullable=True)
    status = Column(String(32), default="OPEN")  # OPEN, INVESTIGATING, ACKNOWLEDGED, RESOLVED
    created_at = Column(DateTime(timezone=True), default=utcnow)

    asset = relationship("Asset", back_populates="findings")
    investigation = relationship(
        "InvestigationRecord",
        back_populates="finding",
        uselist=False,
        cascade="all, delete-orphan",
    )


class InvestigationRecord(Base):
    """Innovation 2: Autonomous Exposure Investigator Record."""
    __tablename__ = "investigation_records"

    investigation_id = Column(String(36), primary_key=True, default=gen_uuid)
    finding_id = Column(String(36), ForeignKey("findings.finding_id", ondelete="CASCADE"), nullable=False, unique=True)
    asset_id = Column(String(36), ForeignKey("assets.asset_id", ondelete="CASCADE"), nullable=False)
    trigger_reason = Column(String(256), nullable=False)
    steps_completed_json = Column(JSON, default=list)
    historical_context = Column(Text, nullable=False)
    business_impact_summary = Column(Text, nullable=False)
    defensive_review_checklist = Column(JSON, default=list)
    notified_owner = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    finding = relationship("Finding", back_populates="investigation")


class NetworkChange(Base):
    __tablename__ = "network_changes"

    change_id = Column(String(36), primary_key=True, default=gen_uuid)
    scan_id = Column(String(36), ForeignKey("scan_jobs.scan_id", ondelete="SET NULL"), nullable=True, index=True)
    asset_id = Column(String(36), ForeignKey("assets.asset_id", ondelete="CASCADE"), nullable=False, index=True)
    change_type = Column(String(64), nullable=False)
    # Types: NEW_DEVICE, MISSING_DEVICE, NEW_OPEN_PORT, PORT_NO_LONGER_OBSERVED, PORT_STATE_CHANGED, SERVICE_VERSION_CHANGED, OS_FINGERPRINT_CHANGED, RISK_CLASSIFICATION_CHANGED
    severity = Column(String(32), nullable=False, default="Medium")
    summary = Column(String(512), nullable=False)
    previous_value = Column(JSON, default=dict)
    current_value = Column(JSON, default=dict)
    significance_score = Column(Float, default=50.0)
    observed_at = Column(DateTime(timezone=True), default=utcnow)

    asset = relationship("Asset", back_populates="changes")


class TopologySnapshot(Base):
    """Innovation 1: Network Exposure Digital Twin Historical Snapshot."""
    __tablename__ = "topology_snapshots"

    snapshot_id = Column(String(36), primary_key=True, default=gen_uuid)
    scan_id = Column(String(36), ForeignKey("scan_jobs.scan_id", ondelete="SET NULL"), nullable=True)
    label = Column(String(256), nullable=False)
    nodes_json = Column(JSON, default=list)
    edges_json = Column(JSON, default=list)
    stats_json = Column(JSON, default=dict)
    captured_at = Column(DateTime(timezone=True), default=utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    alert_id = Column(String(36), primary_key=True, default=gen_uuid)
    category = Column(String(64), nullable=False)
    severity = Column(String(32), nullable=False, default="High")
    title = Column(String(256), nullable=False)
    message = Column(Text, nullable=False)
    asset_ip = Column(String(64), nullable=True)
    dedup_fingerprint = Column(String(256), unique=True, nullable=False, index=True)
    occurrence_count = Column(Integer, default=1)
    channels_notified = Column(JSON, default=list)
    acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String(128), nullable=True)
    first_triggered_at = Column(DateTime(timezone=True), default=utcnow)
    last_triggered_at = Column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    event_id = Column(String(36), primary_key=True, default=gen_uuid)
    actor_id = Column(String(128), nullable=False, default="admin")
    actor_role = Column(String(64), nullable=False, default="SUPER_ADMIN")
    action = Column(String(128), nullable=False)
    resource = Column(String(256), nullable=False)
    details_json = Column(JSON, default=dict)
    outcome = Column(String(32), nullable=False, default="SUCCESS")  # SUCCESS | DENIED | ERROR
    timestamp = Column(DateTime(timezone=True), default=utcnow)


class ScanSchedule(Base):
    """Module 1 + Innovation 6: Autonomous Scan Schedule & Optimization."""
    __tablename__ = "scan_schedules"

    schedule_id = Column(String(36), primary_key=True, default=gen_uuid)
    name = Column(String(128), nullable=False)
    target = Column(String(128), nullable=False)
    scan_profile = Column(String(64), nullable=False, default="STANDARD_TCP_INTEL")
    interval_minutes = Column(Integer, default=60)
    priority_tier = Column(String(32), default="NORMAL")  # NORMAL | HIGH_CHURN_PRIORITY | LOW_FREQUENCY_UDP
    optimization_reason = Column(String(512), nullable=True)
    is_enabled = Column(Boolean, default=True)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    next_run_at = Column(DateTime(timezone=True), nullable=True)

