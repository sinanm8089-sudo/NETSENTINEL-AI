"""Pydantic v2 Request and Response Schemas for NETSENTINEL AI."""
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PortResponse(BaseModel):
    port_id: str
    asset_id: str
    port_number: int
    protocol: str
    state: str
    conventional_service: str
    detected_service: str
    service_mismatch: bool
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    typical_purpose: str
    exposure_class: str
    risk_score: float
    risk_classification: str
    risk_factors_json: Dict[str, Any] = Field(default_factory=dict)
    recommended_action: str
    first_observed: datetime
    last_observed: datetime

    class Config:
        from_attributes = True


class AssetResponse(BaseModel):
    asset_id: str
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    operating_system: Optional[str] = None
    os_accuracy: float = 0.0
    subnet: str
    asset_status: str
    criticality: str
    business_service: Optional[str] = None
    owner_team: Optional[str] = None
    environment_tag: Optional[str] = None
    is_gateway_verified: bool = False
    gateway_evidence: Optional[str] = None
    risk_score: float = 0.0
    risk_classification: str = "Informational"
    volatility_score: float = 0.0
    first_seen: datetime
    last_seen: datetime
    ports: List[PortResponse] = Field(default_factory=list)

    class Config:
        from_attributes = True


class AssetBusinessContextUpdate(BaseModel):
    criticality: Optional[str] = Field(None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    business_service: Optional[str] = None
    owner_team: Optional[str] = None
    environment_tag: Optional[str] = None
    is_gateway_verified: Optional[bool] = None
    gateway_evidence: Optional[str] = None


class AuthorizedCIDRCreate(BaseModel):
    cidr_block: str
    description: str
    environment: str = "Enterprise Production"
    owner_team: str = "SecOps / NetEng"


class AuthorizedCIDRResponse(BaseModel):
    cidr_id: str
    cidr_block: str
    description: str
    environment: str
    owner_team: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class ScanCreateRequest(BaseModel):
    target: str = Field(..., description="IP address or CIDR block within authorized scope")
    scan_profile: str = Field(
        default="STANDARD_TCP_INTEL",
        description="QUICK_TCP | FULL_TCP | FULL_UDP | CONNECT_TCP | DISCOVERY_ONLY | LAB_SIMULATION_BASELINE | LAB_SIMULATION_DRIFT",
    )
    simulation_scenario: Optional[str] = Field(
        default="ENTERPRISE_DRIFT",
        description="Optional lab scenario: BASELINE | ENTERPRISE_DRIFT | ROGUE_DB_EXPOSURE |STEALTH_MISMATCH",
    )


class ScanJobResponse(BaseModel):
    scan_id: str
    target: str
    scan_profile: str
    nmap_command: str
    execution_mode: str
    status: str
    progress_pct: int
    summary_json: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    initiated_by: str
    start_time: datetime
    end_time: Optional[datetime] = None

    class Config:
        from_attributes = True


class InvestigationRecordResponse(BaseModel):
    investigation_id: str
    finding_id: str
    asset_id: str
    trigger_reason: str
    steps_completed_json: List[Dict[str, Any]] = Field(default_factory=list)
    historical_context: str
    business_impact_summary: str
    defensive_review_checklist: List[str] = Field(default_factory=list)
    notified_owner: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    finding_id: str
    asset_id: str
    port_id: Optional[str] = None
    scan_id: Optional[str] = None
    title: str
    category: str
    severity: str
    risk_score: float
    score_breakdown_json: Dict[str, Any] = Field(default_factory=dict)
    evidence_json: Dict[str, Any] = Field(default_factory=dict)
    recommendation: str
    ai_explanation: Optional[str] = None
    ai_provider_used: str
    uncertainty_note: Optional[str] = None
    status: str
    created_at: datetime
    investigation: Optional[InvestigationRecordResponse] = None

    class Config:
        from_attributes = True


class NetworkChangeResponse(BaseModel):
    change_id: str
    scan_id: Optional[str] = None
    asset_id: str
    change_type: str
    severity: str
    summary: str
    previous_value: Dict[str, Any] = Field(default_factory=dict)
    current_value: Dict[str, Any] = Field(default_factory=dict)
    significance_score: float
    observed_at: datetime

    class Config:
        from_attributes = True


class TerminalCommandRequest(BaseModel):
    command: str
    session_id: Optional[str] = "default"


class TerminalCommandResponse(BaseModel):
    command: str
    allowed: bool
    status: str
    output: str
    execution_time_ms: float
    audit_event_id: Optional[str] = None


class AIInvestigateRequest(BaseModel):
    finding_id: Optional[str] = None
    asset_id: Optional[str] = None
    question: Optional[str] = None
    preferred_provider: str = "AUTO"  # AUTO | STATISTICAL_OFFLINE | LOCAL_OLLAMA | CLOUD_GEMINI | CLOUD_OPENAI

