export interface PortRecord {
  port_id: string;
  asset_id: string;
  port_number: number;
  protocol: string;
  state: string;
  conventional_service: string;
  detected_service: string;
  service_mismatch: boolean;
  product?: string | null;
  version?: string | null;
  banner?: string | null;
  typical_purpose: string;
  exposure_class: string;
  risk_score: number;
  risk_classification: string;
  risk_factors_json: Record<string, any>;
  recommended_action: string;
  first_observed: string;
  last_observed: string;
}

export interface AssetRecord {
  asset_id: string;
  ip_address: string;
  hostname?: string | null;
  mac_address?: string | null;
  vendor?: string | null;
  operating_system?: string | null;
  os_accuracy: number;
  subnet: string;
  asset_status: string;
  criticality: string;
  business_service?: string | null;
  owner_team?: string | null;
  environment_tag?: string | null;
  is_gateway_verified: boolean;
  gateway_evidence?: string | null;
  risk_score: number;
  risk_classification: string;
  volatility_score: number;
  first_seen: string;
  last_seen: string;
  ports: PortRecord[];
}

export interface InvestigationRecord {
  investigation_id: string;
  finding_id: string;
  asset_id: string;
  trigger_reason: string;
  steps_completed_json: Array<{
    step: number;
    action: string;
    status: string;
    detail: string;
  }>;
  historical_context: string;
  business_impact_summary: string;
  defensive_review_checklist: string[];
  notified_owner?: string | null;
  created_at: string;
}

export interface FindingRecord {
  finding_id: string;
  asset_id: string;
  port_id?: string | null;
  scan_id?: string | null;
  title: string;
  category: string;
  severity: string;
  risk_score: number;
  score_breakdown_json: Record<string, any>;
  evidence_json: Record<string, any>;
  recommendation: string;
  ai_explanation?: string | null;
  ai_provider_used: string;
  uncertainty_note?: string | null;
  status: string;
  created_at: string;
  investigation?: InvestigationRecord | null;
}

export interface NetworkChangeRecord {
  change_id: string;
  scan_id?: string | null;
  asset_id: string;
  change_type: string;
  severity: string;
  summary: string;
  previous_value: Record<string, any>;
  current_value: Record<string, any>;
  significance_score: number;
  observed_at: string;
}

export interface ScanJobRecord {
  scan_id: string;
  target: string;
  scan_profile: string;
  nmap_command: string;
  execution_mode: string;
  status: string;
  progress_pct: number;
  summary_json: Record<string, any>;
  error_message?: string | null;
  initiated_by: string;
  start_time: string;
  end_time?: string | null;
}

export interface TopologyNode {
  id: string;
  type: "NETWORK_CORE" | "SUBNET" | "HOST" | "SERVICE_PORT";
  label: string;
  status?: string;
  risk_score: number;
  risk_classification?: string;
  ip_address?: string;
  hostname?: string;
  subnet?: string;
  operating_system?: string;
  criticality?: string;
  business_service?: string;
  owner_team?: string;
  is_gateway_verified?: boolean;
  gateway_evidence?: string;
  role_badge?: string;
  port_number?: number;
  protocol?: string;
  detected_service?: string;
  conventional_service?: string;
  service_mismatch?: boolean;
  typical_purpose?: string;
  exposure_class?: string;
  metadata?: Record<string, any>;
}

export interface TopologyEdge {
  id: string;
  source: string;
  target: string;
  relationship_type: string;
  verified_physical: boolean;
}

