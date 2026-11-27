export type DecisionType = "ALLOW" | "STEP_UP" | "DENY" | "INFO";

export interface Identity {
  id: string;
  email: string;
  name: string;
  role: string;
  department: string;
  clearance_level: number;
  mfa_enabled: number;
  status: "active" | "locked" | "suspended";
  failed_attempts: number;
  last_known_geo: string;
  last_login_at: number;
}

export interface Device {
  id: string;
  device_name: string;
  owner_id: string;
  os_type: string;
  os_version: string;
  managed: boolean;
  disk_encrypted: boolean;
  edr_active: boolean;
  patch_age_days: number;
  jailbroken: boolean;
  trust_score: number;
  quarantined: boolean;
  last_seen_at: number;
}

export interface ProtectedResource {
  id: string;
  name: string;
  segment: string;
  classification: "internal" | "confidential" | "restricted";
  min_clearance: number;
  require_managed_device: boolean;
  require_mfa: boolean;
  allowed_roles: string[];
}

export interface ZeroTrustPolicy {
  id: string;
  name: string;
  description: string;
  priority: number;
  effect: "ALLOW" | "STEP_UP" | "DENY";
  enabled: boolean;
  conditions: Record<string, unknown>;
}

export interface SessionRecord {
  id: string;
  identity_id: string;
  device_id: string;
  ip_address: string;
  geo_location: string;
  mfa_verified: boolean;
  step_up_until: number;
  revoked: boolean;
  active: boolean;
  expires_at: number;
  created_at: number;
  email: string;
  identity_name: string;
  role: string;
  device_name: string;
}

export interface AuditIntegrity {
  valid: boolean;
  total_records: number;
  broken_at_id: number | null;
  head_hash?: string;
  error?: string;
}

export interface AuditLog {
  id: number;
  timestamp: number;
  event_type: string;
  actor_id: string;
  actor_email: string;
  device_id: string;
  resource_id: string;
  action: string;
  decision: DecisionType;
  risk_score: number;
  reason: string;
  details: Record<string, unknown>;
  prev_hash: string;
  record_hash: string;
}

export interface OverviewData {
  decisions: { ALLOW: number; STEP_UP: number; DENY: number };
  anomalies_detected: number;
  avg_risk_score: number;
  avg_device_trust: number;
  quarantined_devices: number;
  active_sessions: number;
  locked_identities: number;
  enabled_policies: number;
  audit_integrity: AuditIntegrity;
  geo_locations: string[];
}

export interface RiskFactor {
  code: string;
  category: string;
  delta: number;
  description: string;
}

export interface RuleTraceItem {
  gate: string;
  policy_name?: string;
  effect?: string;
  result: string;
  detail: string;
}

export interface SimulationResult {
  decision: "ALLOW" | "STEP_UP" | "DENY";
  risk_score: number;
  device_trust_score: number;
  risk_level: "LOW" | "MEDIUM" | "CRITICAL";
  matched_policy: string;
  reason: string;
  anomalies: string[];
  risk_factors: RiskFactor[];
  rule_trace: RuleTraceItem[];
  resource_preview?: string | null;
}
