import { Activity, AlertTriangle, CheckCircle2, Lock, ShieldCheck, ShieldAlert } from "lucide-react";
import type { AuditLog, OverviewData } from "../types";

interface Props {
  overview: OverviewData | null;
  recentLogs: AuditLog[];
  onQuickJumpSimulator: () => void;
}

export function DecisionBadge({ decision }: { decision: string }) {
  if (decision === "ALLOW") return <span className="badge badge-allow">ALLOW</span>;
  if (decision === "STEP_UP") return <span className="badge badge-stepup">STEP-UP MFA</span>;
  if (decision === "DENY") return <span className="badge badge-deny">DENY</span>;
  return <span className="badge badge-info">{decision}</span>;
}

export function OverviewTab({ overview, recentLogs, onQuickJumpSimulator }: Props) {
  if (!overview) {
    return <div className="card">Loading Zero Trust telemetry...</div>;
  }

  return (
    <div>
      <div className="grid-4">
        <div className="card">
          <div className="stat-label">PEP Enforcement Decisions</div>
          <div className="stat-value" style={{ color: "var(--green)" }}>
            {overview.decisions.ALLOW} <span style={{ fontSize: "1rem", color: "var(--amber)" }}>/ {overview.decisions.STEP_UP}</span>{" "}
            <span style={{ fontSize: "1rem", color: "var(--red)" }}>/ {overview.decisions.DENY}</span>
          </div>
          <div className="stat-sub">Allow / Step-Up MFA / Deny</div>
        </div>

        <div className="card">
          <div className="stat-label">Continuous Risk & Trust</div>
          <div className="stat-value" style={{ color: overview.avg_risk_score > 50 ? "var(--amber)" : "var(--cyan)" }}>
            {overview.avg_risk_score} <span style={{ fontSize: "0.95rem", color: "var(--text-muted)" }}>risk avg</span>
          </div>
          <div className="stat-sub">
            Avg Endpoint Trust: <strong style={{ color: "var(--text)" }}>{overview.avg_device_trust}/100</strong>
          </div>
        </div>

        <div className="card">
          <div className="stat-label">Anomalies & Containment</div>
          <div className="stat-value" style={{ color: overview.anomalies_detected > 0 ? "var(--red)" : "var(--green)" }}>
            {overview.anomalies_detected}
          </div>
          <div className="stat-sub">
            {overview.quarantined_devices} quarantined devices · {overview.locked_identities} locked identities
          </div>
        </div>

        <div className="card">
          <div className="stat-label">Audit Chain & Sessions</div>
          <div className="stat-value" style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {overview.audit_integrity.valid ? (
              <>
                <CheckCircle2 size={24} color="var(--green)" />
                <span style={{ fontSize: "1.2rem", color: "var(--green)" }}>Verified</span>
              </>
            ) : (
              <>
                <ShieldAlert size={24} color="var(--red)" />
                <span style={{ fontSize: "1.2rem", color: "var(--red)" }}>Tampered</span>
              </>
            )}
          </div>
          <div className="stat-sub">
            {overview.audit_integrity.total_records} chained logs · {overview.active_sessions} active sessions
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-title">
          <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <ShieldCheck size={18} color="var(--cyan)" />
            NIST SP 800-207 Zero Trust Enforcement Pipeline
          </span>
          <button className="btn btn-primary btn-sm" onClick={onQuickJumpSimulator}>
            Open PEP Access Simulator
          </button>
        </div>
        <div className="zta-pipeline">
          <div className="zta-stage">
            <strong>1. Explicit Identity</strong>
            <span>PBKDF2 credentials + short-lived HS256 JWT + RFC 6238 TOTP MFA.</span>
          </div>
          <div className="zta-stage">
            <strong>2. Device Posture</strong>
            <span>MDM enrollment, disk encryption, EDR status, patch hygiene & jailbreak check.</span>
          </div>
          <div className="zta-stage">
            <strong>3. Continuous Risk</strong>
            <span>Geo-velocity impossible travel, Tor/anonymizer IP & off-hours anomaly scoring.</span>
          </div>
          <div className="zta-stage">
            <strong>4. PDP Policy Engine</strong>
            <span>Priority-ordered ABAC + RBAC + Clearance evaluation with default-deny gate.</span>
          </div>
          <div className="zta-stage">
            <strong>5. Micro-Segments</strong>
            <span>Per-request PEP enforcement protecting Finance, Prod K8s & IAM Vault.</span>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-title">
          <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <Activity size={18} color="var(--cyan)" />
            Recent Policy Enforcement Stream
          </span>
          <span className="stat-sub">{overview.enabled_policies} active policies enforcing</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Event</th>
                <th>Actor</th>
                <th>Resource</th>
                <th>Risk</th>
                <th>Decision</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {recentLogs.slice(0, 10).map((log) => (
                <tr key={log.id}>
                  <td className="mono">{new Date(log.timestamp * 1000).toLocaleTimeString()}</td>
                  <td>
                    {log.event_type === "ANOMALY" ? (
                      <span className="badge badge-deny">
                        <AlertTriangle size={12} /> ANOMALY
                      </span>
                    ) : (
                      <span className="badge badge-info">{log.event_type}</span>
                    )}
                  </td>
                  <td className="mono">{log.actor_email}</td>
                  <td className="mono">
                    <Lock size={12} style={{ verticalAlign: "middle", marginRight: 4 }} />
                    {log.resource_id}
                  </td>
                  <td>
                    <strong>{log.risk_score}</strong>/100
                  </td>
                  <td>
                    <DecisionBadge decision={log.decision} />
                  </td>
                  <td>{log.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
