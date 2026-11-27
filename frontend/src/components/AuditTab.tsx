import { CheckCircle2, FileCheck2, ShieldAlert } from "lucide-react";
import { api } from "../api";
import type { AuditIntegrity, AuditLog } from "../types";
import { DecisionBadge } from "./OverviewTab";

interface Props {
  logs: AuditLog[];
  integrity: AuditIntegrity | null;
  onIntegrityUpdate: (res: AuditIntegrity) => void;
}

export function AuditTab({ logs, integrity, onIntegrityUpdate }: Props) {
  async function handleVerify() {
    const res = await api.verifyAudit();
    onIntegrityUpdate(res);
  }

  return (
    <div className="card">
      <div className="card-title">
        <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
          <FileCheck2 size={18} color="var(--cyan)" />
          Tamper-Evident SHA-256 Hash-Chained Audit Trail
        </span>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          {integrity && (
            <span className={`badge ${integrity.valid ? "badge-allow" : "badge-deny"}`}>
              {integrity.valid ? (
                <>
                  <CheckCircle2 size={13} /> Chain Intact ({integrity.total_records} records)
                </>
              ) : (
                <>
                  <ShieldAlert size={13} /> Tamper Detected @ #{integrity.broken_at_id}
                </>
              )}
            </span>
          )}
          <button className="btn btn-primary btn-sm" onClick={handleVerify}>
            Verify Cryptographic Chain
          </button>
        </div>
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Timestamp</th>
              <th>Type</th>
              <th>Actor</th>
              <th>Target</th>
              <th>Decision</th>
              <th>Risk</th>
              <th>Reason</th>
              <th>Record Hash (SHA-256)</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((log) => (
              <tr key={log.id}>
                <td className="mono">{log.id}</td>
                <td className="mono">{new Date(log.timestamp * 1000).toLocaleString()}</td>
                <td>
                  <span className={`badge ${log.event_type === "ANOMALY" ? "badge-deny" : "badge-info"}`}>
                    {log.event_type}
                  </span>
                </td>
                <td className="mono">{log.actor_email}</td>
                <td className="mono">{log.resource_id}</td>
                <td>
                  <DecisionBadge decision={log.decision} />
                </td>
                <td className="mono">{log.risk_score}</td>
                <td>{log.reason}</td>
                <td className="mono" title={`prev: ${log.prev_hash}\ncurr: ${log.record_hash}`}>
                  {log.record_hash.slice(0, 14)}...
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
