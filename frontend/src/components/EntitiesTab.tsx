import { Laptop, ShieldAlert, UserCheck, ZapOff } from "lucide-react";
import { api } from "../api";
import type { Device, Identity, SessionRecord } from "../types";

interface Props {
  identities: Identity[];
  devices: Device[];
  sessions: SessionRecord[];
  onRefresh: () => void;
}

export function EntitiesTab({ identities, devices, sessions, onRefresh }: Props) {
  async function toggleIdentityStatus(identity: Identity) {
    const nextStatus = identity.status === "active" ? "locked" : "active";
    await api.updateIdentity(identity.id, { status: nextStatus, reset_failed_attempts: true });
    onRefresh();
  }

  async function toggleDeviceFlag(device: Device, field: "managed" | "edr_active" | "disk_encrypted" | "jailbroken" | "quarantined") {
    await api.updateDevice(device.id, { [field]: !device[field] });
    onRefresh();
  }

  async function handleRevokeSession(sessionId: string) {
    await api.revokeSession(sessionId);
    onRefresh();
  }

  return (
    <div>
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-title">
          <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <UserCheck size={18} color="var(--cyan)" />
            Verified Identities & Clearance
          </span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Identity</th>
                <th>Role & Dept</th>
                <th>Clearance</th>
                <th>Last Geo</th>
                <th>Failed Logins</th>
                <th>Status</th>
                <th>Control</th>
              </tr>
            </thead>
            <tbody>
              {identities.map((i) => (
                <tr key={i.id}>
                  <td>
                    <strong>{i.name}</strong>
                    <div className="mono" style={{ color: "var(--text-muted)" }}>{i.email}</div>
                  </td>
                  <td>
                    <span className="mono">{i.role}</span> · {i.department}
                  </td>
                  <td>Level {i.clearance_level}</td>
                  <td className="mono">{i.last_known_geo}</td>
                  <td>{i.failed_attempts}</td>
                  <td>
                    <span className={`badge ${i.status === "active" ? "badge-allow" : "badge-deny"}`}>
                      {i.status.toUpperCase()}
                    </span>
                  </td>
                  <td>
                    <button
                      className={`btn btn-sm ${i.status === "active" ? "btn-danger" : "btn-primary"}`}
                      onClick={() => toggleIdentityStatus(i)}
                    >
                      {i.status === "active" ? "Lock Identity" : "Unlock Identity"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-title">
          <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <Laptop size={18} color="var(--cyan)" />
            Endpoint Device Posture & Quarantine Controls
          </span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Device</th>
                <th>OS / Patch Age</th>
                <th>Trust Score</th>
                <th>Posture Signals</th>
                <th>Containment</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.id}>
                  <td>
                    <strong>{d.device_name}</strong>
                    <div className="mono" style={{ color: "var(--text-muted)" }}>{d.id}</div>
                  </td>
                  <td>
                    {d.os_type} {d.os_version}
                    <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                      Patch age: {d.patch_age_days}d
                    </div>
                  </td>
                  <td style={{ minWidth: 150 }}>
                    <div className="mono" style={{ marginBottom: 4 }}>
                      <strong>{d.trust_score}</strong>/100
                    </div>
                    <div className="progress-track">
                      <div
                        className="progress-fill"
                        style={{
                          width: `${d.trust_score}%`,
                          background:
                            d.trust_score >= 75
                              ? "var(--green)"
                              : d.trust_score >= 45
                              ? "var(--amber)"
                              : "var(--red)",
                        }}
                      />
                    </div>
                  </td>
                  <td>
                    <div className="pill-row">
                      <button
                        className={`btn btn-sm ${d.managed ? "btn-primary" : ""}`}
                        onClick={() => toggleDeviceFlag(d, "managed")}
                      >
                        MDM: {d.managed ? "ON" : "OFF"}
                      </button>
                      <button
                        className={`btn btn-sm ${d.edr_active ? "btn-primary" : ""}`}
                        onClick={() => toggleDeviceFlag(d, "edr_active")}
                      >
                        EDR: {d.edr_active ? "ON" : "OFF"}
                      </button>
                      <button
                        className={`btn btn-sm ${d.disk_encrypted ? "btn-primary" : ""}`}
                        onClick={() => toggleDeviceFlag(d, "disk_encrypted")}
                      >
                        FDE: {d.disk_encrypted ? "ON" : "OFF"}
                      </button>
                      <button
                        className={`btn btn-sm ${d.jailbroken ? "btn-danger" : ""}`}
                        onClick={() => toggleDeviceFlag(d, "jailbroken")}
                      >
                        Rooted: {d.jailbroken ? "YES" : "NO"}
                      </button>
                    </div>
                  </td>
                  <td>
                    <button
                      className={`btn btn-sm ${d.quarantined ? "btn-primary" : "btn-danger"}`}
                      onClick={() => toggleDeviceFlag(d, "quarantined")}
                    >
                      <ShieldAlert size={13} />
                      {d.quarantined ? "Release Quarantine" : "Quarantine Device"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card">
        <div className="card-title">
          <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <ZapOff size={18} color="var(--cyan)" />
            Short-Lived Zero Trust Sessions
          </span>
        </div>
        {sessions.length === 0 ? (
          <div style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>
            No sessions issued yet. Use the PEP Simulator's Live JWT Tester to issue a session.
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Session ID</th>
                  <th>Identity</th>
                  <th>Device</th>
                  <th>Origin</th>
                  <th>MFA</th>
                  <th>State</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((s) => (
                  <tr key={s.id}>
                    <td className="mono">{s.id.slice(0, 12)}...</td>
                    <td>{s.email}</td>
                    <td className="mono">{s.device_id}</td>
                    <td className="mono">{s.geo_location} ({s.ip_address})</td>
                    <td>
                      <span className={`badge ${s.mfa_verified ? "badge-allow" : "badge-stepup"}`}>
                        {s.mfa_verified ? "Verified" : "Pending"}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${s.active ? "badge-allow" : "badge-deny"}`}>
                        {s.active ? "ACTIVE" : s.revoked ? "REVOKED" : "EXPIRED"}
                      </span>
                    </td>
                    <td>
                      {s.active && (
                        <button className="btn btn-danger btn-sm" onClick={() => handleRevokeSession(s.id)}>
                          Revoke Now
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
