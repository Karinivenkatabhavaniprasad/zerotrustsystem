import { useState } from "react";
import { AlertTriangle, KeyRound, Play, Shield, Terminal } from "lucide-react";
import { api } from "../api";
import type { Device, Identity, ProtectedResource, SimulationResult } from "../types";
import { DecisionBadge } from "./OverviewTab";

interface Props {
  identities: Identity[];
  devices: Device[];
  resources: ProtectedResource[];
  geos: string[];
  onRefresh: () => void;
}

export function SimulatorTab({ identities, devices, resources, geos, onRefresh }: Props) {
  const [identityId, setIdentityId] = useState("id-alice");
  const [deviceId, setDeviceId] = useState("dev-mac-alice");
  const [resourceId, setResourceId] = useState("prod-k8s");
  const [ipAddress, setIpAddress] = useState("10.24.1.15");
  const [geoLocation, setGeoLocation] = useState("US-SFO");
  const [mfaVerified, setMfaVerified] = useState(true);
  const [hourUtc, setHourUtc] = useState(14);
  const [simResult, setSimResult] = useState<SimulationResult | null>(null);
  const [simLoading, setSimLoading] = useState(false);

  // Live JWT + Step-Up Auth Tester state
  const [loginEmail, setLoginEmail] = useState("alice@corp.local");
  const [loginPassword, setLoginPassword] = useState("ZeroTrust!2026");
  const [loginDevice, setLoginDevice] = useState("dev-mac-alice");
  const [loginGeo, setLoginGeo] = useState("US-SFO");
  const [token, setToken] = useState<string | null>(null);
  const [liveResource, setLiveResource] = useState("prod-k8s");
  const [totpCode, setTotpCode] = useState("");
  const [liveLog, setLiveLog] = useState<Record<string, unknown> | null>(null);
  const [liveError, setLiveError] = useState<string | null>(null);

  async function runSimulation() {
    setSimLoading(true);
    try {
      const res = await api.simulatePep({
        identity_id: identityId,
        device_id: deviceId,
        resource_id: resourceId,
        ip_address: ipAddress,
        geo_location: geoLocation,
        mfa_verified: mfaVerified,
        hour_utc: hourUtc,
        record_audit: true,
      });
      setSimResult(res);
      onRefresh();
    } finally {
      setSimLoading(false);
    }
  }

  function applyScenario(preset: "legit" | "stepup" | "impossible_travel" | "unmanaged_byod") {
    if (preset === "legit") {
      setIdentityId("id-alice");
      setDeviceId("dev-mac-alice");
      setResourceId("prod-k8s");
      setIpAddress("10.24.1.15");
      setGeoLocation("US-SFO");
      setMfaVerified(true);
      setHourUtc(14);
    } else if (preset === "stepup") {
      setIdentityId("id-bob");
      setDeviceId("dev-win-bob");
      setResourceId("finance-ledger");
      setIpAddress("10.30.2.10");
      setGeoLocation("US-NYC");
      setMfaVerified(false);
      setHourUtc(15);
    } else if (preset === "impossible_travel") {
      setIdentityId("id-admin");
      setDeviceId("dev-linux-admin");
      setResourceId("iam-vault");
      setIpAddress("185.220.101.42");
      setGeoLocation("SG-SIN");
      setMfaVerified(true);
      setHourUtc(3);
    } else {
      setIdentityId("id-contractor");
      setDeviceId("dev-byod-untrusted");
      setResourceId("finance-ledger");
      setIpAddress("172.16.40.9");
      setGeoLocation("DE-FRA");
      setMfaVerified(true);
      setHourUtc(11);
    }
  }

  async function handleLogin() {
    setLiveError(null);
    const res = await api.login({
      email: loginEmail,
      password: loginPassword,
      device_id: loginDevice,
      geo_location: loginGeo,
    });
    setLiveLog(res.data);
    if (res.status === 200 && res.data.access_token) {
      setToken(res.data.access_token);
    } else {
      setLiveError(res.data.error || "Login failed");
    }
    onRefresh();
  }

  async function handleFetchDemoTotp() {
    const match = identities.find((i) => i.email === loginEmail);
    if (!match) return;
    const res = await api.getDemoTotp(match.id);
    setTotpCode(res.totp_code);
  }

  async function handleAccessResource() {
    if (!token) return;
    setLiveError(null);
    const res = await api.accessResource(liveResource, token);
    setLiveLog(res.data);
    onRefresh();
  }

  async function handleStepUp() {
    if (!token || !totpCode) return;
    setLiveError(null);
    const res = await api.stepUpMfa(token, totpCode);
    setLiveLog(res.data);
    if (res.status !== 200) {
      setLiveError(res.data.error || "Step-up failed");
    }
    onRefresh();
  }

  return (
    <div className="grid-2">
      <div className="card">
        <div className="card-title">
          <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <Shield size={18} color="var(--cyan)" />
            PEP / PDP Policy Access Simulator
          </span>
        </div>

        <div className="pill-row" style={{ marginBottom: 14 }}>
          <button className="btn btn-sm" onClick={() => applyScenario("legit")}>
            Scenario: Verified Engineer
          </button>
          <button className="btn btn-sm" onClick={() => applyScenario("stepup")}>
            Scenario: Missing MFA (Step-Up)
          </button>
          <button className="btn btn-sm" onClick={() => applyScenario("impossible_travel")}>
            Scenario: Impossible Travel + Tor
          </button>
          <button className="btn btn-sm" onClick={() => applyScenario("unmanaged_byod")}>
            Scenario: Unmanaged BYOD
          </button>
        </div>

        <div className="form-grid" style={{ marginBottom: 14 }}>
          <label className="field">
            Identity
            <select value={identityId} onChange={(e) => setIdentityId(e.target.value)}>
              {identities.map((i) => (
                <option key={i.id} value={i.id}>
                  {i.email} ({i.role}, L{i.clearance_level})
                </option>
              ))}
            </select>
          </label>

          <label className="field">
            Endpoint Device
            <select value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
              {devices.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.device_name} (Trust {d.trust_score})
                </option>
              ))}
            </select>
          </label>

          <label className="field">
            Target Micro-Segment
            <select value={resourceId} onChange={(e) => setResourceId(e.target.value)}>
              {resources.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name} ({r.classification})
                </option>
              ))}
            </select>
          </label>

          <label className="field">
            Source IP Address
            <input value={ipAddress} onChange={(e) => setIpAddress(e.target.value)} />
          </label>

          <label className="field">
            Geo Location
            <select value={geoLocation} onChange={(e) => setGeoLocation(e.target.value)}>
              {geos.map((g) => (
                <option key={g} value={g}>
                  {g}
                </option>
              ))}
            </select>
          </label>

          <label className="field">
            UTC Hour ({hourUtc}:00)
            <input
              type="range"
              min={0}
              max={23}
              value={hourUtc}
              onChange={(e) => setHourUtc(Number(e.target.value))}
            />
          </label>
        </div>

        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
          <label style={{ display: "inline-flex", alignItems: "center", gap: 8, fontSize: "0.85rem" }}>
            <input
              type="checkbox"
              checked={mfaVerified}
              onChange={(e) => setMfaVerified(e.target.checked)}
            />
            Fresh TOTP MFA Verified
          </label>

          <button className="btn btn-primary" onClick={runSimulation} disabled={simLoading}>
            <Play size={15} />
            {simLoading ? "Evaluating..." : "Evaluate Zero Trust Request"}
          </button>
        </div>

        {simResult && (
          <div style={{ marginTop: 18, borderTop: "1px solid var(--border)", paddingTop: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <div>
                <div className="stat-label">Enforcement Verdict</div>
                <div style={{ marginTop: 4, display: "flex", alignItems: "center", gap: 10 }}>
                  <DecisionBadge decision={simResult.decision} />
                  <span className="mono" style={{ color: "var(--text-muted)" }}>
                    matched: {simResult.matched_policy}
                  </span>
                </div>
              </div>
              <div style={{ textAlign: "right" }}>
                <div className="stat-label">Risk / Device Trust</div>
                <div className="mono" style={{ fontSize: "1rem", fontWeight: 700 }}>
                  Risk {simResult.risk_score}/100 · Trust {simResult.device_trust_score}/100
                </div>
              </div>
            </div>

            <div className="alert-box" style={{ background: "var(--bg-elevated)", border: "1px solid var(--border)" }}>
              <strong>Reason:</strong> {simResult.reason}
              {simResult.resource_preview && (
                <div className="mono" style={{ marginTop: 8, color: "var(--green)" }}>
                  Unlocked Payload: {simResult.resource_preview}
                </div>
              )}
            </div>

            {simResult.anomalies.length > 0 && (
              <div className="alert-box" style={{ background: "var(--red-dim)", border: "1px solid rgba(239,68,68,0.4)" }}>
                <AlertTriangle size={14} style={{ verticalAlign: "middle", marginRight: 6 }} />
                <strong>Anomalies Flagged:</strong> {simResult.anomalies.join(", ")}
              </div>
            )}

            {simResult.risk_factors.length > 0 && (
              <div style={{ marginTop: 12 }}>
                <div className="stat-label" style={{ marginBottom: 6 }}>Continuous Risk Breakdown</div>
                {simResult.risk_factors.map((f) => (
                  <div key={f.code} className="trace-item">
                    <span>
                      <strong className="mono">{f.code}</strong> — {f.description}
                    </span>
                    <span className="badge badge-deny">+{f.delta}</span>
                  </div>
                ))}
              </div>
            )}

            <div style={{ marginTop: 12 }}>
              <div className="stat-label" style={{ marginBottom: 6 }}>PDP Gate & Policy Trace</div>
              {simResult.rule_trace.map((t, idx) => (
                <div key={idx} className="trace-item">
                  <span>
                    <strong className="mono">{t.gate}</strong>{" "}
                    <span style={{ color: "var(--text-muted)" }}>({t.detail})</span>
                  </span>
                  <span
                    className={`badge ${
                      t.result === "FAIL" || t.effect === "DENY"
                        ? "badge-deny"
                        : t.result === "PASS" || t.effect === "ALLOW"
                        ? "badge-allow"
                        : "badge-info"
                    }`}
                  >
                    {t.result}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-title">
          <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <KeyRound size={18} color="var(--cyan)" />
            Live JWT + Step-Up TOTP Flow Tester
          </span>
        </div>
        <p style={{ fontSize: "0.82rem", color: "var(--text-muted)", marginTop: 0 }}>
          Test real end-to-end authentication: log in without MFA (default password{" "}
          <code className="mono">ZeroTrust!2026</code>), attempt to access a restricted micro-segment,
          receive a <code className="mono">STEP_UP_MFA_REQUIRED</code> challenge, and elevate with a live RFC 6238 TOTP code.
        </p>

        <div className="form-grid" style={{ marginBottom: 12 }}>
          <label className="field">
            Identity Email
            <select value={loginEmail} onChange={(e) => setLoginEmail(e.target.value)}>
              {identities.map((i) => (
                <option key={i.id} value={i.email}>
                  {i.email}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            Password
            <input
              type="password"
              value={loginPassword}
              onChange={(e) => setLoginPassword(e.target.value)}
            />
          </label>
          <label className="field">
            Device
            <select value={loginDevice} onChange={(e) => setLoginDevice(e.target.value)}>
              {devices.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.id}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            Origin Geo
            <select value={loginGeo} onChange={(e) => setLoginGeo(e.target.value)}>
              {geos.map((g) => (
                <option key={g} value={g}>
                  {g}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="pill-row" style={{ marginBottom: 14 }}>
          <button className="btn btn-primary" onClick={handleLogin}>
            1. Issue Short-Lived JWT
          </button>
          <button className="btn" onClick={handleFetchDemoTotp}>
            Generate Demo TOTP
          </button>
        </div>

        {token && (
          <div style={{ marginBottom: 14, padding: 12, background: "var(--bg-elevated)", borderRadius: 8, border: "1px solid var(--border)" }}>
            <div className="stat-label" style={{ marginBottom: 6 }}>Active Bearer Token</div>
            <div className="mono" style={{ wordBreak: "break-all", color: "var(--cyan)", marginBottom: 10 }}>
              {token.slice(0, 72)}...
            </div>
            <div className="form-grid">
              <label className="field">
                Call Protected Endpoint (/api/resources/...)
                <select value={liveResource} onChange={(e) => setLiveResource(e.target.value)}>
                  {resources.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.id} ({r.classification})
                    </option>
                  ))}
                </select>
              </label>
              <label className="field">
                TOTP Code (6 digits)
                <input
                  value={totpCode}
                  placeholder="123456"
                  onChange={(e) => setTotpCode(e.target.value)}
                />
              </label>
            </div>
            <div className="pill-row" style={{ marginTop: 10 }}>
              <button className="btn btn-primary btn-sm" onClick={handleAccessResource}>
                2. Request Protected Resource
              </button>
              <button className="btn btn-sm" onClick={handleStepUp} disabled={!totpCode}>
                3. Submit Step-Up MFA
              </button>
            </div>
          </div>
        )}

        {liveError && (
          <div className="alert-box" style={{ background: "var(--red-dim)", border: "1px solid rgba(239,68,68,0.4)" }}>
            {liveError}
          </div>
        )}

        {liveLog && (
          <div style={{ marginTop: 12 }}>
            <div className="stat-label" style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
              <Terminal size={13} /> Gateway Response
            </div>
            <pre
              className="mono"
              style={{
                background: "#060910",
                border: "1px solid var(--border)",
                padding: 12,
                borderRadius: 8,
                overflowX: "auto",
                maxHeight: 280,
                margin: 0,
              }}
            >
              {JSON.stringify(liveLog, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
