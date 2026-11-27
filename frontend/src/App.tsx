import { useCallback, useEffect, useState } from "react";
import { Activity, FileCheck2, RefreshCw, Shield, SlidersHorizontal, Users } from "lucide-react";
import { api } from "./api";
import { AuditTab } from "./components/AuditTab";
import { EntitiesTab } from "./components/EntitiesTab";
import { OverviewTab } from "./components/OverviewTab";
import { PoliciesTab } from "./components/PoliciesTab";
import { SimulatorTab } from "./components/SimulatorTab";
import type {
  AuditIntegrity,
  AuditLog,
  Device,
  Identity,
  OverviewData,
  ProtectedResource,
  SessionRecord,
  ZeroTrustPolicy,
} from "./types";

type TabId = "overview" | "simulator" | "policies" | "entities" | "audit";

export default function App() {
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const [overview, setOverview] = useState<OverviewData | null>(null);
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [resources, setResources] = useState<ProtectedResource[]>([]);
  const [policies, setPolicies] = useState<ZeroTrustPolicy[]>([]);
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [integrity, setIntegrity] = useState<AuditIntegrity | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadAll = useCallback(async () => {
    try {
      setError(null);
      const [ov, idRes, devRes, resRes, polRes, sessRes, audRes] = await Promise.all([
        api.getOverview(),
        api.getIdentities(),
        api.getDevices(),
        api.getResources(),
        api.getPolicies(),
        api.getSessions(),
        api.getAudit(80),
      ]);
      setOverview(ov);
      setIdentities(idRes.identities);
      setDevices(devRes.devices);
      setResources(resRes.resources);
      setPolicies(polRes.policies);
      setSessions(sessRes.sessions);
      setAuditLogs(audRes.logs);
      setIntegrity(audRes.integrity);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to connect to Zero Trust Control Plane");
    }
  }, []);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={22} />
          </div>
          <div>
            <h1>Zero Trust Security Command Center</h1>
            <p>NIST SP 800-207 Control Plane · Continuous Verification · Micro-Segmentation</p>
          </div>
        </div>

        <nav className="nav-tabs">
          <button
            className={`nav-tab ${activeTab === "overview" ? "active" : ""}`}
            onClick={() => setActiveTab("overview")}
          >
            <Activity size={15} /> Overview
          </button>
          <button
            className={`nav-tab ${activeTab === "simulator" ? "active" : ""}`}
            onClick={() => setActiveTab("simulator")}
          >
            <Shield size={15} /> PEP Simulator & Auth
          </button>
          <button
            className={`nav-tab ${activeTab === "policies" ? "active" : ""}`}
            onClick={() => setActiveTab("policies")}
          >
            <SlidersHorizontal size={15} /> Policies & Segments
          </button>
          <button
            className={`nav-tab ${activeTab === "entities" ? "active" : ""}`}
            onClick={() => setActiveTab("entities")}
          >
            <Users size={15} /> Identities & Devices
          </button>
          <button
            className={`nav-tab ${activeTab === "audit" ? "active" : ""}`}
            onClick={() => setActiveTab("audit")}
          >
            <FileCheck2 size={15} /> Audit Chain
          </button>
          <button className="btn btn-sm" onClick={() => void loadAll()} title="Refresh telemetry">
            <RefreshCw size={14} />
          </button>
        </nav>
      </header>

      {error && (
        <div className="alert-box" style={{ background: "var(--red-dim)", border: "1px solid rgba(239,68,68,0.4)", marginBottom: 16 }}>
          <strong>Control Plane Connection Error:</strong> {error}
        </div>
      )}

      {activeTab === "overview" && (
        <OverviewTab
          overview={overview}
          recentLogs={auditLogs}
          onQuickJumpSimulator={() => setActiveTab("simulator")}
        />
      )}
      {activeTab === "simulator" && (
        <SimulatorTab
          identities={identities}
          devices={devices}
          resources={resources}
          geos={overview?.geo_locations || ["US-SFO", "US-NYC", "UK-LON", "DE-FRA", "SG-SIN", "RU-MOW"]}
          onRefresh={() => void loadAll()}
        />
      )}
      {activeTab === "policies" && (
        <PoliciesTab
          policies={policies}
          resources={resources}
          onRefresh={() => void loadAll()}
        />
      )}
      {activeTab === "entities" && (
        <EntitiesTab
          identities={identities}
          devices={devices}
          sessions={sessions}
          onRefresh={() => void loadAll()}
        />
      )}
      {activeTab === "audit" && (
        <AuditTab
          logs={auditLogs}
          integrity={integrity}
          onIntegrityUpdate={(res) => setIntegrity(res)}
        />
      )}
    </div>
  );
}
