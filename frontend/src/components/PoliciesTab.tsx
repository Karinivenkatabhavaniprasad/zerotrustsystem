import { useState } from "react";
import { Lock, PlusCircle, SlidersHorizontal } from "lucide-react";
import { api } from "../api";
import type { ProtectedResource, ZeroTrustPolicy } from "../types";
import { DecisionBadge } from "./OverviewTab";

interface Props {
  policies: ZeroTrustPolicy[];
  resources: ProtectedResource[];
  onRefresh: () => void;
}

export function PoliciesTab({ policies, resources, onRefresh }: Props) {
  const [name, setName] = useState("");
  const [effect, setEffect] = useState<"DENY" | "STEP_UP" | "ALLOW">("DENY");
  const [priority, setPriority] = useState(35);
  const [segment, setSegment] = useState("finance");
  const [role, setRole] = useState("contractor");

  async function togglePolicy(pol: ZeroTrustPolicy) {
    await api.updatePolicy(pol.id, { enabled: !pol.enabled });
    onRefresh();
  }

  async function handleCreatePolicy(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    const conditions: Record<string, unknown> = {};
    if (segment) conditions.segments = [segment];
    if (role) conditions.roles = [role];
    await api.createPolicy({
      name: name.trim(),
      description: `Custom Zero Trust rule for ${role || "all roles"} on ${segment || "all segments"}`,
      priority,
      effect,
      conditions,
    });
    setName("");
    onRefresh();
  }

  return (
    <div>
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-title">
          <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <Lock size={18} color="var(--cyan)" />
            Micro-Segmented Protected Resources
          </span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Resource ID</th>
                <th>Name</th>
                <th>Segment</th>
                <th>Classification</th>
                <th>Min Clearance</th>
                <th>Allowed Roles</th>
                <th>Security Gates</th>
              </tr>
            </thead>
            <tbody>
              {resources.map((r) => (
                <tr key={r.id}>
                  <td className="mono">{r.id}</td>
                  <td><strong>{r.name}</strong></td>
                  <td className="mono">{r.segment}</td>
                  <td>
                    <span
                      className={`badge ${
                        r.classification === "restricted"
                          ? "badge-deny"
                          : r.classification === "confidential"
                          ? "badge-stepup"
                          : "badge-info"
                      }`}
                    >
                      {r.classification.toUpperCase()}
                    </span>
                  </td>
                  <td>Level {r.min_clearance}</td>
                  <td className="mono">{r.allowed_roles.join(", ")}</td>
                  <td>
                    {r.require_managed_device ? "MDM Required" : "Any Device"} ·{" "}
                    {r.require_mfa ? "MFA Required" : "Optional MFA"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-title">
            <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
              <SlidersHorizontal size={18} color="var(--cyan)" />
              Active PDP Policy Rules (Priority Ordered)
            </span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Pri</th>
                  <th>Policy</th>
                  <th>Effect</th>
                  <th>Conditions</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {policies.map((p) => (
                  <tr key={p.id} style={{ opacity: p.enabled ? 1 : 0.55 }}>
                    <td className="mono">{p.priority}</td>
                    <td>
                      <strong>{p.name}</strong>
                      <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>{p.description}</div>
                    </td>
                    <td>
                      <DecisionBadge decision={p.effect} />
                    </td>
                    <td className="mono">{JSON.stringify(p.conditions)}</td>
                    <td>
                      <button
                        className={`btn btn-sm ${p.enabled ? "btn-primary" : ""}`}
                        onClick={() => togglePolicy(p)}
                      >
                        {p.enabled ? "Enabled" : "Disabled"}
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
              <PlusCircle size={18} color="var(--cyan)" />
              Add Custom ABAC Zero Trust Rule
            </span>
          </div>
          <form onSubmit={handleCreatePolicy}>
            <div className="form-grid" style={{ marginBottom: 14 }}>
              <label className="field">
                Rule Name
                <input
                  value={name}
                  placeholder="e.g. Block Contractors from Finance"
                  onChange={(e) => setName(e.target.value)}
                  required
                />
              </label>
              <label className="field">
                Effect
                <select value={effect} onChange={(e) => setEffect(e.target.value as "DENY" | "STEP_UP" | "ALLOW")}>
                  <option value="DENY">DENY</option>
                  <option value="STEP_UP">STEP_UP</option>
                  <option value="ALLOW">ALLOW</option>
                </select>
              </label>
              <label className="field">
                Priority (lower runs first)
                <input
                  type="number"
                  min={1}
                  max={200}
                  value={priority}
                  onChange={(e) => setPriority(Number(e.target.value))}
                />
              </label>
              <label className="field">
                Target Segment
                <select value={segment} onChange={(e) => setSegment(e.target.value)}>
                  <option value="">Any Segment</option>
                  <option value="engineering">engineering</option>
                  <option value="finance">finance</option>
                  <option value="restricted_admin">restricted_admin</option>
                </select>
              </label>
              <label className="field">
                Target Role
                <select value={role} onChange={(e) => setRole(e.target.value)}>
                  <option value="">Any Role</option>
                  <option value="contractor">contractor</option>
                  <option value="engineer">engineer</option>
                  <option value="finance_analyst">finance_analyst</option>
                  <option value="secops_admin">secops_admin</option>
                </select>
              </label>
            </div>
            <button type="submit" className="btn btn-primary">
              <PlusCircle size={15} /> Deploy Policy to PDP
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
