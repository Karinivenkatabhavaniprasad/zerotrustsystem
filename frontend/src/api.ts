import type {
  AuditIntegrity,
  AuditLog,
  Device,
  Identity,
  OverviewData,
  ProtectedResource,
  SessionRecord,
  SimulationResult,
  ZeroTrustPolicy,
} from "./types";

const API_BASE = "/api";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(options?.headers || {}),
    },
    ...options,
  });
  const data = await res.json();
  if (!res.ok && !("decision" in data)) {
    throw new Error(data.error || `Request failed (${res.status})`);
  }
  return data as T;
}

export const api = {
  getOverview: () => request<OverviewData>("/overview"),
  getIdentities: () => request<{ identities: Identity[] }>("/identities"),
  updateIdentity: (id: string, body: Record<string, unknown>) =>
    request<{ identity: Identity }>(`/identities/${id}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  getDevices: () => request<{ devices: Device[] }>("/devices"),
  updateDevice: (id: string, body: Record<string, unknown>) =>
    request<{ device: Device }>(`/devices/${id}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  getResources: () => request<{ resources: ProtectedResource[] }>("/resources"),
  getPolicies: () => request<{ policies: ZeroTrustPolicy[] }>("/policies"),
  createPolicy: (body: Record<string, unknown>) =>
    request<{ policy: ZeroTrustPolicy }>("/policies", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updatePolicy: (id: string, body: Record<string, unknown>) =>
    request<{ policy: ZeroTrustPolicy }>(`/policies/${id}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  getSessions: () => request<{ sessions: SessionRecord[] }>("/sessions"),
  revokeSession: (id: string) =>
    request<{ ok: boolean }>(`/sessions/${id}/revoke`, { method: "POST" }),
  getAudit: (limit = 60) =>
    request<{ logs: AuditLog[]; integrity: AuditIntegrity }>(`/audit?limit=${limit}`),
  verifyAudit: () => request<AuditIntegrity>("/audit/verify"),
  simulatePep: (body: Record<string, unknown>) =>
    request<SimulationResult>("/pep/simulate", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  getDemoTotp: (identityId: string) =>
    request<{ identity_id: string; email: string; totp_code: string; seconds_remaining: number }>(
      `/auth/demo-totp/${identityId}`
    ),
  login: (body: Record<string, unknown>) =>
    fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }).then(async (r) => ({ status: r.status, data: await r.json() })),
  stepUpMfa: (token: string, totpCode: string) =>
    fetch(`${API_BASE}/auth/step-up`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ totp_code: totpCode }),
    }).then(async (r) => ({ status: r.status, data: await r.json() })),
  accessResource: (
    resourceId: string,
    token: string,
    headers?: Record<string, string>
  ) =>
    fetch(`${API_BASE}/resources/${resourceId}`, {
      headers: {
        Authorization: `Bearer ${token}`,
        ...(headers || {}),
      },
    }).then(async (r) => ({ status: r.status, data: await r.json() })),
};
