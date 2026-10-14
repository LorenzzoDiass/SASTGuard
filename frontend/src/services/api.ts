import type {
  Scan,
  ScanDetail,
  Finding,
  DashboardSummary,
  SeverityDistribution,
  TrendPoint,
  CriticalFile,
  LanguageDistribution,
  GateResult,
  LoginResponse,
  AuthUser,
} from "../types";

// In dev the Vite proxy forwards /api to the backend. In production the
// dashboard is served behind the same host, so a relative base works.
const BASE = import.meta.env.VITE_API_BASE_URL ?? "";

// --- auth token management -------------------------------------------------
let authToken: string | null = null;
let unauthorizedHandler: (() => void) | null = null;

export function setAuthToken(token: string | null): void {
  authToken = token;
}

/** Register a callback invoked when the API returns 401 (expired/invalid). */
export function onUnauthorized(handler: () => void): void {
  unauthorizedHandler = handler;
}

function authHeaders(extra?: Record<string, string>): Record<string, string> {
  const headers: Record<string, string> = { ...(extra ?? {}) };
  if (authToken) headers["Authorization"] = `Bearer ${authToken}`;
  return headers;
}

async function http<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: authHeaders({ "Content-Type": "application/json", ...(options?.headers as Record<string, string>) }),
  });
  if (res.status === 401 && unauthorizedHandler) {
    unauthorizedHandler();
  }
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => http<{ status: string; version: string }>("/health"),

  // --- auth ---
  login: (username: string, password: string) =>
    http<LoginResponse>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  me: () => http<AuthUser>("/api/auth/me"),
  logout: () => http<{ detail: string }>("/api/auth/logout", { method: "POST" }),

  createScan: (projectName: string, sourcePath: string, runAi = false) =>
    http<Scan>("/api/scans", {
      method: "POST",
      body: JSON.stringify({ project_name: projectName, source_path: sourcePath, run_ai: runAi }),
    }),

  uploadScan: (projectName: string, file: File, runAi = false) => {
    const form = new FormData();
    form.append("project_name", projectName);
    form.append("run_ai", String(runAi));
    form.append("file", file);
    return fetch(`${BASE}/api/scans/upload`, {
      method: "POST",
      body: form,
      headers: authHeaders(), // no Content-Type: let the browser set the multipart boundary
    }).then((r) => {
      if (r.status === 401 && unauthorizedHandler) unauthorizedHandler();
      if (!r.ok) throw new Error(`Upload failed: ${r.status}`);
      return r.json() as Promise<Scan>;
    });
  },

  listScans: () => http<Scan[]>("/api/scans"),
  getScan: (id: string) => http<ScanDetail>(`/api/scans/${id}`),

  getFindings: (
    scanId: string,
    filters: { severity?: string; file?: string; cwe?: string; engine?: string } = {}
  ) => {
    const q = new URLSearchParams();
    Object.entries(filters).forEach(([k, v]) => v && q.append(k, v));
    const qs = q.toString();
    return http<Finding[]>(`/api/scans/${scanId}/findings${qs ? `?${qs}` : ""}`);
  },

  getFinding: (id: string) => http<Finding>(`/api/findings/${id}`),
  runAiAnalysis: (id: string) =>
    http<Finding>(`/api/findings/${id}/ai-analysis`, { method: "POST" }),

  dashboardSummary: () => http<DashboardSummary>("/api/dashboard/summary"),
  dashboardSeverity: () => http<SeverityDistribution[]>("/api/dashboard/severity"),
  dashboardTrends: () => http<TrendPoint[]>("/api/dashboard/trends"),
  dashboardCriticalFiles: () => http<CriticalFile[]>("/api/dashboard/critical-files"),
  dashboardLanguages: () => http<LanguageDistribution[]>("/api/dashboard/languages"),

  evaluateGate: (scanId: string) =>
    http<GateResult>("/api/security-gate/evaluate", {
      method: "POST",
      body: JSON.stringify({ scan_id: scanId }),
    }),
};
