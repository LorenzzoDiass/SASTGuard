import type {
  Scan,
  ScanDetail,
  Finding,
  DashboardSummary,
  SeverityDistribution,
  TrendPoint,
  CriticalFile,
  GateResult,
} from "../types";

// In dev the Vite proxy forwards /api to the backend. In production the
// dashboard is served behind the same host, so a relative base works.
const BASE = import.meta.env.VITE_API_BASE_URL ?? "";

async function http<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => http<{ status: string; version: string }>("/health"),

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
    return fetch(`${BASE}/api/scans/upload`, { method: "POST", body: form }).then((r) => {
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

  evaluateGate: (scanId: string) =>
    http<GateResult>("/api/security-gate/evaluate", {
      method: "POST",
      body: JSON.stringify({ scan_id: scanId }),
    }),
};
