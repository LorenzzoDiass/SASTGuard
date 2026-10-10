export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type ScanStatus = "PENDING" | "RUNNING" | "COMPLETED" | "FAILED";
export type GateStatus = "PASS" | "WARNING" | "FAIL";

export interface TaintStep {
  kind: string;
  description: string;
  line: number;
  code: string;
}

export interface AIAnalysis {
  id: string;
  finding_id: string;
  available: boolean;
  model: string | null;
  ai_severity: Severity | null;
  confidence: number | null;
  possible_false_positive: boolean | null;
  explanation: string;
  impact: string;
  remediation: string;
  fixed_code: string;
  created_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  rule_id: string;
  title: string;
  description: string;
  file_path: string;
  line: number;
  column: number;
  code_snippet: string;
  severity: Severity;
  original_severity: Severity;
  confidence: number;
  cwe: string | null;
  owasp: string | null;
  recommendation: string;
  engines: string[];
  taint_path: TaintStep[] | null;
  status: string;
  created_at: string;
  ai_analysis: AIAnalysis | null;
}

export interface Scan {
  id: string;
  project_name: string;
  status: ScanStatus;
  source_path: string | null;
  error_message: string | null;
  created_at: string;
  finished_at: string | null;
  total_files: number;
  total_findings: number;
}

export interface ScanDetail extends Scan {
  findings: Finding[];
}

export interface DashboardSummary {
  total_vulnerabilities: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total_scans: number;
  last_scan_findings: number;
}

export interface SeverityDistribution {
  severity: Severity;
  count: number;
}

export interface TrendPoint {
  scan_id: string;
  project_name: string;
  created_at: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface CriticalFile {
  file_path: string;
  critical: number;
  high: number;
  total: number;
}

export interface GateResult {
  status: GateStatus;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  reasons: string[];
}
