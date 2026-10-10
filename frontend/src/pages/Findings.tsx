import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../services/api";
import type { Finding, Scan } from "../types";
import { Badge } from "../components/Badge";
import FindingModal from "../components/FindingModal";

export default function Findings() {
  const { scanId: routeScanId } = useParams();
  const [scans, setScans] = useState<Scan[]>([]);
  const [scanId, setScanId] = useState<string>(routeScanId ?? "");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const [severity, setSeverity] = useState("");
  const [fileFilter, setFileFilter] = useState("");
  const [cwe, setCwe] = useState("");
  const [engine, setEngine] = useState("");
  const [query, setQuery] = useState("");

  useEffect(() => {
    api.listScans().then((s) => {
      setScans(s);
      if (!routeScanId && s.length > 0) setScanId(s[0].id);
    }).catch((e) => setError(e.message));
  }, [routeScanId]);

  useEffect(() => {
    if (!scanId) return;
    setLoading(true);
    api.getFindings(scanId, { severity, file: fileFilter, cwe, engine })
      .then(setFindings)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [scanId, severity, fileFilter, cwe, engine]);

  const engines = useMemo(() => {
    const set = new Set<string>();
    findings.forEach((f) => f.engines.forEach((e) => set.add(e)));
    return Array.from(set);
  }, [findings]);

  // Client-side free-text search over already-loaded findings (no backend change).
  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return findings;
    return findings.filter((f) =>
      [f.title, f.file_path, f.cwe ?? "", f.rule_id].join(" ").toLowerCase().includes(q)
    );
  }, [findings, query]);

  return (
    <div>
      <div className="page-head">
        <h1 className="page-title">Findings</h1>
        <p className="page-sub">Vulnerabilidades identificadas durante a análise estática do código.</p>
      </div>

      {error && <div className="alert error">{error}</div>}

      <div className="filters">
        <div className="search-box">
          <span className="search-ico" aria-hidden="true">🔎</span>
          <input placeholder="Buscar por vulnerabilidade, arquivo, CWE ou regra..."
            value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Buscar findings" />
        </div>
        <select value={scanId} onChange={(e) => setScanId(e.target.value)} aria-label="Selecionar análise">
          {scans.map((s) => (
            <option key={s.id} value={s.id}>{s.project_name} ({s.total_findings})</option>
          ))}
        </select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Filtrar por Severity">
          <option value="">Severity: todas</option>
          {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <input placeholder="Arquivo" value={fileFilter} onChange={(e) => setFileFilter(e.target.value)}
          aria-label="Filtrar por arquivo" />
        <input placeholder="CWE" value={cwe} onChange={(e) => setCwe(e.target.value)}
          aria-label="Filtrar por CWE" style={{ maxWidth: 120 }} />
        <select value={engine} onChange={(e) => setEngine(e.target.value)} aria-label="Filtrar por Engine">
          <option value="">Engine: todas</option>
          {engines.map((e) => <option key={e}>{e}</option>)}
        </select>
      </div>

      <div className="panel">
        {loading ? (
          <div className="loading"><span className="spinner" /> Carregando findings...</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Severity</th><th>Vulnerabilidade</th><th>Arquivo</th><th>Linha</th>
                  <th>CWE</th><th>Engine</th>
                </tr>
              </thead>
              <tbody>
                {visible.length === 0 && (
                  <tr><td colSpan={6} className="empty">
                    {findings.length === 0 ? "Nenhuma vulnerabilidade nesta análise." : "Nenhum finding corresponde aos filtros."}
                  </td></tr>
                )}
                {visible.map((f) => (
                  <tr key={f.id} className="clickable" onClick={() => setSelected(f)}>
                    <td><Badge value={f.severity} kind="severity" /></td>
                    <td>{f.title}</td>
                    <td className="mono">{f.file_path}</td>
                    <td className="num">{f.line}</td>
                    <td>{f.cwe ?? "-"}</td>
                    <td>{f.engines.join(" + ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selected && <FindingModal finding={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
