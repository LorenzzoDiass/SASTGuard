import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../services/api";
import type { Scan, Finding } from "../types";
import { Badge } from "../components/Badge";
import { formatDate } from "../i18n";

interface ScanRow extends Scan {
  critical?: number;
  high?: number;
}

export default function Scans() {
  const nav = useNavigate();
  const [scans, setScans] = useState<ScanRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.listScans()
      .then(async (list) => {
        // Enrich with critical/high counts using the real findings endpoint.
        const enriched = await Promise.all(
          list.map(async (s) => {
            if (s.total_findings === 0) return { ...s, critical: 0, high: 0 };
            try {
              const f: Finding[] = await api.getFindings(s.id);
              return {
                ...s,
                critical: f.filter((x) => x.severity === "CRITICAL").length,
                high: f.filter((x) => x.severity === "HIGH").length,
              };
            } catch {
              return { ...s };
            }
          })
        );
        setScans(enriched);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading"><span className="spinner" /> Carregando análises...</div>;
  if (error) return <div className="empty"><span className="empty-ico">⚠️</span>Não foi possível carregar as análises: {error}</div>;

  return (
    <div>
      <div className="page-head">
        <h1 className="page-title">Scans</h1>
        <p className="page-sub">Histórico das análises de segurança realizadas.</p>
      </div>

      <div className="panel">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Projeto</th><th>Data</th><th>Status</th>
                <th>Vulnerabilidades</th><th>Critical</th><th>High</th><th>Ações</th>
              </tr>
            </thead>
            <tbody>
              {scans.length === 0 && (
                <tr><td colSpan={7} className="empty">Nenhuma análise realizada ainda.</td></tr>
              )}
              {scans.map((s) => (
                <tr key={s.id} className="clickable" onClick={() => nav(`/scans/${s.id}`)}>
                  <td>{s.project_name}</td>
                  <td>{formatDate(s.created_at)}</td>
                  <td><Badge value={s.status} kind="status" /></td>
                  <td className="num">{s.total_findings}</td>
                  <td className="num" style={{ color: s.critical ? "var(--crit)" : undefined }}>{s.critical ?? "-"}</td>
                  <td className="num" style={{ color: s.high ? "var(--high)" : undefined }}>{s.high ?? "-"}</td>
                  <td><span className="chip">Ver resultados →</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
