import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  BarChart, Bar, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer,
  LineChart, Line, Legend, CartesianGrid,
} from "recharts";
import { api } from "../services/api";
import type {
  DashboardSummary, SeverityDistribution, TrendPoint, CriticalFile,
  LanguageDistribution, Scan,
} from "../types";
import { Badge } from "../components/Badge";

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#e5484d", HIGH: "#f06a37", MEDIUM: "#e0b020", LOW: "#3aa0ff", INFO: "#8a98ad",
};

const tooltipStyle = { background: "#161e2b", border: "1px solid #2a3647", borderRadius: 8, color: "#e8eef6" };

export default function Dashboard() {
  const nav = useNavigate();
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [severity, setSeverity] = useState<SeverityDistribution[]>([]);
  const [trends, setTrends] = useState<TrendPoint[]>([]);
  const [critFiles, setCritFiles] = useState<CriticalFile[]>([]);
  const [languages, setLanguages] = useState<LanguageDistribution[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      api.dashboardSummary(),
      api.dashboardSeverity(),
      api.dashboardTrends(),
      api.dashboardCriticalFiles(),
      api.dashboardLanguages(),
      api.listScans(),
    ])
      .then(([s, sev, tr, cf, langs, sc]) => {
        setSummary(s); setSeverity(sev); setTrends(tr); setCritFiles(cf);
        setLanguages(langs); setScans(sc.slice(0, 5));
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading"><span className="spinner" /> Carregando o dashboard...</div>;
  if (error) return (
    <div className="empty">
      <span className="empty-ico">⚠️</span>
      Não foi possível conectar à API.<br />
      <span className="mono">{error}</span>
    </div>
  );
  if (!summary) return null;

  const hasData = summary.total_scans > 0;

  return (
    <div>
      <div className="page-head">
        <h1 className="page-title">Dashboard</h1>
        <p className="page-sub">Visão geral da segurança dos projetos analisados pelo SASTGuard.</p>
      </div>

      {!hasData ? (
        <div className="empty">
          <span className="empty-ico">📭</span>
          Nenhuma análise realizada ainda. Inicie uma em <b>Nova Análise</b>.
        </div>
      ) : (
        <>
          <div className="cards">
            <Card cls="total" label="Total de Vulnerabilidades" value={summary.total_vulnerabilities} color={SEV_COLORS.LOW} />
            <Card cls="crit" label="Critical" value={summary.critical} color={SEV_COLORS.CRITICAL} />
            <Card cls="high" label="High" value={summary.high} color={SEV_COLORS.HIGH} />
            <Card cls="med" label="Medium" value={summary.medium} color={SEV_COLORS.MEDIUM} />
            <Card cls="low" label="Low" value={summary.low} color={SEV_COLORS.LOW} />
          </div>

          <div className="grid-2">
            <div className="panel">
              <h3><span className="h-accent" />Severity Distribution</h3>
              <ResponsiveContainer width="100%" height={260}>
                <BarChart data={severity} margin={{ top: 4, right: 8, left: -16, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#223049" vertical={false} />
                  <XAxis dataKey="severity" stroke="#93a1b5" fontSize={12} />
                  <YAxis stroke="#93a1b5" allowDecimals={false} fontSize={12} />
                  <Tooltip cursor={{ fill: "#1d273655" }} contentStyle={tooltipStyle} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {severity.map((s) => (
                      <Cell key={s.severity} fill={SEV_COLORS[s.severity]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="panel">
              <h3><span className="h-accent" />Evolução das Vulnerabilidades</h3>
              <ResponsiveContainer width="100%" height={260}>
                <LineChart data={trends} margin={{ top: 4, right: 10, left: -16, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#223049" vertical={false} />
                  <XAxis dataKey="project_name" stroke="#93a1b5" fontSize={12} />
                  <YAxis stroke="#93a1b5" allowDecimals={false} fontSize={12} />
                  <Tooltip contentStyle={tooltipStyle} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <Line type="monotone" dataKey="critical" name="Critical" stroke={SEV_COLORS.CRITICAL} strokeWidth={2} dot={{ r: 3 }} />
                  <Line type="monotone" dataKey="high" name="High" stroke={SEV_COLORS.HIGH} strokeWidth={2} dot={{ r: 3 }} />
                  <Line type="monotone" dataKey="total" name="Total" stroke="#3b82f6" strokeWidth={2} dot={{ r: 3 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="grid-2">
            <div className="panel">
              <h3><span className="h-accent" />Arquivos Críticos</h3>
              <div className="table-wrap compact">
                <table>
                  <thead><tr><th>Arquivo</th><th>Critical</th><th>High</th><th>Total</th></tr></thead>
                  <tbody>
                    {critFiles.length === 0 && <tr><td colSpan={4} className="empty">Nenhum arquivo crítico.</td></tr>}
                    {critFiles.map((f) => (
                      <tr key={f.file_path}>
                        <td className="mono">{f.file_path}</td>
                        <td className="num">{f.critical}</td>
                        <td className="num">{f.high}</td>
                        <td className="num">{f.total}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="panel">
              <h3><span className="h-accent" />Análises Recentes</h3>
              <div className="table-wrap compact">
                <table>
                  <thead><tr><th>Projeto</th><th>Status</th><th>Vulnerabilidades</th></tr></thead>
                  <tbody>
                    {scans.length === 0 && <tr><td colSpan={3} className="empty">Nenhuma análise ainda.</td></tr>}
                    {scans.map((s) => (
                      <tr key={s.id} className="clickable" onClick={() => nav(`/scans/${s.id}`)}
                        title={`Abrir ${s.project_name}`}>
                        <td>{s.project_name}</td>
                        <td><Badge value={s.status} kind="status" /></td>
                        <td className="num">{s.total_findings}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {languages.length > 0 && (
            <div className="panel">
              <h3><span className="h-accent" />Vulnerabilidades por Linguagem</h3>
              <div className="table-wrap compact">
                <table>
                  <thead><tr><th>Linguagem</th><th>Findings</th></tr></thead>
                  <tbody>
                    {languages.map((l) => (
                      <tr key={l.language}>
                        <td>{l.label}</td>
                        <td className="num">{l.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function Card({ cls, label, value, color }: { cls: string; label: string; value: number; color: string }) {
  return (
    <div className={`card ${cls}`}>
      <div className="card-top">
        <span className="l">{label}</span>
        <span className="dot" style={{ background: color }} aria-hidden="true" />
      </div>
      <div className="n">{value}</div>
    </div>
  );
}
