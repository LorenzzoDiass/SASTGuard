import { useEffect, useState } from "react";
import { api } from "../services/api";
import type { Scan, GateResult } from "../types";

export default function SecurityGate() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [scanId, setScanId] = useState("");
  const [result, setResult] = useState<GateResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.listScans().then((s) => {
      setScans(s);
      if (s.length) setScanId(s[0].id);
    }).catch((e) => setError(e.message));
  }, []);

  async function evaluate() {
    setBusy(true); setError(null);
    try {
      setResult(await api.evaluateGate(scanId));
    } catch (e) {
      setError(`Não foi possível avaliar o Security Gate: ${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  const msg = result
    ? result.status === "FAIL"
      ? "Esta análise não atende aos critérios configurados no Security Gate."
      : result.status === "PASS"
        ? "Esta análise atende aos critérios configurados no Security Gate."
        : "Esta análise atende aos critérios, mas gerou avisos (warnings)."
    : "";

  return (
    <div>
      <div className="page-head">
        <h1 className="page-title">Security Gate</h1>
        <p className="page-sub">Valide se uma análise atende aos critérios de segurança definidos para o pipeline.</p>
      </div>

      <div className="panel" style={{ maxWidth: 680 }}>
        <div className="callout" style={{ marginBottom: 16 }}>
          <b style={{ color: "var(--text)" }}>Política padrão</b>
          <div className="policy-box">
            <span className="policy-item">Falhar se <b>≥ 1 Critical</b></span>
            <span className="policy-item">ou <b>≥ 3 High</b></span>
            <span className="policy-item" style={{ color: "var(--muted)" }}>Warning se ≥ 5 Medium</span>
          </div>
        </div>

        <div className="filters">
          <select className="grow" value={scanId} onChange={(e) => setScanId(e.target.value)}
            aria-label="Selecionar análise">
            {scans.map((s) => <option key={s.id} value={s.id}>{s.project_name}</option>)}
          </select>
          <button className="btn" onClick={evaluate} disabled={!scanId || busy}>
            {busy ? (<><span className="spinner" /> Avaliando...</>) : "Avaliar Security Gate"}
          </button>
        </div>

        {error && <div className="alert error">{error}</div>}

        {result && (
          <>
            <div className={`gate-result ${result.status}`}>
              <div className="gate-status">{result.status}</div>
              <div className="gate-msg">{msg}</div>
            </div>

            <div className="cards" style={{ marginTop: 18 }}>
              <div className="card crit"><div className="card-top"><span className="l">Critical</span></div><div className="n">{result.critical}</div></div>
              <div className="card high"><div className="card-top"><span className="l">High</span></div><div className="n">{result.high}</div></div>
              <div className="card med"><div className="card-top"><span className="l">Medium</span></div><div className="n">{result.medium}</div></div>
              <div className="card low"><div className="card-top"><span className="l">Low</span></div><div className="n">{result.low}</div></div>
            </div>

            {result.reasons && result.reasons.length > 0 && (
              <div className="section">
                <h4 className="section-title"><span className="s-accent" />Motivos</h4>
                <ul className="reasons">
                  {result.reasons.map((r, i) => <li key={i}>{r}</li>)}
                </ul>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
