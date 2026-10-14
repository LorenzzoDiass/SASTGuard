import { useState } from "react";
import type { Finding } from "../types";
import { api } from "../services/api";
import { Badge } from "./Badge";

function CodeBlock({ code, startLine }: { code: string; startLine?: number }) {
  const lines = (code ?? "").split("\n");
  if (startLine && lines.length > 0) {
    return (
      <pre className="code">
        {lines.map((l, i) => (
          <div className="code-line" key={i}>
            <span className="ln">{startLine + i}</span>
            <span className="lc">{l || " "}</span>
          </div>
        ))}
      </pre>
    );
  }
  return <pre className="code plain">{code}</pre>;
}

export default function FindingModal({
  finding,
  onClose,
}: {
  finding: Finding;
  onClose: () => void;
}) {
  const [current, setCurrent] = useState<Finding>(finding);
  const [loadingAi, setLoadingAi] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  async function runAi() {
    setLoadingAi(true);
    setAiError(null);
    try {
      const updated = await api.runAiAnalysis(current.id);
      setCurrent(updated);
    } catch (e) {
      setAiError(`Não foi possível executar a análise com IA: ${(e as Error).message}`);
    } finally {
      setLoadingAi(false);
    }
  }

  const ai = current.ai_analysis;

  return (
    <div className="modal-overlay" onClick={onClose} role="dialog" aria-modal="true"
      aria-label={`Detalhe: ${current.title}`}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        {/* ---------- Header ---------- */}
        <div className="modal-head">
          <div>
            <h2>{current.title}</h2>
            <div className="sub-loc mono">{current.file_path}:{current.line}</div>
            <div className="tags">
              <Badge value={current.severity} kind="severity" />
              <span className="chip"><b>{current.rule_id}</b></span>
              {current.language && <span className="chip">Linguagem: <b>{current.language}</b></span>}
              {current.engines.map((e) => <span key={e} className="chip">Engine: <b>{e}</b></span>)}
            </div>
          </div>
          <button className="close" onClick={onClose} aria-label="Fechar">×</button>
        </div>

        {/* ---------- Summary ---------- */}
        <div className="section">
          <h4 className="section-title"><span className="s-accent" />Resumo</h4>
          <p style={{ margin: 0 }}>{current.description}</p>
        </div>

        {/* ---------- Classification ---------- */}
        <div className="section">
          <h4 className="section-title"><span className="s-accent" />Classificação</h4>
          <div className="kv">
            <span className="k">CWE</span><span className="v">{current.cwe ?? "—"}</span>
            <span className="k">OWASP</span><span className="v">{current.owasp ?? "—"}</span>
            <span className="k">Confidence</span><span className="v">{(current.confidence * 100).toFixed(0)}%</span>
            <span className="k">Engine(s)</span><span className="v">{current.engines.join(", ")}</span>
          </div>
        </div>

        {/* ---------- Code snippet ---------- */}
        <div className="section">
          <h4 className="section-title"><span className="s-accent" />Trecho de Código</h4>
          <CodeBlock code={current.code_snippet} startLine={current.line} />
        </div>

        {/* ---------- Taint path ---------- */}
        {current.taint_path && current.taint_path.length > 0 && (
          <div className="section">
            <h4 className="section-title"><span className="s-accent" />Taint Analysis — Source → Propagation → Sink</h4>
            <div className="taint-flow">
              {current.taint_path.map((s, i) => (
                <div key={i}>
                  <div className={`taint-node ${s.kind}`}>
                    <div className="t-kind">{s.kind}</div>
                    <div className="t-desc mono">{s.description}</div>
                    <div className="t-meta">
                      {s.code ? <span className="mono">{s.code}</span> : null}
                      {s.line ? <span> · linha {s.line}</span> : null}
                    </div>
                  </div>
                  {i < current.taint_path!.length - 1 && <div className="taint-arrow" aria-hidden="true">↓</div>}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ---------- How to fix ---------- */}
        <div className="section">
          <h4 className="section-title"><span className="s-accent" />Como corrigir</h4>
          <p style={{ margin: 0 }}>{current.recommendation || "Sem recomendação fornecida."}</p>
        </div>

        {/* ---------- AI analysis (clearly separated) ---------- */}
        <div className="section">
          <h4 className="section-title"><span className="s-accent" />Análise complementar com IA</h4>
          <div className="callout info" style={{ marginBottom: 12 }}>
            Análise complementar. A vulnerabilidade foi detectada pelo motor SAST;
            a IA é utilizada para contextualização e sugestão de remediação.
          </div>

          <button className="btn secondary" onClick={runAi} disabled={loadingAi}>
            {loadingAi ? (<><span className="spinner" /> Analisando...</>) : "Analisar com IA"}
          </button>

          {aiError && <div className="alert error">{aiError}</div>}

          {ai && (
            ai.available ? (
              <div style={{ marginTop: 14 }}>
                <div className="kv">
                  <span className="k">Severity original</span><span className="v">{current.original_severity}</span>
                  <span className="k">Severity sugerida (IA)</span><span className="v">{ai.ai_severity ?? "—"}</span>
                  <span className="k">Confidence</span><span className="v">{ai.confidence != null ? `${(ai.confidence * 100).toFixed(0)}%` : "—"}</span>
                  <span className="k">Possível falso positivo</span><span className="v">{ai.possible_false_positive ? "Sim" : "Não"}</span>
                </div>
                {ai.explanation && (<><h4 className="section-title" style={{ marginTop: 16 }}>Explicação</h4><p style={{ margin: 0 }}>{ai.explanation}</p></>)}
                {ai.impact && (<><h4 className="section-title" style={{ marginTop: 16 }}>Impacto</h4><p style={{ margin: 0 }}>{ai.impact}</p></>)}
                {ai.remediation && (<><h4 className="section-title" style={{ marginTop: 16 }}>Remediação</h4><p style={{ margin: 0 }}>{ai.remediation}</p></>)}
                {ai.fixed_code && (<><h4 className="section-title" style={{ marginTop: 16 }}>Código sugerido</h4><CodeBlock code={ai.fixed_code} /></>)}
              </div>
            ) : (
              <p className="help" style={{ marginTop: 12 }}>IA local não disponível neste ambiente.</p>
            )
          )}
          {!ai && !aiError && (
            <p className="help" style={{ marginTop: 12 }}>
              Nenhuma análise com IA executada ainda para este finding.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
