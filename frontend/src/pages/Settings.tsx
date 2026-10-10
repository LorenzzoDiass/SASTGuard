import { useEffect, useState } from "react";
import { api } from "../services/api";

export default function Settings() {
  const [health, setHealth] = useState<{ status: string; version: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.health().then(setHealth).catch((e) => setError(e.message));
  }, []);

  const base = import.meta.env.VITE_API_BASE_URL || "(mesma origem / proxy do Vite)";

  return (
    <div>
      <div className="page-head">
        <h1 className="page-title">Configurações</h1>
        <p className="page-sub">Status da plataforma e parâmetros de referência.</p>
      </div>

      <div className="panel" style={{ maxWidth: 680 }}>
        <h3><span className="h-accent" />Backend</h3>
        <div className="kv">
          <span className="k">API base URL</span><span className="v mono">{base}</span>
          <span className="k">Status</span>
          <span className="v">{error ? <span style={{ color: "var(--crit)" }}>indisponível</span> : (health?.status ?? "...")}</span>
          <span className="k">Versão</span><span className="v">{health?.version ?? "—"}</span>
        </div>

        <h3 style={{ marginTop: 24 }}><span className="h-accent" />Security Gate — política padrão</h3>
        <div className="kv">
          <span className="k">FAIL</span><span className="v">≥ 1 Critical ou ≥ 3 High</span>
          <span className="k">WARNING</span><span className="v">≥ 5 Medium</span>
          <span className="k">PASS</span><span className="v">caso contrário</span>
        </div>

        <h3 style={{ marginTop: 24 }}><span className="h-accent" />IA (Ollama)</h3>
        <p className="help">
          A análise com IA usa um modelo local via Ollama. Quando o Ollama está
          indisponível, a plataforma mantém a análise SAST determinística e
          informa "IA local não disponível neste ambiente".
        </p>
      </div>
    </div>
  );
}
