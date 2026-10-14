import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../services/api";

export default function NewScan() {
  const nav = useNavigate();
  const [mode, setMode] = useState<"path" | "upload">("path");
  const [projectName, setProjectName] = useState("");
  const [sourcePath, setSourcePath] = useState("/app/vulnerable_samples");
  const [file, setFile] = useState<File | null>(null);
  const [runAi, setRunAi] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    if (!projectName.trim()) { setError("Informe o nome do projeto para continuar."); return; }
    setBusy(true); setError(null);
    try {
      const scan = mode === "path"
        ? await api.createScan(projectName, sourcePath, runAi)
        : file
          ? await api.uploadScan(projectName, file, runAi)
          : null;
      if (!scan) { setError("Selecione um arquivo de código (.py, .js, .ts, .java) ou .zip para enviar."); setBusy(false); return; }
      nav(`/scans/${scan.id}`);
    } catch (e) {
      setError(`Não foi possível concluir a análise: ${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="page-head">
        <h1 className="page-title">Nova Análise</h1>
        <p className="page-sub">Analise um projeto ou arquivo em busca de vulnerabilidades de segurança.</p>
      </div>

      <div className="panel" style={{ maxWidth: 620 }}>
        <div className="segmented" role="tablist" aria-label="Forma de análise">
          <button className={mode === "path" ? "active" : ""} onClick={() => setMode("path")}
            role="tab" aria-selected={mode === "path"}>Caminho Local</button>
          <button className={mode === "upload" ? "active" : ""} onClick={() => setMode("upload")}
            role="tab" aria-selected={mode === "upload"}>Upload</button>
        </div>

        <label htmlFor="pname">Nome do Projeto</label>
        <input id="pname" value={projectName} onChange={(e) => setProjectName(e.target.value)}
          placeholder="ex.: meu-servico-api" style={{ width: "100%" }} />

        {mode === "path" ? (
          <>
            <label htmlFor="spath">Caminho do diretório</label>
            <input id="spath" value={sourcePath} onChange={(e) => setSourcePath(e.target.value)}
              style={{ width: "100%" }} className="mono" />
            <p className="help">Analise um diretório disponível localmente para o SASTGuard.</p>
          </>
        ) : (
          <>
            <label htmlFor="sfile">Arquivo do projeto</label>
            <input id="sfile" type="file" accept=".py,.js,.jsx,.mjs,.cjs,.ts,.tsx,.java,.zip"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            <p className="help">Envie um arquivo Python (.py), JavaScript/TypeScript (.js/.ts),
              Java (.java) ou um projeto compactado (.zip).</p>
          </>
        )}

        <div className="callout info" style={{ marginTop: 20 }}>
          <b style={{ color: "var(--text)" }}>Análise complementar com IA</b>
          <p style={{ margin: "6px 0 10px" }}>
            Utiliza o modelo local configurado para revisar a severidade, avaliar
            possíveis falsos positivos e sugerir correções. A detecção é sempre
            feita pelo motor SAST (AST + Taint Analysis); a IA apenas contextualiza.
          </p>
          <label style={{ display: "flex", alignItems: "center", gap: 8, margin: 0, color: "var(--text)" }}>
            <input type="checkbox" checked={runAi} onChange={(e) => setRunAi(e.target.checked)}
              style={{ width: "auto" }} />
            Executar análise com IA após o scan
          </label>
        </div>

        {error && <div className="alert error" role="alert">{error}</div>}

        <div style={{ marginTop: 20 }}>
          <button className="btn" onClick={submit} disabled={busy}>
            {busy ? (<><span className="spinner" /> Analisando código...</>) : "Iniciar Análise"}
          </button>
        </div>
      </div>
    </div>
  );
}
