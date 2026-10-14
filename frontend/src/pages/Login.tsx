import { useState } from "react";
import type { FormEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

export default function Login() {
  const { login } = useAuth();
  const nav = useNavigate();
  const location = useLocation() as { state?: { from?: { pathname?: string } } };
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError("Informe usuário e senha.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await login(username.trim(), password);
      const dest = location.state?.from?.pathname ?? "/";
      nav(dest, { replace: true });
    } catch (err) {
      // 401 -> credenciais inválidas; outros -> mensagem crua.
      const msg = (err as Error).message;
      setError(
        msg.includes("401")
          ? "Usuário ou senha inválidos."
          : `Não foi possível entrar: ${msg}`
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit} aria-label="Entrar no SASTGuard">
        <div className="login-brand">
          <span className="logo" aria-hidden="true">🛡️</span>
          <div>
            <div className="brand-name">SASTGuard</div>
            <div className="brand-sub">Application Security</div>
          </div>
        </div>

        <h1 className="login-title">Entrar</h1>
        <p className="login-sub">Acesse o painel de segurança da plataforma.</p>

        <label htmlFor="username">Usuário</label>
        <input
          id="username"
          autoComplete="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          disabled={busy}
          autoFocus
        />

        <label htmlFor="password">Senha</label>
        <input
          id="password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={busy}
        />

        {error && <div className="alert error" role="alert">{error}</div>}

        <button className="btn" type="submit" disabled={busy} style={{ marginTop: 16, width: "100%" }}>
          {busy ? (<><span className="spinner" /> Entrando...</>) : "Entrar"}
        </button>
      </form>
    </div>
  );
}
