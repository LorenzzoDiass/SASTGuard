import { NavLink } from "react-router-dom";

const links = [
  { to: "/", label: "Dashboard", icon: "📊", end: true },
  { to: "/new-scan", label: "Nova Análise", icon: "➕" },
  { to: "/scans", label: "Scans", icon: "🗂️" },
  { to: "/findings", label: "Findings", icon: "🐛" },
  { to: "/security-gate", label: "Security Gate", icon: "🚦" },
  { to: "/settings", label: "Configurações", icon: "⚙️" },
];

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="logo" aria-hidden="true">🛡️</span>
        <span className="brand-text">
          <span className="brand-name">SASTGuard</span>
          <span className="brand-sub">Application Security</span>
        </span>
      </div>
      <div className="sidebar-divider" />
      <nav className="nav" aria-label="Navegação principal">
        {links.map((l) => (
          <NavLink
            key={l.to}
            to={l.to}
            end={l.end}
            className={({ isActive }) => (isActive ? "active" : "")}
          >
            <span className="nav-ico" aria-hidden="true">{l.icon}</span> {l.label}
          </NavLink>
        ))}
      </nav>
      <div className="sidebar-foot">
        SAST · Taint Analysis · DevSecOps
      </div>
    </aside>
  );
}
