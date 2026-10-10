import { Routes, Route } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";
import NewScan from "./pages/NewScan";
import Scans from "./pages/Scans";
import Findings from "./pages/Findings";
import SecurityGate from "./pages/SecurityGate";
import Settings from "./pages/Settings";

export default function App() {
  return (
    <div className="layout">
      <Sidebar />
      <main className="content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/new-scan" element={<NewScan />} />
          <Route path="/scans" element={<Scans />} />
          <Route path="/scans/:scanId" element={<Findings />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/security-gate" element={<SecurityGate />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
    </div>
  );
}
