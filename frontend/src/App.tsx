import { Routes, Route, Navigate } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";
import NewScan from "./pages/NewScan";
import Scans from "./pages/Scans";
import Findings from "./pages/Findings";
import SecurityGate from "./pages/SecurityGate";
import Settings from "./pages/Settings";
import Login from "./pages/Login";
import ProtectedRoute from "./auth/ProtectedRoute";

function AppLayout() {
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
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/*"
        element={
          <ProtectedRoute>
            <AppLayout />
          </ProtectedRoute>
        }
      />
    </Routes>
  );
}
