import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "./AuthContext";

/** Gate for authenticated areas. Redirects to /login when there is no session. */
export default function ProtectedRoute({ children }: { children: ReactNode }) {
  const { user, token, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="loading" style={{ height: "100vh" }}>
        <span className="spinner" /> Verificando sessão...
      </div>
    );
  }

  // A valid session requires both a token and a resolved user.
  if (!token || !user) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  return <>{children}</>;
}
