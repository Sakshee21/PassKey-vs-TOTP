import { useEffect, useState } from "react";
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from "react-router-dom";
import { me } from "./lib/auth";
import { clearToken, getToken } from "./lib/api";
import { AuthPage } from "./pages/AuthPage";
import { Dashboard } from "./pages/Dashboard";
import { RegisterWizard, primeRegistrationResume } from "./pages/RegisterWizard";
import { RecoveryFlow } from "./pages/RecoveryFlow";
import type { User } from "./lib/types";

function useSession() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!getToken()) {
      setLoading(false);
      return;
    }
    me()
      .then(setUser)
      .catch(() => clearToken())
      .finally(() => setLoading(false));
  }, []);

  function refresh() {
    setLoading(true);
    return me()
      .then(setUser)
      .finally(() => setLoading(false));
  }

  function logout() {
    clearToken();
    setUser(null);
  }

  return { user, loading, refresh, logout };
}

function LoginRoute({ onAuthenticated }: { onAuthenticated: () => Promise<void> }) {
  const navigate = useNavigate();
  return (
    <AuthPage
      onAuthenticated={() => onAuthenticated().then(() => navigate("/dashboard"))}
      onResumeRegistration={(token, email) => {
        primeRegistrationResume(token, email);
        navigate("/register");
      }}
      onWantsRegister={() => navigate("/register")}
      onWantsRecovery={(email) => navigate("/recovery", { state: { email } })}
    />
  );
}

function RegisterRoute({ onComplete }: { onComplete: () => Promise<void> }) {
  const navigate = useNavigate();
  return (
    <RegisterWizard
      onComplete={() => onComplete().then(() => navigate("/dashboard"))}
      onBackToLogin={() => navigate("/")}
    />
  );
}

function RecoveryRoute({ onComplete }: { onComplete: () => Promise<void> }) {
  const navigate = useNavigate();
  const location = useLocation();
  const prefillEmail = (location.state as { email?: string } | null)?.email;
  return (
    <RecoveryFlow
      prefillEmail={prefillEmail}
      onComplete={() => onComplete().then(() => navigate("/dashboard"))}
      onCancel={() => navigate("/")}
    />
  );
}

function ProtectedRoute({
  user,
  loading,
  children,
}: {
  user: User | null;
  loading: boolean;
  children: React.ReactNode;
}) {
  if (loading) return <p className="hint">Loading…</p>;
  if (!user) return <Navigate to="/" replace />;
  return <>{children}</>;
}

function App() {
  const { user, loading, refresh, logout } = useSession();

  return (
    <BrowserRouter>
      <h1>PassKey vs TOTP</h1>
      <Routes>
        <Route
          path="/"
          element={
            loading ? (
              <p className="hint">Loading…</p>
            ) : user ? (
              <Navigate to="/dashboard" replace />
            ) : (
              <LoginRoute onAuthenticated={refresh} />
            )
          }
        />
        <Route
          path="/register"
          element={user ? <Navigate to="/dashboard" replace /> : <RegisterRoute onComplete={refresh} />}
        />
        <Route path="/recovery" element={<RecoveryRoute onComplete={refresh} />} />
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute user={user} loading={loading}>
              <Dashboard user={user as User} onLogout={logout} />
            </ProtectedRoute>
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
