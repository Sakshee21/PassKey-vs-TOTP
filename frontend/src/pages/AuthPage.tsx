import { useState } from "react";
import {
  authenticateWithPasskey,
  login,
  persistSession,
  verifyBackupCode,
  verifyTotp,
} from "../lib/auth";
import { ApiError } from "../lib/api";

interface Props {
  onAuthenticated: () => void;
  onResumeRegistration: (registrationToken: string, email: string) => void;
  onWantsRegister: () => void;
  onWantsRecovery: (email: string) => void;
}

export function AuthPage({
  onAuthenticated,
  onResumeRegistration,
  onWantsRegister,
  onWantsRecovery,
}: Props) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Set once a password login says TOTP is required.
  const [loginToken, setLoginToken] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [backupCode, setBackupCode] = useState("");
  const [useBackupCode, setUseBackupCode] = useState(false);

  async function handlePasswordSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const result = await login(email, password);
      if (result.registration_incomplete && result.registration_token) {
        onResumeRegistration(result.registration_token, email);
      } else if (result.totp_required && result.login_token) {
        setLoginToken(result.login_token);
      } else if (result.token) {
        persistSession(result.token);
        onAuthenticated();
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  }

  async function handleTotpSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!loginToken) return;
    setError(null);
    setBusy(true);
    try {
      const token = useBackupCode
        ? await verifyBackupCode(loginToken, backupCode)
        : await verifyTotp(loginToken, totpCode);
      persistSession(token);
      onAuthenticated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Invalid code");
    } finally {
      setBusy(false);
    }
  }

  async function handlePasskeyAuth() {
    if (!email) {
      setError("Enter your email first");
      return;
    }
    setError(null);
    setBusy(true);
    try {
      const token = await authenticateWithPasskey(email);
      persistSession(token);
      onAuthenticated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Passkey ceremony failed or was cancelled");
    } finally {
      setBusy(false);
    }
  }

  if (loginToken) {
    return (
      <div className="card">
        <h2>Two-factor authentication</h2>
        <form onSubmit={handleTotpSubmit}>
          {useBackupCode ? (
            <input
              placeholder="Backup code"
              value={backupCode}
              onChange={(e) => setBackupCode(e.target.value)}
              autoFocus
            />
          ) : (
            <input
              placeholder="6-digit authenticator code"
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value)}
              inputMode="numeric"
              autoFocus
            />
          )}
          {error && <p className="error">{error}</p>}
          <button type="submit" disabled={busy}>
            Verify
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => setUseBackupCode((v) => !v)}
          >
            {useBackupCode ? "Use authenticator code instead" : "Use a backup code instead"}
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className="card">
      <h2>Sign in</h2>
      <form onSubmit={handlePasswordSubmit}>
        <input
          type="email"
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          minLength={8}
        />
        {error && <p className="error">{error}</p>}
        <button type="submit" disabled={busy}>
          Sign in with password
        </button>
      </form>

      <p className="hint">or</p>
      <button className="secondary" onClick={handlePasskeyAuth} disabled={busy}>
        Sign in with passkey
      </button>
      <p className="hint" style={{ marginTop: "0.4rem" }}>
        <button
          className="secondary"
          style={{ padding: 0, border: "none", textDecoration: "underline", fontSize: "0.85rem" }}
          onClick={() => onWantsRecovery(email)}
        >
          Lost your passkey?
        </button>
      </p>

      <p className="hint" style={{ marginTop: "1rem" }}>
        No account yet?{" "}
        <button
          className="secondary"
          style={{ padding: 0, border: "none", textDecoration: "underline" }}
          onClick={onWantsRegister}
        >
          Register
        </button>
      </p>
    </div>
  );
}
