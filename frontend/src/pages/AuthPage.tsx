import { useState } from "react";
import {
  authenticateWithPasskey,
  completeLogin,
  persistSession,
  verifyBackupCodeFirst,
  verifyTotpFirst,
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
  const [code, setCode] = useState("");
  const [backupCode, setBackupCode] = useState("");
  const [useBackupCode, setUseBackupCode] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Set once the second factor (TOTP/backup code) has been verified — the
  // password is only asked for after this, by design.
  const [passwordToken, setPasswordToken] = useState<string | null>(null);
  const [lowCodesWarning, setLowCodesWarning] = useState<number | null>(null);
  const [password, setPassword] = useState("");

  async function handleSecondFactorSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      let passwordTokenResult: string | null;
      let remaining: number | null = null;
      if (useBackupCode) {
        const result = await verifyBackupCodeFirst(email, backupCode);
        if (result.registration_incomplete && result.registration_token) {
          onResumeRegistration(result.registration_token, email);
          return;
        }
        passwordTokenResult = result.password_token;
        remaining = result.backup_codes_remaining;
      } else {
        const result = await verifyTotpFirst(email, code);
        if (result.registration_incomplete && result.registration_token) {
          onResumeRegistration(result.registration_token, email);
          return;
        }
        passwordTokenResult = result.password_token;
      }
      if (passwordTokenResult) {
        setPasswordToken(passwordTokenResult);
        if (remaining !== null && remaining < 3) setLowCodesWarning(remaining);
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Invalid code");
    } finally {
      setBusy(false);
    }
  }

  async function handlePasswordSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!passwordToken) return;
    setError(null);
    setBusy(true);
    try {
      const token = await completeLogin(passwordToken, password);
      persistSession(token);
      onAuthenticated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Incorrect password");
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

  if (passwordToken) {
    return (
      <div className="card">
        <h2>Enter your password</h2>
        {lowCodesWarning !== null && (
          <p className="error">
            Only {lowCodesWarning} backup code{lowCodesWarning === 1 ? "" : "s"} left — regenerate
            them from your dashboard once you're signed in.
          </p>
        )}
        <form onSubmit={handlePasswordSubmit}>
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoFocus
          />
          {error && <p className="error">{error}</p>}
          <button type="submit" disabled={busy}>
            Sign in
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className="card">
      <h2>Sign in</h2>
      <form onSubmit={handleSecondFactorSubmit}>
        <input
          type="email"
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        {useBackupCode ? (
          <input
            placeholder="Backup code"
            value={backupCode}
            onChange={(e) => setBackupCode(e.target.value)}
          />
        ) : (
          <input
            placeholder="6-digit authenticator code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            inputMode="numeric"
          />
        )}
        {error && <p className="error">{error}</p>}
        <button type="submit" disabled={busy}>
          Continue
        </button>
        <button type="button" className="secondary" onClick={() => setUseBackupCode((v) => !v)}>
          {useBackupCode ? "Use authenticator code instead" : "Use a backup code instead"}
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
