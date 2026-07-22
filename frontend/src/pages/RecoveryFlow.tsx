import { useState } from "react";
import {
  login,
  persistSession,
  registerPasskey,
  verifyBackupCode,
  verifyTotp,
} from "../lib/auth";
import { ApiError } from "../lib/api";

interface Props {
  prefillEmail?: string;
  onComplete: () => void;
  onCancel: () => void;
}

type Phase = "verify" | "verified";

const LOW_BACKUP_CODES_THRESHOLD = 3;

export function RecoveryFlow({ prefillEmail, onComplete, onCancel }: Props) {
  const [phase, setPhase] = useState<Phase>("verify");
  const [email, setEmail] = useState(prefillEmail ?? "");
  const [password, setPassword] = useState("");
  const [loginToken, setLoginToken] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [backupCode, setBackupCode] = useState("");
  const [useBackupCode, setUseBackupCode] = useState(false);
  const [lowCodesWarning, setLowCodesWarning] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [passkeyRegistered, setPasskeyRegistered] = useState(false);

  async function handlePasswordSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const result = await login(email, password);
      if (result.token) {
        persistSession(result.token);
        setPhase("verified");
      } else if (result.totp_required && result.login_token) {
        setLoginToken(result.login_token);
      } else {
        setError("This account hasn't finished the registration wizard yet.");
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  }

  async function handleVerifySubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!loginToken) return;
    setError(null);
    setBusy(true);
    try {
      if (useBackupCode) {
        const result = await verifyBackupCode(loginToken, backupCode);
        persistSession(result);
        if (result.backup_codes_remaining < LOW_BACKUP_CODES_THRESHOLD) {
          setLowCodesWarning(result.backup_codes_remaining);
        }
      } else {
        const token = await verifyTotp(loginToken, totpCode);
        persistSession(token);
      }
      setPhase("verified");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Invalid code");
    } finally {
      setBusy(false);
    }
  }

  async function handleRegisterPasskey() {
    setError(null);
    setBusy(true);
    try {
      await registerPasskey();
      setPasskeyRegistered(true);
    } catch (err) {
      console.error("Passkey registration failed:", err);
      setError(err instanceof ApiError ? err.message : "Passkey ceremony failed or was cancelled");
    } finally {
      setBusy(false);
    }
  }

  if (phase === "verified") {
    return (
      <div className="card">
        <h2>Identity verified</h2>
        {lowCodesWarning !== null && (
          <p className="error">
            Only {lowCodesWarning} backup code{lowCodesWarning === 1 ? "" : "s"} left — regenerate
            them from your dashboard once you're back in.
          </p>
        )}
        {passkeyRegistered ? (
          <>
            <p>New passkey registered.</p>
            <button onClick={onComplete}>Continue to dashboard</button>
          </>
        ) : (
          <>
            <p className="hint">
              Register a new passkey now so you can sign in without your password next time.
            </p>
            {error && <p className="error">{error}</p>}
            <button onClick={handleRegisterPasskey} disabled={busy}>
              Register a new passkey
            </button>
            <button className="secondary" onClick={onComplete} style={{ marginTop: "0.5rem" }}>
              Skip for now
            </button>
          </>
        )}
      </div>
    );
  }

  if (loginToken) {
    return (
      <div className="card">
        <h2>Verify it's you</h2>
        <form onSubmit={handleVerifySubmit}>
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
          <button type="button" className="secondary" onClick={() => setUseBackupCode((v) => !v)}>
            {useBackupCode ? "Use authenticator code instead" : "Use a backup code instead"}
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className="card">
      <h2>Lost your passkey?</h2>
      <p className="hint">
        Sign in with your password to verify it's you, then register a new passkey.
      </p>
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
        />
        {error && <p className="error">{error}</p>}
        <button type="submit" disabled={busy}>
          Verify identity
        </button>
      </form>
      <button
        className="secondary"
        onClick={onCancel}
        style={{ marginTop: "0.75rem", border: "none", textDecoration: "underline", padding: 0 }}
      >
        Back to sign in
      </button>
    </div>
  );
}
