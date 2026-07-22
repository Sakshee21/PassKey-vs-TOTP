import { useState } from "react";
import {
  completeLogin,
  persistSession,
  registerPasskey,
  verifyBackupCodeFirst,
  verifyTotpFirst,
} from "../lib/auth";
import { ApiError } from "../lib/api";

interface Props {
  prefillEmail?: string;
  onComplete: () => void;
  onCancel: () => void;
}

type Phase = "code" | "password" | "verified";

const LOW_BACKUP_CODES_THRESHOLD = 3;

export function RecoveryFlow({ prefillEmail, onComplete, onCancel }: Props) {
  const [phase, setPhase] = useState<Phase>("code");
  const [email, setEmail] = useState(prefillEmail ?? "");
  const [code, setCode] = useState("");
  const [backupCode, setBackupCode] = useState("");
  const [useBackupCode, setUseBackupCode] = useState(false);
  const [passwordToken, setPasswordToken] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [lowCodesWarning, setLowCodesWarning] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [passkeyRegistered, setPasskeyRegistered] = useState(false);

  async function handleSecondFactorSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      let passwordTokenResult: string | null;
      let remaining: number | null = null;
      if (useBackupCode) {
        const result = await verifyBackupCodeFirst(email, backupCode);
        if (result.registration_incomplete) {
          setError("This account hasn't finished the registration wizard yet.");
          return;
        }
        passwordTokenResult = result.password_token;
        remaining = result.backup_codes_remaining;
      } else {
        const result = await verifyTotpFirst(email, code);
        if (result.registration_incomplete) {
          setError("This account hasn't finished the registration wizard yet.");
          return;
        }
        passwordTokenResult = result.password_token;
      }
      if (passwordTokenResult) {
        setPasswordToken(passwordTokenResult);
        if (remaining !== null && remaining < LOW_BACKUP_CODES_THRESHOLD) {
          setLowCodesWarning(remaining);
        }
        setPhase("password");
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
      setPhase("verified");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Incorrect password");
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

  if (phase === "password") {
    return (
      <div className="card">
        <h2>Enter your password</h2>
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
            Verify identity
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className="card">
      <h2>Lost your passkey?</h2>
      <p className="hint">
        Verify your authenticator code (or a backup code) first, then your password, to regain
        access and register a new passkey.
      </p>
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
