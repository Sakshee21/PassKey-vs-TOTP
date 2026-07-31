import { useEffect, useState } from "react";
import QRCode from "qrcode";
import {
  persistSession,
  platformAuthenticatorLikelyAvailable,
  registrationPasskeyConfirm,
  registrationPasskeySkip,
  registrationStatus,
  registrationTotpConfirm,
  registrationTotpSetup,
  startRegistrationWizard,
} from "../lib/auth";
import { ApiError } from "../lib/api";

interface Props {
  onComplete: () => void;
  onBackToLogin: () => void;
}

type Step = 1 | 2 | 3;

const STORAGE_KEY = "registration_wizard";

interface StoredState {
  registrationToken: string;
  email: string;
}

function loadStored(): StoredState | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as StoredState) : null;
  } catch {
    return null;
  }
}

function saveStored(state: StoredState | null) {
  if (state) sessionStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  else sessionStorage.removeItem(STORAGE_KEY);
}

/** Seeds resume state for an in-progress wizard, e.g. when a login attempt
 * reveals the account never finished registering. */
export function primeRegistrationResume(registrationToken: string, email: string): void {
  saveStored({ registrationToken, email });
}

const STEPS: { n: Step; label: string }[] = [
  { n: 1, label: "Account" },
  { n: 2, label: "Authenticator app" },
  { n: 3, label: "Passkey" },
];

function ProgressBar({ step }: { step: Step }) {
  return (
    <div className="wizard-progress">
      {STEPS.map(({ n, label }) => (
        <div className="wizard-progress-item" key={n}>
          <div
            className={
              "wizard-progress-dot" +
              (n < step ? " done" : n === step ? " current" : "")
            }
          >
            {n < step ? "✓" : n}
          </div>
          <span className="wizard-progress-label">{label}</span>
        </div>
      ))}
    </div>
  );
}

export function RegisterWizard({ onComplete, onBackToLogin }: Props) {
  const [step, setStep] = useState<Step>(1);
  const [registrationToken, setRegistrationToken] = useState<string | null>(null);
  const [restoring, setRestoring] = useState(true);

  // Step 1 state
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  // Step 2 state
  const [secret, setSecret] = useState<string | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);

  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Step 3 state - null while the capability check is still in flight
  const [platformAuthAvailable, setPlatformAuthAvailable] = useState<boolean | null>(null);

  // Resume an in-progress wizard after a reload, trusting server-side status
  // over whatever step was last cached client-side.
  useEffect(() => {
    const stored = loadStored();
    if (!stored) {
      setRestoring(false);
      return;
    }
    registrationStatus(stored.registrationToken)
      .then((status) => {
        setRegistrationToken(stored.registrationToken);
        setEmail(stored.email);
        setStep(status.totp_done ? 3 : 2);
      })
      .catch(() => saveStored(null))
      .finally(() => setRestoring(false));
  }, []);

  useEffect(() => {
    if (step === 2 && registrationToken && !secret && !backupCodes) {
      registrationTotpSetup(registrationToken)
        .then((res) => {
          setSecret(res.secret);
          return QRCode.toDataURL(res.provisioning_uri);
        })
        .then(setQrDataUrl)
        .catch((err) =>
          setError(err instanceof ApiError ? err.message : "Failed to start TOTP setup"),
        );
    }
  }, [step, registrationToken, secret, backupCodes]);

  useEffect(() => {
    if (step !== 3) return;
    let cancelled = false;
    platformAuthenticatorLikelyAvailable().then((available) => {
      if (!cancelled) setPlatformAuthAvailable(available);
    });
    return () => {
      cancelled = true;
    };
  }, [step]);

  async function handleStart(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const res = await startRegistrationWizard(email, password);
      setRegistrationToken(res.registration_token);
      saveStored({ registrationToken: res.registration_token, email: res.email });
      setStep(2);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to start registration");
    } finally {
      setBusy(false);
    }
  }

  async function handleConfirmTotp(e: React.FormEvent) {
    e.preventDefault();
    if (!registrationToken || !secret) return;
    setError(null);
    setBusy(true);
    try {
      const res = await registrationTotpConfirm(registrationToken, secret, code);
      setBackupCodes(res.backup_codes);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Invalid code");
    } finally {
      setBusy(false);
    }
  }

  async function handlePasskey() {
    if (!registrationToken) return;
    setError(null);
    setBusy(true);
    try {
      const token = await registrationPasskeyConfirm(registrationToken);
      persistSession(token);
      saveStored(null);
      onComplete();
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Passkey ceremony failed or was cancelled",
      );
    } finally {
      setBusy(false);
    }
  }

  async function handlePasskeySkip() {
    if (!registrationToken) return;
    setError(null);
    setBusy(true);
    try {
      const token = await registrationPasskeySkip(registrationToken);
      persistSession(token);
      saveStored(null);
      onComplete();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to skip the passkey step");
    } finally {
      setBusy(false);
    }
  }

  if (restoring) {
    return (
      <div className="card">
        <p className="hint">Loading…</p>
      </div>
    );
  }

  return (
    <div className="card">
      <h2>Create your account</h2>
      <ProgressBar step={step} />

      {step === 1 && (
        <form onSubmit={handleStart}>
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
            Continue
          </button>
        </form>
      )}

      {step === 2 && !backupCodes && (
        <form onSubmit={handleConfirmTotp}>
          <p className="hint">
            Scan this QR code with your authenticator app (Google Authenticator, Authy, 1Password,
            etc.), then enter the 6-digit code it shows.
          </p>
          {qrDataUrl ? (
            <img src={qrDataUrl} alt="TOTP QR code" width={200} height={200} />
          ) : (
            <p className="hint">Generating QR code…</p>
          )}
          <input
            placeholder="6-digit code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            inputMode="numeric"
            autoFocus
          />
          {error && <p className="error">{error}</p>}
          <button type="submit" disabled={busy || !secret}>
            Confirm code
          </button>
        </form>
      )}

      {step === 2 && backupCodes && (
        <div>
          <p>
            Save these one-time backup codes somewhere safe — each can be used once to sign in if
            you lose access to your authenticator app:
          </p>
          <div>
            {backupCodes.map((c) => (
              <code className="backup-code" key={c}>
                {c}
              </code>
            ))}
          </div>
          <button style={{ marginTop: "1rem" }} onClick={() => setStep(3)}>
            I've saved my backup codes — continue
          </button>
        </div>
      )}

      {step === 3 && (
        <div>
          <p className="hint">
            Last step: register a passkey for this device. Your browser or password manager will
            prompt you — prefer a discoverable (resident) passkey so you can sign in without typing
            your email.
          </p>
          {platformAuthAvailable === false && (
            <p className="hint">
              We couldn't detect a platform authenticator (Windows Hello, Touch ID, etc.) on this
              device. If you have a physical security key, click "Register passkey" and use that
              instead. Only if you have neither should you skip this step.
            </p>
          )}
          {error && <p className="error">{error}</p>}
          <button onClick={handlePasskey} disabled={busy}>
            Register passkey
          </button>
          {platformAuthAvailable === false && (
            <button
              className="secondary"
              style={{ marginTop: "0.5rem" }}
              onClick={handlePasskeySkip}
              disabled={busy}
            >
              Skip for now — add a passkey later
            </button>
          )}
        </div>
      )}

      {step === 1 && (
        <p className="hint" style={{ marginTop: "1rem" }}>
          Already have an account?{" "}
          <button
            className="secondary"
            style={{ padding: 0, border: "none", textDecoration: "underline" }}
            onClick={onBackToLogin}
          >
            Sign in
          </button>
        </p>
      )}
    </div>
  );
}
