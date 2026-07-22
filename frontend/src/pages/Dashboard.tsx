import { useEffect, useState } from "react";
import {
  getBackupCodesStatus,
  getSessionLoginMethod,
  listPasskeys,
  regenerateBackupCodes,
  registerPasskey,
} from "../lib/auth";
import { ApiError } from "../lib/api";
import type { LoginMethod, User, WebAuthnCredentialOut } from "../lib/types";

interface Props {
  user: User;
  onLogout: () => void;
}

const LOGIN_METHOD_LABEL: Record<LoginMethod, string> = {
  passkey: "a passkey",
  password_totp: "your password + authenticator app",
  password_backup_code: "your password + a backup code",
  password: "your password",
};

export function Dashboard({ user, onLogout }: Props) {
  const [passkeys, setPasskeys] = useState<WebAuthnCredentialOut[]>([]);
  const [backupCodesRemaining, setBackupCodesRemaining] = useState<number | null>(null);
  const [newBackupCodes, setNewBackupCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const loginMethod = getSessionLoginMethod();

  function refreshOverview() {
    listPasskeys().then(setPasskeys).catch(() => setPasskeys([]));
    getBackupCodesStatus()
      .then((s) => setBackupCodesRemaining(s.remaining))
      .catch(() => setBackupCodesRemaining(null));
  }

  useEffect(refreshOverview, []);

  async function handleAddPasskey() {
    setError(null);
    setBusy(true);
    try {
      const name = window.prompt("Name this passkey (optional):") ?? undefined;
      await registerPasskey(name || undefined);
      setPasskeys(await listPasskeys());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to register passkey");
    } finally {
      setBusy(false);
    }
  }

  async function handleRegenerateBackupCodes() {
    setError(null);
    if (
      !window.confirm(
        "This invalidates all existing backup codes and generates 10 new ones. Continue?",
      )
    ) {
      return;
    }
    setBusy(true);
    try {
      const result = await regenerateBackupCodes();
      setNewBackupCodes(result.backup_codes);
      setBackupCodesRemaining(result.backup_codes.length);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to regenerate backup codes");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="card">
        <h2>Welcome back, {user.email}</h2>
        <p className="hint">
          Signed in with {loginMethod ? LOGIN_METHOD_LABEL[loginMethod] : "an unknown method"} this
          session.
        </p>
        <button className="secondary" onClick={onLogout}>
          Log out
        </button>
      </div>

      <div className="card">
        <h2>Account overview</h2>
        <ul className="plain">
          <li>
            <strong>Passkeys:</strong> {passkeys.length} registered
          </li>
          <li>
            <strong>Backup codes:</strong>{" "}
            {backupCodesRemaining === null ? "—" : `${backupCodesRemaining} remaining`}
            {backupCodesRemaining !== null && backupCodesRemaining < 3 && (
              <span className="error"> — running low, regenerate below</span>
            )}
          </li>
          <li>
            <strong>Authenticator app (TOTP):</strong>{" "}
            {user.is_totp_enabled ? "Enabled" : "Not set up"}
          </li>
        </ul>
      </div>

      <div className="card">
        <h2>Passkeys</h2>
        {passkeys.length === 0 ? (
          <p className="hint">No passkeys registered yet.</p>
        ) : (
          <ul className="plain">
            {passkeys.map((p) => (
              <li key={p.id}>
                {p.device_name ?? "Unnamed passkey"} —{" "}
                {p.is_discoverable ? "discoverable" : "non-discoverable"},{" "}
                {p.backup_state ? "synced across devices" : "device-bound only"} — added{" "}
                {new Date(p.created_at).toLocaleDateString()}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="card">
        <h2>Manage</h2>
        <button onClick={handleAddPasskey} disabled={busy}>
          Add another passkey
        </button>
        <button
          className="secondary"
          onClick={handleRegenerateBackupCodes}
          disabled={busy}
          style={{ marginTop: "0.5rem" }}
        >
          Regenerate backup codes
        </button>
        {error && <p className="error">{error}</p>}

        {newBackupCodes && (
          <div style={{ marginTop: "1rem" }}>
            <p>New backup codes — save them now, shown only once:</p>
            <div>
              {newBackupCodes.map((c) => (
                <code className="backup-code" key={c}>
                  {c}
                </code>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
