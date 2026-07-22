import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { api, decodeJwtPayload, getToken, setToken } from "./api";
import type {
  BackupCodeRegenerateResponse,
  BackupCodeStatusResponse,
  BackupCodeVerifyResponse,
  LoginMethod,
  LoginResponse,
  RegisterStartResponse,
  RegisterStatusResponse,
  TOTPEnableResponse,
  TOTPSetupResponse,
  Token,
  User,
  WebAuthnCredentialOut,
} from "./types";

export function login(email: string, password: string): Promise<LoginResponse> {
  return api.post<LoginResponse>("/auth/login", { email, password });
}

export function me(): Promise<User> {
  return api.get<User>("/auth/me", getToken() ?? undefined);
}

export function persistSession(token: Token): void {
  setToken(token.access_token);
}

/** Reads the `method` claim off the current session's access token — how
 * this session's login was actually established. JWTs aren't secret payload
 * wise, so decoding our own token client-side is fine. */
export function getSessionLoginMethod(): LoginMethod | null {
  const token = getToken();
  if (!token) return null;
  const payload = decodeJwtPayload(token);
  const method = payload?.method;
  return typeof method === "string" ? (method as LoginMethod) : null;
}

// --- Registration wizard (all three steps required, in order) ---------------

export function startRegistrationWizard(
  email: string,
  password: string,
): Promise<RegisterStartResponse> {
  return api.post<RegisterStartResponse>("/register/start", { email, password });
}

export function registrationStatus(
  registrationToken: string,
): Promise<RegisterStatusResponse> {
  return api.get<RegisterStatusResponse>("/register/status", registrationToken);
}

export function registrationTotpSetup(registrationToken: string): Promise<TOTPSetupResponse> {
  return api.post<TOTPSetupResponse>("/register/totp/setup", undefined, registrationToken);
}

export function registrationTotpConfirm(
  registrationToken: string,
  secret: string,
  code: string,
): Promise<TOTPEnableResponse> {
  return api.post<TOTPEnableResponse>(
    "/register/totp/confirm",
    { secret, code },
    registrationToken,
  );
}

/** Runs the WebAuthn registration ceremony for the final wizard step and
 * returns a ready-to-use access token — the account is fully registered. */
export async function registrationPasskeyConfirm(registrationToken: string): Promise<Token> {
  const options = await api.post<PublicKeyCredentialCreationOptionsJSON>(
    "/register/passkey/options",
    undefined,
    registrationToken,
  );
  const credential = await startRegistration({ optionsJSON: options });
  return api.post<Token>("/register/passkey/confirm", { credential }, registrationToken);
}

// --- Account management (already signed in) ---------------------------------

export function setupTotp(): Promise<TOTPSetupResponse> {
  return api.post<TOTPSetupResponse>("/totp/setup", undefined, getToken() ?? undefined);
}

export function enableTotp(secret: string, code: string): Promise<TOTPEnableResponse> {
  return api.post<TOTPEnableResponse>(
    "/totp/enable",
    { secret, code },
    getToken() ?? undefined,
  );
}

export function disableTotp(): Promise<void> {
  return api.post<void>("/totp/disable", undefined, getToken() ?? undefined);
}

export function verifyTotp(loginToken: string, code: string): Promise<Token> {
  return api.post<Token>("/totp/verify", { login_token: loginToken, code });
}

export function verifyBackupCode(
  loginToken: string,
  backupCode: string,
): Promise<BackupCodeVerifyResponse> {
  return api.post<BackupCodeVerifyResponse>("/totp/verify-backup-code", {
    login_token: loginToken,
    backup_code: backupCode,
  });
}

export function getBackupCodesStatus(): Promise<BackupCodeStatusResponse> {
  return api.get<BackupCodeStatusResponse>("/totp/backup-codes/status", getToken() ?? undefined);
}

export function regenerateBackupCodes(): Promise<BackupCodeRegenerateResponse> {
  return api.post<BackupCodeRegenerateResponse>(
    "/totp/backup-codes/regenerate",
    undefined,
    getToken() ?? undefined,
  );
}

export function listPasskeys(): Promise<WebAuthnCredentialOut[]> {
  return api.get<WebAuthnCredentialOut[]>("/webauthn/credentials", getToken() ?? undefined);
}

/** Adds another passkey to the signed-in user's account. */
export async function registerPasskey(deviceName?: string): Promise<WebAuthnCredentialOut> {
  const sessionToken = getToken() ?? undefined;
  const options = await api.post<PublicKeyCredentialCreationOptionsJSON>(
    "/webauthn/register/options",
    undefined,
    sessionToken,
  );
  const credential = await startRegistration({ optionsJSON: options });
  return api.post<WebAuthnCredentialOut>(
    "/webauthn/register/verify",
    { credential, device_name: deviceName || null },
    sessionToken,
  );
}

/** Runs the full WebAuthn authentication ceremony and returns an access token. */
export async function authenticateWithPasskey(email: string): Promise<Token> {
  const options = await api.post<PublicKeyCredentialRequestOptionsJSON>(
    "/webauthn/authenticate/options",
    { email },
  );
  const credential = await startAuthentication({ optionsJSON: options });
  return api.post<Token>("/webauthn/authenticate/verify", { email, credential });
}

// Minimal structural types for what @simplewebauthn/browser expects as input;
// the full shapes are re-exported by @simplewebauthn/types but importing the
// whole package isn't needed for this shape.
type PublicKeyCredentialCreationOptionsJSON = Parameters<typeof startRegistration>[0]["optionsJSON"];
type PublicKeyCredentialRequestOptionsJSON = Parameters<typeof startAuthentication>[0]["optionsJSON"];
