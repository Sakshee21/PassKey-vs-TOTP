export type UserRole = "user" | "admin";

export interface User {
  id: string;
  email: string;
  role: UserRole;
  is_totp_enabled: boolean;
  created_at: string;
}

export interface Token {
  access_token: string;
  token_type: string;
}

export type LoginMethod = "passkey" | "password_totp" | "password_backup_code" | "password";

/** Result of the *first* step of password+TOTP login: verifying the second
 * factor before any password is asked for. */
export interface SecondFactorResponse {
  registration_incomplete: boolean;
  registration_token: string | null;
  password_token: string | null;
}

export interface BackupCodeSecondFactorResponse extends SecondFactorResponse {
  backup_codes_remaining: number | null;
}

export interface RegisterStartResponse {
  registration_token: string;
  email: string;
}

export interface RegisterStatusResponse {
  email: string;
  totp_done: boolean;
  passkey_done: boolean;
}

export interface TOTPSetupResponse {
  secret: string;
  provisioning_uri: string;
}

export interface TOTPEnableResponse {
  backup_codes: string[];
}

export interface BackupCodeStatusResponse {
  remaining: number;
}

export interface BackupCodeRegenerateResponse {
  backup_codes: string[];
}

export type ResidentKeyPolicy = "required" | "preferred" | "discouraged";

export interface WebAuthnCredentialOut {
  id: string;
  resident_key_policy: ResidentKeyPolicy;
  is_discoverable: boolean;
  backup_eligible: boolean;
  backup_state: boolean;
  device_name: string | null;
  created_at: string;
}

export type AuthMethod = "passkey" | "totp_password";

export interface MethodStat {
  method: AuthMethod;
  total_attempts: number;
  successful_attempts: number;
  success_rate: number;
  avg_latency_ms: number | null;
}

export interface TimeBucket {
  bucket: string;
  attempts: number;
  simulated_attempts: number;
}

export interface FailureReason {
  reason: string;
  count: number;
}

export interface AnalyticsSummary {
  by_method: MethodStat[];
  attempts_over_time: TimeBucket[];
  failure_reasons: FailureReason[];
  total_events: number;
  simulated_events: number;
}
