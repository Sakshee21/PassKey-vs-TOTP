export interface User {
  id: string;
  email: string;
  is_totp_enabled: boolean;
  created_at: string;
}

export interface Token {
  access_token: string;
  token_type: string;
}

export type LoginMethod = "passkey" | "password_totp" | "password_backup_code" | "password";

export interface LoginResponse {
  registration_incomplete: boolean;
  registration_token: string | null;
  totp_required: boolean;
  login_token: string | null;
  token: Token | null;
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

export interface BackupCodeVerifyResponse extends Token {
  backup_codes_remaining: number;
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
