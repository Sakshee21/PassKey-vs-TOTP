from pydantic import BaseModel, EmailStr


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginResponse(BaseModel):
    """Returned after a password check.

    Exactly one of three outcomes:
    - `registration_incomplete`: the account never finished the signup wizard;
      `registration_token` lets the client resume it.
    - `totp_required`: password was correct; call /totp/verify (or
      /totp/verify-backup-code) with `login_token` to complete login.
    - neither flag set: `token` is a ready-to-use access token.
    """

    registration_incomplete: bool = False
    registration_token: str | None = None

    totp_required: bool = False
    login_token: str | None = None

    token: Token | None = None


class TOTPSetupResponse(BaseModel):
    secret: str
    provisioning_uri: str


class TOTPEnableRequest(BaseModel):
    # The secret from /totp/setup is round-tripped here rather than persisted
    # at setup time, so an abandoned setup never leaves totp_secret set.
    secret: str
    code: str


class TOTPEnableResponse(BaseModel):
    backup_codes: list[str]


class TOTPVerifyRequest(BaseModel):
    login_token: str
    code: str


class BackupCodeVerifyRequest(BaseModel):
    login_token: str
    backup_code: str


class BackupCodeVerifyResponse(Token):
    backup_codes_remaining: int


class BackupCodeStatusResponse(BaseModel):
    remaining: int


class BackupCodeRegenerateResponse(BaseModel):
    backup_codes: list[str]
