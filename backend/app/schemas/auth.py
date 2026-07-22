from pydantic import BaseModel, EmailStr


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class SecondFactorResponse(BaseModel):
    """Returned after the *first* step of password+TOTP login - verifying the
    second factor (TOTP code or backup code) before any password is asked.

    Exactly one of two outcomes:
    - `registration_incomplete`: the account never finished the signup wizard
      (so it has no confirmed TOTP secret to check against); `registration_token`
      lets the client resume it.
    - neither flag set: `password_token` proves the second factor and is
      submitted with the password to /auth/login to finish signing in.
    """

    registration_incomplete: bool = False
    registration_token: str | None = None
    password_token: str | None = None


class BackupCodeSecondFactorResponse(SecondFactorResponse):
    backup_codes_remaining: int | None = None


class TotpVerifyRequest(BaseModel):
    email: EmailStr
    code: str


class BackupCodeVerifyRequest(BaseModel):
    email: EmailStr
    backup_code: str


class LoginRequest(BaseModel):
    """The *second* step of password+TOTP login: the password, plus the
    `password_token` proving the second factor already passed."""

    password_token: str
    password: str


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


class BackupCodeStatusResponse(BaseModel):
    remaining: int


class BackupCodeRegenerateResponse(BaseModel):
    backup_codes: list[str]
