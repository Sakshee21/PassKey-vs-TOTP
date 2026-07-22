from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID

import bcrypt
import jwt

from app.core.config import settings

# How this session's access token was obtained - carried as a JWT claim (JWTs
# are signed, not encrypted, so this is fine to read back out client-side)
# purely so the UI can say e.g. "you signed in with a passkey this session".
LoginMethod = Literal["passkey", "password_totp", "password_backup_code", "password"]


def hash_secret(plain: str) -> str:
    """Hash a password or backup code with bcrypt."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_secret(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def _create_token(
    user_id: UUID, purpose: str, expires_minutes: int, extra_claims: dict | None = None
) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    payload = {"sub": str(user_id), "purpose": purpose, "exp": expire, **(extra_claims or {})}
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_access_token(
    user_id: UUID, method: LoginMethod, expires_minutes: int | None = None
) -> str:
    return _create_token(
        user_id,
        "access",
        expires_minutes or settings.JWT_EXPIRE_MINUTES,
        extra_claims={"method": method},
    )


SecondFactor = Literal["totp", "backup_code"]


def create_password_pending_token(user_id: UUID, second_factor: SecondFactor) -> str:
    """Proves the second factor (TOTP or a backup code) was verified *before*
    the password - the deliberately-flipped order for password+TOTP login.
    `second_factor` is carried through so the final access token's `method`
    claim can distinguish "password_totp" from "password_backup_code"."""
    return _create_token(
        user_id, "password_pending", expires_minutes=5, extra_claims={"second_factor": second_factor}
    )


def create_registration_token(user_id: UUID) -> str:
    """Proves step 1 (email+password) passed; used to authenticate steps 2-3 of
    the registration wizard before the account is fully registered."""
    return _create_token(user_id, "registration_pending", expires_minutes=30)


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
