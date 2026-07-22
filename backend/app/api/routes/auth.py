import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import decode_purpose_token, get_current_user
from app.core.database import get_db
from app.core.security import create_access_token, verify_secret
from app.models.user import User
from app.schemas.auth import LoginRequest, Token
from app.schemas.user import UserOut

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=Token)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> Token:
    """Second (and final) step of password+TOTP login: the second factor was
    already verified by /totp/verify or /totp/verify-backup-code, which is
    what `password_token` proves. Only the password remains to be checked."""
    payload_claims = decode_purpose_token(payload.password_token, "password_pending")
    try:
        user_id = uuid.UUID(payload_claims["sub"])
    except (KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.get(User, user_id)
    if user is None or user.password_hash is None or not verify_secret(
        payload.password, user.password_hash
    ):
        raise HTTPException(status_code=401, detail="Incorrect password")

    second_factor = payload_claims.get("second_factor", "totp")
    method = "password_totp" if second_factor == "totp" else "password_backup_code"
    return Token(access_token=create_access_token(user.id, method=method))


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user
