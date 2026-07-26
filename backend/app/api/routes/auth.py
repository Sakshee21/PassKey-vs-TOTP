import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.api.deps import decode_purpose_token, get_current_user, is_simulated_request
from app.core.database import get_db
from app.core.rate_limit import limiter
from app.core.security import create_access_token, verify_secret
from app.models.auth_event import AuthMethod
from app.models.user import User
from app.schemas.auth import LoginRequest, Token
from app.schemas.user import UserOut
from app.services.audit_service import log_auth_event

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=Token)
@limiter.limit("5/minute")
def login(
    request: Request,
    payload: LoginRequest,
    db: Session = Depends(get_db),
    simulated: bool = Depends(is_simulated_request),
) -> Token:
    """Second (and final) step of password+TOTP login: the second factor was
    already verified by /totp/verify or /totp/verify-backup-code, which is
    what `password_token` proves. Only the password remains to be checked.

    This is where the logical login attempt concludes, so it's where the
    auth_events row for the whole attempt gets logged (success or failure)."""
    start = time.monotonic()
    payload_claims = decode_purpose_token(payload.password_token, "password_pending")
    try:
        user_id = uuid.UUID(payload_claims["sub"])
    except (KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    second_factor = payload_claims.get("second_factor", "totp")
    method_label = "password_totp" if second_factor == "totp" else "password_backup_code"

    user = db.get(User, user_id)
    if user is None or user.password_hash is None or not verify_secret(
        payload.password, user.password_hash
    ):
        log_auth_event(
            db,
            user_id=user.id if user else None,
            method=AuthMethod.TOTP_PASSWORD,
            success=False,
            latency_ms=int((time.monotonic() - start) * 1000),
            request=request,
            failure_reason="invalid_password",
            is_simulated=simulated,
        )
        raise HTTPException(status_code=401, detail="Incorrect password")

    log_auth_event(
        db,
        user_id=user.id,
        method=AuthMethod.TOTP_PASSWORD,
        success=True,
        latency_ms=int((time.monotonic() - start) * 1000),
        request=request,
        is_simulated=simulated,
    )
    return Token(access_token=create_access_token(user.id, method=method_label))


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user
