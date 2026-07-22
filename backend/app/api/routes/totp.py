from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, user_from_token
from app.core.database import get_db
from app.core.security import create_access_token, verify_secret
from app.models.backup_code import BackupCode
from app.models.user import User
from app.schemas.auth import (
    BackupCodeRegenerateResponse,
    BackupCodeStatusResponse,
    BackupCodeVerifyRequest,
    BackupCodeVerifyResponse,
    TOTPEnableRequest,
    TOTPEnableResponse,
    TOTPSetupResponse,
    TOTPVerifyRequest,
    Token,
)
from app.services.totp_service import (
    generate_backup_codes,
    generate_totp_secret,
    get_provisioning_uri,
    hash_backup_codes,
    verify_totp_code,
)

router = APIRouter(prefix="/totp", tags=["totp"])


@router.post("/setup", response_model=TOTPSetupResponse)
def setup_totp(current_user: User = Depends(get_current_user)) -> TOTPSetupResponse:
    # Not persisted here: totp_secret is only written once a code is confirmed
    # in /enable, so an abandoned setup never leaves totp_secret set.
    secret = generate_totp_secret()
    return TOTPSetupResponse(
        secret=secret, provisioning_uri=get_provisioning_uri(secret, current_user.email)
    )


@router.post("/enable", response_model=TOTPEnableResponse)
def enable_totp(
    payload: TOTPEnableRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> TOTPEnableResponse:
    if not verify_totp_code(payload.secret, payload.code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    current_user.totp_secret = payload.secret

    codes = generate_backup_codes()
    for hashed in hash_backup_codes(codes):
        db.add(BackupCode(user_id=current_user.id, code_hash=hashed))
    db.commit()

    return TOTPEnableResponse(backup_codes=codes)


@router.post("/disable", status_code=status.HTTP_204_NO_CONTENT)
def disable_totp(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> None:
    current_user.totp_secret = None
    db.query(BackupCode).filter(BackupCode.user_id == current_user.id).delete()
    db.commit()


@router.post("/verify", response_model=Token)
def verify_totp(payload: TOTPVerifyRequest, db: Session = Depends(get_db)) -> Token:
    user = user_from_token(payload.login_token, "login_pending", db)
    if not user.totp_secret or not verify_totp_code(user.totp_secret, payload.code):
        raise HTTPException(status_code=401, detail="Invalid TOTP code")
    return Token(access_token=create_access_token(user.id, method="password_totp"))


@router.post("/verify-backup-code", response_model=BackupCodeVerifyResponse)
def verify_backup_code(
    payload: BackupCodeVerifyRequest, db: Session = Depends(get_db)
) -> BackupCodeVerifyResponse:
    user = user_from_token(payload.login_token, "login_pending", db)

    unused_codes = (
        db.query(BackupCode)
        .filter(BackupCode.user_id == user.id, BackupCode.used.is_(False))
        .all()
    )
    matched = next(
        (bc for bc in unused_codes if verify_secret(payload.backup_code, bc.code_hash)), None
    )
    if matched is None:
        raise HTTPException(status_code=401, detail="Invalid or already-used backup code")

    matched.used = True
    db.commit()

    remaining = sum(1 for bc in unused_codes if bc.id != matched.id)
    return BackupCodeVerifyResponse(
        access_token=create_access_token(user.id, method="password_backup_code"),
        backup_codes_remaining=remaining,
    )


@router.get("/backup-codes/status", response_model=BackupCodeStatusResponse)
def backup_codes_status(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> BackupCodeStatusResponse:
    remaining = (
        db.query(BackupCode)
        .filter(BackupCode.user_id == current_user.id, BackupCode.used.is_(False))
        .count()
    )
    return BackupCodeStatusResponse(remaining=remaining)


@router.post("/backup-codes/regenerate", response_model=BackupCodeRegenerateResponse)
def regenerate_backup_codes(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> BackupCodeRegenerateResponse:
    if current_user.totp_secret is None:
        raise HTTPException(status_code=400, detail="TOTP is not enabled on this account")

    # Invalidate every existing code (used or not) so old codes can't linger.
    db.query(BackupCode).filter(BackupCode.user_id == current_user.id).delete()

    codes = generate_backup_codes()
    for hashed in hash_backup_codes(codes):
        db.add(BackupCode(user_id=current_user.id, code_hash=hashed))
    db.commit()

    return BackupCodeRegenerateResponse(backup_codes=codes)
