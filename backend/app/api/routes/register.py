from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.api.deps import get_registration_user
from app.core.database import get_db
from app.core.security import create_access_token, create_registration_token, hash_secret, verify_secret
from app.models.backup_code import BackupCode
from app.models.passkey_credential import PasskeyCredential
from app.models.user import User
from app.schemas.auth import Token, TOTPEnableRequest, TOTPEnableResponse, TOTPSetupResponse
from app.schemas.register import RegisterStartRequest, RegisterStartResponse, RegisterStatusResponse
from app.schemas.webauthn import WebAuthnRegisterFinishRequest
from app.services.totp_service import (
    generate_backup_codes,
    generate_totp_secret,
    get_provisioning_uri,
    hash_backup_codes,
    verify_totp_code,
)
from app.services.webauthn_service import (
    IS_DISCOVERABLE,
    RESIDENT_KEY_POLICY_VALUE,
    backup_flags_from_verification,
    build_registration_options,
    encode_credential_id,
    verify_registration,
)

router = APIRouter(prefix="/register", tags=["register"])


@router.post("/start", response_model=RegisterStartResponse)
def start_registration(
    payload: RegisterStartRequest, db: Session = Depends(get_db)
) -> RegisterStartResponse:
    user = db.query(User).filter(User.email == payload.email).first()
    if user is not None:
        # Resume an abandoned wizard for the same account (re-prove the password);
        # a completed account with this email is a genuine conflict.
        if (
            user.is_fully_registered
            or user.password_hash is None
            or not verify_secret(payload.password, user.password_hash)
        ):
            raise HTTPException(status_code=400, detail="Email already registered")
    else:
        user = User(email=payload.email, password_hash=hash_secret(payload.password))
        db.add(user)
        db.commit()
        db.refresh(user)

    return RegisterStartResponse(
        registration_token=create_registration_token(user.id), email=user.email
    )


@router.get("/status", response_model=RegisterStatusResponse)
def registration_status(user: User = Depends(get_registration_user)) -> RegisterStatusResponse:
    return RegisterStatusResponse(
        email=user.email,
        totp_done=user.totp_secret is not None,
        passkey_done=len(user.passkey_credentials) > 0,
    )


@router.post("/totp/setup", response_model=TOTPSetupResponse)
def registration_totp_setup(user: User = Depends(get_registration_user)) -> TOTPSetupResponse:
    # Not persisted here: totp_secret is only written once a code is confirmed
    # below, so an abandoned setup never leaves a secret behind.
    secret = generate_totp_secret()
    return TOTPSetupResponse(
        secret=secret, provisioning_uri=get_provisioning_uri(secret, user.email)
    )


@router.post("/totp/confirm", response_model=TOTPEnableResponse)
def registration_totp_confirm(
    payload: TOTPEnableRequest,
    user: User = Depends(get_registration_user),
    db: Session = Depends(get_db),
) -> TOTPEnableResponse:
    if not verify_totp_code(payload.secret, payload.code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    user.totp_secret = payload.secret

    codes = generate_backup_codes()
    for hashed in hash_backup_codes(codes):
        db.add(BackupCode(user_id=user.id, code_hash=hashed))
    db.commit()

    return TOTPEnableResponse(backup_codes=codes)


@router.post("/passkey/options")
def registration_passkey_options(user: User = Depends(get_registration_user)) -> Response:
    if user.totp_secret is None:
        raise HTTPException(status_code=400, detail="Complete TOTP setup first")

    existing_credential_ids = [cred.credential_id for cred in user.passkey_credentials]
    options_json = build_registration_options(user.id.bytes, user.email, existing_credential_ids)
    return Response(content=options_json, media_type="application/json")


@router.post("/passkey/skip", response_model=Token)
def registration_passkey_skip(
    user: User = Depends(get_registration_user), db: Session = Depends(get_db)
) -> Token:
    """Lets a user finish registration without a passkey - e.g. no platform
    authenticator or security key available. Password+TOTP is a complete,
    valid account; a passkey can be added later from the dashboard."""
    if user.totp_secret is None:
        raise HTTPException(status_code=400, detail="Complete TOTP setup first")

    user.passkey_skipped = True
    db.commit()

    return Token(access_token=create_access_token(user.id, method="password_totp"))


@router.post("/passkey/confirm", response_model=Token)
def registration_passkey_confirm(
    payload: WebAuthnRegisterFinishRequest,
    user: User = Depends(get_registration_user),
    db: Session = Depends(get_db),
) -> Token:
    if user.totp_secret is None:
        raise HTTPException(status_code=400, detail="Complete TOTP setup first")

    try:
        verification = verify_registration(user.email, payload.credential)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Passkey registration failed: {exc}")

    backup_eligible, backup_state = backup_flags_from_verification(verification)
    credential = PasskeyCredential(
        user_id=user.id,
        credential_id=encode_credential_id(verification.credential_id),
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        resident_key_policy=RESIDENT_KEY_POLICY_VALUE,
        is_discoverable=IS_DISCOVERABLE,
        backup_eligible=backup_eligible,
        backup_state=backup_state,
        device_name=payload.device_name,
    )
    db.add(credential)
    db.commit()

    # All three steps are now done - issue a real access token.
    return Token(access_token=create_access_token(user.id, method="passkey"))
