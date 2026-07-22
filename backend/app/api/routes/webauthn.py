from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.core.security import create_access_token
from app.models.passkey_credential import PasskeyCredential
from app.models.user import User
from app.schemas.auth import Token
from app.schemas.webauthn import (
    WebAuthnAuthenticateFinishRequest,
    WebAuthnAuthenticateStartRequest,
    WebAuthnCredentialOut,
    WebAuthnRegisterFinishRequest,
)
from app.services.webauthn_service import (
    IS_DISCOVERABLE,
    RESIDENT_KEY_POLICY_VALUE,
    backup_flags_from_verification,
    build_authentication_options,
    build_registration_options,
    encode_credential_id,
    verify_authentication,
    verify_registration,
)

router = APIRouter(prefix="/webauthn", tags=["webauthn"])


@router.get("/credentials", response_model=list[WebAuthnCredentialOut])
def list_credentials(current_user: User = Depends(get_current_user)) -> list[PasskeyCredential]:
    return current_user.passkey_credentials


@router.post("/register/options")
def register_options(current_user: User = Depends(get_current_user)) -> Response:
    """Add another passkey to the signed-in user's account."""
    existing_credential_ids = [cred.credential_id for cred in current_user.passkey_credentials]
    options_json = build_registration_options(
        current_user.id.bytes, current_user.email, existing_credential_ids
    )
    return Response(content=options_json, media_type="application/json")


@router.post("/register/verify", response_model=WebAuthnCredentialOut)
def register_verify(
    payload: WebAuthnRegisterFinishRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PasskeyCredential:
    try:
        verification = verify_registration(current_user.email, payload.credential)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Passkey registration failed: {exc}")

    backup_eligible, backup_state = backup_flags_from_verification(verification)
    credential = PasskeyCredential(
        user_id=current_user.id,
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
    db.refresh(credential)

    return credential


@router.post("/authenticate/options")
def authenticate_options(
    payload: WebAuthnAuthenticateStartRequest, db: Session = Depends(get_db)
) -> Response:
    user = db.query(User).filter(User.email == payload.email).first()
    if user is None or not user.passkey_credentials:
        raise HTTPException(status_code=404, detail="No passkeys registered for this account")

    credential_ids = [cred.credential_id for cred in user.passkey_credentials]
    options_json = build_authentication_options(payload.email, credential_ids)
    return Response(content=options_json, media_type="application/json")


@router.post("/authenticate/verify", response_model=Token)
def authenticate_verify(
    payload: WebAuthnAuthenticateFinishRequest, db: Session = Depends(get_db)
) -> Token:
    user = db.query(User).filter(User.email == payload.email).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid credential")

    raw_id = payload.credential.get("id")
    credential = (
        db.query(PasskeyCredential)
        .filter(PasskeyCredential.user_id == user.id, PasskeyCredential.credential_id == raw_id)
        .first()
    )
    if credential is None:
        raise HTTPException(status_code=401, detail="Unknown passkey")

    try:
        verification = verify_authentication(
            payload.email, payload.credential, credential.public_key, credential.sign_count
        )
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"Passkey authentication failed: {exc}")

    credential.sign_count = verification.new_sign_count
    db.commit()

    return Token(access_token=create_access_token(user.id, method="passkey"))
