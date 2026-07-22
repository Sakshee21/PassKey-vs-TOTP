import json

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.authentication.verify_authentication_response import VerifiedAuthentication
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    CredentialDeviceType,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.registration.verify_registration_response import VerifiedRegistration

from app.core.config import settings

# The residentKey policy we request for every passkey registered through this
# app. Stored verbatim on each PasskeyCredential rather than inferred from the
# verification response's backup flags (see registration_options() below and
# the "Known Limitations / Fixes" section in the README for why).
RESIDENT_KEY_REQUIREMENT = ResidentKeyRequirement.REQUIRED
RESIDENT_KEY_POLICY_VALUE: str = RESIDENT_KEY_REQUIREMENT.value
IS_DISCOVERABLE: bool = RESIDENT_KEY_REQUIREMENT == ResidentKeyRequirement.REQUIRED

# In-memory challenge store keyed by email, for this single-process dev scaffold.
# Swap for Redis (or a DB table) with a short TTL before running multiple workers
# or in production.
_challenge_store: dict[str, bytes] = {}


def _store_challenge(email: str, challenge: bytes) -> None:
    _challenge_store[email] = challenge


def _pop_challenge(email: str) -> bytes | None:
    return _challenge_store.pop(email, None)


def encode_credential_id(raw_credential_id: bytes) -> str:
    return bytes_to_base64url(raw_credential_id)


def backup_flags_from_verification(verification: VerifiedRegistration) -> tuple[bool, bool]:
    """Returns (backup_eligible, backup_state) — the BE/BS authenticator flags.

    These indicate whether the credential CAN sync across devices and IS
    currently synced. They say nothing about whether it was registered as a
    resident/discoverable credential; use RESIDENT_KEY_REQUIREMENT for that.
    """
    backup_eligible = verification.credential_device_type == CredentialDeviceType.MULTI_DEVICE
    backup_state = verification.credential_backed_up
    return backup_eligible, backup_state


def build_registration_options(
    user_id: bytes, email: str, existing_credential_ids: list[str]
) -> str:
    options = generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        rp_name=settings.WEBAUTHN_RP_NAME,
        user_id=user_id,
        user_name=email,
        user_display_name=email,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=RESIDENT_KEY_REQUIREMENT,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred_id))
            for cred_id in existing_credential_ids
        ],
    )
    _store_challenge(email, options.challenge)
    return options_to_json(options)


def verify_registration(email: str, credential: dict) -> VerifiedRegistration:
    challenge = _pop_challenge(email)
    if challenge is None:
        raise ValueError("No pending registration challenge for this user")

    return verify_registration_response(
        credential=json.dumps(credential),
        expected_challenge=challenge,
        expected_origin=settings.WEBAUTHN_ORIGIN,
        expected_rp_id=settings.WEBAUTHN_RP_ID,
        require_user_verification=True,
    )


def build_authentication_options(email: str, credential_ids: list[str]) -> str:
    options = generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred_id))
            for cred_id in credential_ids
        ],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    _store_challenge(email, options.challenge)
    return options_to_json(options)


def verify_authentication(
    email: str, credential: dict, public_key: bytes, sign_count: int
) -> VerifiedAuthentication:
    challenge = _pop_challenge(email)
    if challenge is None:
        raise ValueError("No pending authentication challenge for this user")

    return verify_authentication_response(
        credential=json.dumps(credential),
        expected_challenge=challenge,
        expected_origin=settings.WEBAUTHN_ORIGIN,
        expected_rp_id=settings.WEBAUTHN_RP_ID,
        credential_public_key=public_key,
        credential_current_sign_count=sign_count,
        require_user_verification=True,
    )
