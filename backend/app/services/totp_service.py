import secrets

import pyotp

from app.core.config import settings
from app.core.security import hash_secret

BACKUP_CODE_COUNT = 10
BACKUP_CODE_LENGTH = 10


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_provisioning_uri(secret: str, email: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=email, issuer_name=settings.WEBAUTHN_RP_NAME
    )


def verify_totp_code(secret: str, code: str) -> bool:
    return pyotp.totp.TOTP(secret).verify(code, valid_window=1)


def generate_backup_codes() -> list[str]:
    """Plaintext codes to show the user once; caller must store their hashes."""
    return [secrets.token_hex(BACKUP_CODE_LENGTH // 2) for _ in range(BACKUP_CODE_COUNT)]


def hash_backup_codes(codes: list[str]) -> list[str]:
    return [hash_secret(code) for code in codes]
