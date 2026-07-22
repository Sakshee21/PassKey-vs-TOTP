import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr


class WebAuthnRegisterFinishRequest(BaseModel):
    credential: dict[str, Any]
    device_name: str | None = None


class WebAuthnAuthenticateStartRequest(BaseModel):
    email: EmailStr


class WebAuthnAuthenticateFinishRequest(BaseModel):
    email: EmailStr
    credential: dict[str, Any]


class WebAuthnCredentialOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    resident_key_policy: str
    is_discoverable: bool
    backup_eligible: bool
    backup_state: bool
    device_name: str | None
    created_at: datetime
