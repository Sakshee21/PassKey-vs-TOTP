from pydantic import BaseModel, EmailStr


class RegisterStartRequest(BaseModel):
    email: EmailStr
    password: str


class RegisterStartResponse(BaseModel):
    registration_token: str
    email: EmailStr


class RegisterStatusResponse(BaseModel):
    email: EmailStr
    totp_done: bool
    passkey_done: bool
