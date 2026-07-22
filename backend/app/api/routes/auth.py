from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.core.security import (
    create_access_token,
    create_login_token,
    create_registration_token,
    verify_secret,
)
from app.models.user import User
from app.schemas.auth import LoginRequest, LoginResponse, Token
from app.schemas.user import UserOut

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    user = db.query(User).filter(User.email == payload.email).first()
    if user is None or user.password_hash is None or not verify_secret(
        payload.password, user.password_hash
    ):
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    if not user.is_fully_registered:
        return LoginResponse(
            registration_incomplete=True,
            registration_token=create_registration_token(user.id),
        )

    if user.is_totp_enabled:
        return LoginResponse(totp_required=True, login_token=create_login_token(user.id))

    return LoginResponse(token=Token(access_token=create_access_token(user.id, method="password")))


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user
