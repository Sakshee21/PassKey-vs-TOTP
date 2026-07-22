import uuid

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import decode_token
from app.models.user import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def user_from_token(token: str, purpose: str, db: Session) -> User:
    """Resolve a user from a JWT of the given purpose, or raise 401."""
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token)
        if payload.get("purpose") != purpose:
            raise unauthorized
        user_id = uuid.UUID(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise unauthorized

    user = db.get(User, user_id)
    if user is None:
        raise unauthorized
    return user


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    return user_from_token(token, "access", db)


def get_registration_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    user = user_from_token(token, "registration_pending", db)
    if user.is_fully_registered:
        raise HTTPException(status_code=400, detail="Registration already complete")
    return user
