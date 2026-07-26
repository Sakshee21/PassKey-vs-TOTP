import uuid

import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.security import decode_token
from app.models.user import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def is_simulated_request(
    x_attack_sim_token: str | None = Header(default=None),
) -> bool:
    """True only if the caller presents the exact shared ATTACK_SIM_TOKEN -
    lets security-demos/attack_sim.py tag the auth_events rows it produces as
    is_simulated=true. Doesn't grant any access; it only affects a label on
    an audit-log row, and only when the caller proves it knows the token."""
    return x_attack_sim_token is not None and x_attack_sim_token == settings.ATTACK_SIM_TOKEN


def decode_purpose_token(token: str, purpose: str) -> dict:
    """Decode a JWT and check its `purpose` claim, or raise 401. Returns the
    full payload so callers needing extra claims (e.g. `second_factor`) don't
    have to decode twice."""
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token)
        if payload.get("purpose") != purpose:
            raise unauthorized
    except jwt.PyJWTError:
        raise unauthorized
    return payload


def user_from_token(token: str, purpose: str, db: Session) -> User:
    """Resolve a user from a JWT of the given purpose, or raise 401."""
    payload = decode_purpose_token(token, purpose)
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        user_id = uuid.UUID(payload["sub"])
    except (KeyError, ValueError):
        raise unauthorized

    user = db.get(User, user_id)
    if user is None:
        raise unauthorized
    return user


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    return user_from_token(token, "access", db)


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Checks the role on the JWT-resolved User (a fresh DB lookup via
    get_current_user), not just that the JWT is valid - a revoked admin role
    is rejected on the very next request, not just at token-issue time."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


def get_registration_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    user = user_from_token(token, "registration_pending", db)
    if user.is_fully_registered:
        raise HTTPException(status_code=400, detail="Registration already complete")
    return user
