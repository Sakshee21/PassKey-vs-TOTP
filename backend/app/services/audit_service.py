import uuid

from fastapi import Request
from sqlalchemy.orm import Session

from app.models.auth_event import AuthEvent, AuthMethod


def log_auth_event(
    db: Session,
    *,
    user_id: uuid.UUID | None,
    method: AuthMethod,
    success: bool,
    latency_ms: int,
    request: Request | None,
    failure_reason: str | None = None,
) -> None:
    """Records one row per *logical* login attempt (not per HTTP request) -
    for the flipped-order TOTP+password flow, that's only once the attempt
    actually concludes, at whichever step succeeds or terminally fails.
    Commits immediately so a failure path (which otherwise has nothing else
    to commit) still gets logged."""
    db.add(
        AuthEvent(
            user_id=user_id,
            method=method,
            success=success,
            latency_ms=latency_ms,
            ip_address=request.client.host if request and request.client else None,
            user_agent=request.headers.get("user-agent") if request else None,
            failure_reason=failure_reason,
        )
    )
    db.commit()
