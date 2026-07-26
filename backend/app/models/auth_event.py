import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.core.database import Base


class AuthMethod(str, enum.Enum):
    PASSKEY = "passkey"
    TOTP_PASSWORD = "totp_password"


class AuthEvent(Base):
    """Audit log entry for a single authentication attempt."""

    __tablename__ = "auth_events"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Nullable: a failed attempt (e.g. unknown email) may not resolve to a user.
    # ON DELETE SET NULL keeps the audit trail if the user is later deleted.
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    method: Mapped[AuthMethod] = mapped_column(Enum(AuthMethod, name="auth_method"), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # True only for traffic from security-demos/attack_sim.py (proven via a
    # shared token, see app/api/deps.py:is_simulated_request) - lets the
    # analytics dashboard's charts include a labeled, distinguishable spike
    # from a simulated attack run rather than silently mixing it with real
    # login attempts.
    is_simulated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
