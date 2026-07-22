import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.user import User


class PasskeyCredential(Base):
    """A single registered passkey/authenticator for a user."""

    __tablename__ = "passkey_credentials"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    # base64url-encoded credential ID returned by the authenticator.
    credential_id: Mapped[str] = mapped_column(String(512), unique=True, index=True, nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # The residentKey requirement we actually asked the authenticator for at
    # registration time ("required" / "preferred" / "discouraged") — not
    # inferred after the fact. See is_discoverable below.
    resident_key_policy: Mapped[str] = mapped_column(String(20), nullable=False)
    # Whether we required (and therefore know we got) a discoverable/resident
    # credential. Derived from resident_key_policy at registration time, not
    # from the authenticator's backup flags.
    is_discoverable: Mapped[bool] = mapped_column(Boolean, nullable=False)

    # Honest labels for the authenticator data's BE/BS flags. These describe
    # whether the credential CAN sync across devices (backup_eligible) and IS
    # currently synced (backup_state) — a different axis from resident-key-ness.
    backup_eligible: Mapped[bool] = mapped_column(Boolean, nullable=False)
    backup_state: Mapped[bool] = mapped_column(Boolean, nullable=False)

    # Optional user-supplied label, e.g. "Work laptop" — helps distinguish
    # credentials when a user registers more than one.
    device_name: Mapped[str | None] = mapped_column(String(128), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    user: Mapped["User"] = relationship(back_populates="passkey_credentials")
