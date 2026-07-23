import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.backup_code import BackupCode
    from app.models.passkey_credential import PasskeyCredential


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)

    # Nullable: a user may register with a passkey only and never set a password.
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Only ever set once a TOTP code has been confirmed; its presence is what
    # "TOTP enabled" means (see the is_totp_enabled property below).
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Plain string, not a DB enum, by design - "user" or "admin". Promotion is
    # a one-off DB update (see app/scripts/promote_admin.py), not a feature.
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="user", server_default="user")

    passkey_credentials: Mapped[list["PasskeyCredential"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    backup_codes: Mapped[list["BackupCode"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def is_totp_enabled(self) -> bool:
        return self.totp_secret is not None

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_fully_registered(self) -> bool:
        """True once all three registration steps (password, TOTP, passkey) are done."""
        return (
            self.password_hash is not None
            and self.totp_secret is not None
            and len(self.passkey_credentials) > 0
        )
