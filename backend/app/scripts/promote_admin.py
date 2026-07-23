"""One-off script to promote an existing account to role="admin".

There is no separate admin registration flow - an admin signs up and signs in
through the exact same passkey / password+TOTP infrastructure as everyone
else. This script only flips the `role` column on an already-registered
account; it doesn't create a user or touch auth at all.

Usage (from backend/, with the venv active):
    python -m app.scripts.promote_admin someone@example.com
"""

import sys

from app.core.database import SessionLocal
from app.models.user import User


def promote(email: str) -> None:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if user is None:
            print(f"No user found with email {email!r}")
            sys.exit(1)
        if not user.is_fully_registered:
            print(
                f"Warning: {email!r} hasn't finished the registration wizard yet "
                "(missing password, TOTP, and/or a passkey). Promoting anyway."
            )
        user.role = "admin"
        db.commit()
        print(f"{email} promoted to admin.")
    finally:
        db.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m app.scripts.promote_admin <email>")
        sys.exit(1)
    promote(sys.argv[1])
