"""Structural proof: a captured WebAuthn assertion cannot be replayed
against a different origin than the one it was signed for.

This is NOT a live "attack" demo - there's no bypass to show, because there
isn't one. The authenticator's signature covers `clientDataJSON`, and
`clientDataJSON.origin` records the origin the browser believed it was
talking to at signing time. py_webauthn's `verify_authentication_response`
decodes that field and compares it against `expected_origin`; if they don't
match, verification fails regardless of whether the signature itself is
valid. That's the whole property being demonstrated here.

This script replays ONE real, validly-signed assertion (captured via
`security-demos/capture_assertion.mjs`, since only a browser/authenticator
can produce a genuine signature - py_webauthn is a relying-party/server
library, it has no client simulator) against the actual `expected_origin`
it was signed for, and then against a different one, using the exact
verification function this app runs in production.

It bypasses the app's own challenge-store bookkeeping (which is single-use
by design and would make a second call fail for an unrelated reason) so the
two calls below differ in ONLY `expected_origin` - isolating the property
under test.

Usage (from backend/, with the venv active):
    python -m app.scripts.verify_origin_binding /path/to/captured_assertion.json
"""

import json
import sys
from pathlib import Path

from webauthn import verify_authentication_response
from webauthn.helpers import base64url_to_bytes

from app.core.database import SessionLocal
from app.models.passkey_credential import PasskeyCredential

EVIL_ORIGIN = "https://evil.example.com"


def load_credential_key(credential_id: str) -> tuple[bytes, int]:
    db = SessionLocal()
    try:
        cred = (
            db.query(PasskeyCredential)
            .filter(PasskeyCredential.credential_id == credential_id)
            .first()
        )
        if cred is None:
            print(f"No PasskeyCredential found for credential_id={credential_id!r}")
            print("(the DB used here must be the same one capture_assertion.mjs ran against)")
            sys.exit(1)
        # capture_assertion.mjs's real login ceremony already ran the app's own
        # verify_authentication_response once, which advances sign_count on
        # success (WebAuthn's own separate anti-replay mechanism - a signature
        # can't be reused once its counter has been consumed). By the time we
        # read the DB here, it already reflects that post-verification value,
        # one higher than what the captured assertion's authenticatorData
        # actually claims. Roll it back so the ONLY variable across the two
        # attempts below is expected_origin, not an unrelated counter check.
        return cred.public_key, max(cred.sign_count - 1, 0)
    finally:
        db.close()


def attempt(label: str, credential: dict, challenge: bytes, origin: str, rp_id: str,
            public_key: bytes, sign_count: int) -> bool:
    print(f"{label} (expected_origin={origin!r})...")
    try:
        verify_authentication_response(
            credential=json.dumps(credential),
            expected_challenge=challenge,
            expected_origin=origin,
            expected_rp_id=rp_id,
            credential_public_key=public_key,
            credential_current_sign_count=sign_count,
            require_user_verification=True,
        )
        print("  -> ACCEPTED\n")
        return True
    except Exception as exc:
        print(f"  -> REJECTED: {exc}\n")
        return False


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python -m app.scripts.verify_origin_binding <captured_assertion.json>")
        sys.exit(1)

    captured = json.loads(Path(sys.argv[1]).read_text())
    credential = captured["credential"]
    challenge = base64url_to_bytes(captured["challenge_b64url"])
    real_origin = captured["origin"]
    rp_id = captured["rp_id"]

    public_key, sign_count = load_credential_key(credential["id"])

    print(f"Captured assertion was signed for origin: {real_origin!r}\n")

    same_origin_ok = attempt(
        "Attempt 1: replaying against the SAME origin it was signed for",
        credential, challenge, real_origin, rp_id, public_key, sign_count,
    )
    if not same_origin_ok:
        print("UNEXPECTED: the real origin should have been accepted. Re-capture and retry")
        print("(sign_count may have advanced since capture, or the DB doesn't match).")
        sys.exit(1)

    cross_origin_ok = attempt(
        f"Attempt 2: replaying the SAME assertion against a DIFFERENT origin",
        credential, challenge, EVIL_ORIGIN, rp_id, public_key, sign_count,
    )
    if cross_origin_ok:
        print("THIS WOULD BE A BUG: cross-origin replay must never succeed.")
        sys.exit(1)

    print("Conclusion: the same captured assertion is accepted for the origin it was")
    print("signed for, and rejected for every other origin - not because of a rate limit")
    print("or a revoked credential, but because `clientDataJSON.origin` is part of what")
    print("the authenticator's signature covers. A captured assertion cannot be replayed")
    print("anywhere else without invalidating that check. There is no bypass to")
    print("demonstrate here; the absence of one is the proof.")


if __name__ == "__main__":
    main()
