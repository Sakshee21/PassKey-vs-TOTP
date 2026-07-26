# Security demos

Two demonstrations, deliberately different in kind:

1. **`attack_sim.py`** - a genuine simulated attack. It sends real requests
   against a real (mis)behavior in this app (a reusable `password_token`)
   and shows rate limiting cutting it short.
2. **`capture_assertion.mjs` + `verify_origin_binding.py`** - not an attack
   at all. There's no bypass to demonstrate for WebAuthn origin-binding, so
   instead of faking one, this proves the defense structurally: one real
   signed assertion, checked against the correct origin (accepted) and a
   different one (rejected), using the app's actual verification code.

Both are read-only with respect to real user data - they create their own
throwaway test accounts (`attack-sim-victim-*@example.com`,
`origin-proof-*@example.com`) and only touch those.

## 1. Credential stuffing + rate limiting (`attack_sim.py`)

### Why this isn't the "normal" credential-stuffing story

This app checks the second factor (TOTP or a backup code) **before** the
password (see the main README). A classic credential-stuffing attacker -
someone with a leaked email/password list and nothing else - cannot reach
`/auth/login` at all without first supplying a valid TOTP code, which they
don't have. That's a real structural benefit of the flipped order, and this
demo doesn't pretend otherwise.

The residual risk it demonstrates: `/totp/verify` hands out a
`password_token` (a JWT, valid 5 minutes) once the TOTP step passes. That
token is **not single-use** - nothing stops it from being replayed against
`/auth/login` repeatedly until it expires. So an attacker who obtains *one*
valid token (phished/observed TOTP code, intercepted token, whatever) can
spend the rest of its 5-minute lifetime trying passwords against it. Rate
limiting (5/minute per IP, `app/core/rate_limit.py`) is what actually bounds
that exposure to a handful of guesses instead of an entire wordlist.

### Running it

```bash
# 1. Provision a fully-registered target account (needs a real passkey
#    ceremony, hence Node/Puppeteer rather than pure Python):
cd security-demos
npm install puppeteer-core
node setup_victim.mjs --out victim.json

# 2. Run the attack simulation against it:
pip install -r requirements.txt
python attack_sim.py --from-file victim.json --sim-token <backend's ATTACK_SIM_TOKEN>
```

> **Use `--out victim.json`, not `> victim.json`.** Shell output redirection
> writes text in whatever encoding the shell defaults to - Windows
> PowerShell's `>` uses UTF-16, which silently produces a file
> `attack_sim.py` can't parse as JSON. `--out` has the script write the file
> itself (plain UTF-8), so it's safe from any shell.
>
> **On Windows with the repo on a WSL filesystem** (`\\wsl.localhost\...`):
> run `setup_victim.mjs` and `capture_assertion.mjs` from a Windows-native
> terminal (PowerShell, Git Bash, cmd), not from inside WSL - Puppeteer needs
> to read Chrome's debug-port URL back from its own stdout, and that
> handshake doesn't survive the WSL→Windows process boundary when Chrome
> itself is a Windows binary. `attack_sim.py` and `verify_origin_binding.py`
> have no such restriction; run those from wherever's convenient.

Omit `--sim-token` and it still works identically, just without the
`is_simulated=true` tag on the resulting `auth_events` rows (so it won't be
labeled as simulated on the analytics dashboard, but the requests - and
the rate limiting - are exactly the same either way).

Expected output: 5 attempts go through normally (each a real password
check against the real password hash), then a `429` on the 6th, well before
`common_passwords.txt`'s real entry (`Summer2024!`, deliberately placed at
position 11) is ever tried.

### Verifying on the dashboard

Log in as an admin (see the main README's Analytics section) and open
`/analytics`. With `--sim-token` set, the run shows up as a labeled spike on
"Login attempts over time" (a separate red line, distinct from real
traffic) and the top summary line calls out how many of the logged events
were simulated.

## 2. Passkey origin-binding (`capture_assertion.mjs` + `verify_origin_binding.py`)

### What this proves

A WebAuthn assertion's signature covers `clientDataJSON`, which embeds the
origin the browser believed it was talking to. The relying party (this
app's backend, via py_webauthn's `verify_authentication_response`) checks
that field against its own configured origin. If a captured assertion is
replayed against any other origin, that check fails - not because of a
nonce, a rate limit, or a revoked credential, but because the field being
compared is part of what the authenticator already signed. There is no
attack to demonstrate here; the point is that there isn't one.

### Running it

```bash
# 1. Capture one real, validly-signed assertion (needs a real browser +
#    virtual authenticator, driven the same way as setup_victim.mjs):
cd security-demos
node capture_assertion.mjs --out captured_assertion.json

# 2. Replay it against the real origin, then a different one:
cd ../backend
source .venv/bin/activate
python -m app.scripts.verify_origin_binding ../security-demos/captured_assertion.json
```

(Same `--out`-not-`>` and Windows-terminal notes as above apply here too.)

Expected output: "ACCEPTED" against the origin it was actually signed for
(`http://localhost:5173` by default), "REJECTED" against
`https://evil.example.com` - using the exact same assertion both times, so
the only variable is the origin being checked against.
