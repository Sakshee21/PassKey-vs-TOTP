# PassKey vs TOTP

A demo app comparing two second-factor / passwordless auth methods:

- **Passkeys (WebAuthn)** via [`py_webauthn`](https://github.com/duo-labs/py_webauthn) (backend) and
  [`@simplewebauthn/browser`](https://github.com/MasterKale/SimpleWebAuthn) (frontend)
- **TOTP** (authenticator app codes) via [`pyotp`](https://github.com/pyauth/pyotp), with bcrypt-hashed
  one-time backup codes

## Stack

- **Backend:** FastAPI, SQLAlchemy 2.0, PostgreSQL, Alembic, PyJWT, bcrypt
- **Frontend:** React + TypeScript + Vite

## Project layout

```
backend/
  app/
    core/       # settings, DB session, password hashing, JWT
    models/     # SQLAlchemy models: User, PasskeyCredential, BackupCode, AuthEvent
    schemas/    # Pydantic request/response models
    services/   # TOTP and WebAuthn business logic
    api/routes/ # FastAPI routers: auth, register, totp, webauthn
  alembic/      # DB migrations
  requirements.txt
  .env.example
frontend/
  src/
    lib/        # API client, auth helpers, types
    pages/      # AuthPage (sign in), RegisterWizard (3-step signup),
                # RecoveryFlow (lost passkey), Dashboard (protected /dashboard route)
  .env.example
docker-compose.yml   # local Postgres
.env.example         # docker-compose Postgres credentials
security-demos/       # standalone: credential-stuffing + rate-limit demo, WebAuthn
                       # origin-binding proof (not part of the running app)
```

## Local setup

**Docker is optional.** It's only used to run Postgres — the app itself (backend, frontend) never
runs in a container. `docker-compose.yml` exists purely as a convenient, disposable way to get a
Postgres matching `backend/.env.example`'s defaults. If you already have Postgres (native install,
WSL, a cloud instance, whatever), skip Docker entirely and just point `DATABASE_URL` at it.

### 1. Get a Postgres

**With Docker:**

```bash
cp .env.example .env
docker compose up -d postgres
```

**Without Docker** — use any Postgres you already have. Create a matching user/db (or reuse
whatever credentials you already have and adjust `DATABASE_URL` in step 2 accordingly):

```bash
createuser passkey_user -P    # prompts for a password; use "passkey_pass" to match the example env, or pick your own
createdb passkey_vs_totp -O passkey_user
```

Either way, the only thing the backend actually needs is a reachable `DATABASE_URL` — how the
Postgres behind it got there doesn't matter.

### 2. Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate        # .venv\Scripts\activate on Windows
pip install -r requirements.txt

cp .env.example .env             # adjust DATABASE_URL/JWT_SECRET if needed
alembic upgrade head             # create tables

uvicorn app.main:app --reload --port 8000
```

API docs: http://localhost:8000/docs

### 3. Frontend

```bash
cd frontend
npm install
cp .env.example .env             # points VITE_API_BASE_URL at the backend
npm run dev
```

App: http://localhost:5173

> WebAuthn/passkeys require the frontend origin to match `WEBAUTHN_ORIGIN` /
> `WEBAUTHN_RP_ID` in `backend/.env` (defaults assume `localhost:5173`), and a
> platform authenticator (Windows Hello, Touch ID, a security key, etc.) or a
> password-manager passkey provider available to the browser.

## Auth flows implemented

- **Registration wizard** (`/register/*`, frontend `RegisterWizard`) — a new account MUST complete
  all three steps, in order: email+password → TOTP (QR code, confirmed before it's saved, 10
  bcrypt-hashed backup codes issued) → a passkey (WebAuthn, discoverable/resident required). The
  account only counts as fully registered — and can only get a real access token — once all three
  are done; abandoning partway through resumes where you left off next time you try to log in.
- **Password + TOTP login** — deliberately reversed order: the second factor is verified *first*,
  the password *last*. `/totp/verify` or `/totp/verify-backup-code` take `{email, code}` (no
  password) and return a short-lived `password_token`; `/auth/login` then takes
  `{password_token, password}` and issues the real access token. Every fully-registered account has
  TOTP enabled, so this is the only password-login path.
- **Passkey login** (`/webauthn/authenticate/*`) — a single WebAuthn ceremony, no password step, no
  ordering to speak of.
- **Account recovery** (frontend `RecoveryFlow`, "Lost your passkey?" on the sign-in page) — same
  flipped order as above (TOTP-or-backup-code, then password) to prove identity, then offers to
  register a replacement passkey. Backup codes are single-use (`used` flips to `true` on
  consumption) and the UI warns once fewer than 3 remain; regenerate a fresh set of 10 anytime from
  the dashboard.
- **Dashboard** (`/dashboard`, JWT-gated — redirects to `/` without a valid session) — shows which
  method authenticated *this session* (read from a `method` claim on the access token: passkey /
  password+TOTP / password+backup-code), an account overview (passkeys, backup codes remaining,
  TOTP status), and management actions (add another passkey, regenerate backup codes).
- **Analytics** (`/analytics`, **admin-only**) — aggregates `auth_events` across all accounts
  (success rate and average latency by method, login attempts over time, failure-reason breakdown).
  Restricted to accounts with `role="admin"` on the `users` table:
  - There is **no separate admin login** — an admin authenticates through the exact same
    passkey / password+TOTP infrastructure as everyone else. `role` only changes what an
    already-authenticated account is allowed to see, not how it signs in.
  - Enforced on the backend via a `require_admin` dependency (`app/api/deps.py`), applied at the
    router level to everything under `/api/analytics/*`, checked against the JWT-*resolved* User
    (a fresh DB lookup on every request) rather than a claim baked into the token — so a revoked
    admin role takes effect on the next request, not just at next login.
  - Enforced on the frontend too (hides the nav link for non-admins; a non-admin hitting
    `/analytics` directly sees an explicit 403 state, not a silent redirect) — but the backend
    check is what actually matters; the frontend gate is just UX.
  - **Promoting an account to admin** is a one-off DB update, not a feature:
    ```bash
    cd backend && source .venv/bin/activate
    python -m app.scripts.promote_admin someone@example.com
    ```

## Security

- **Rate limiting** ([slowapi](https://github.com/laurentS/slowapi), 5 requests/minute per IP,
  `app/core/rate_limit.py`) on every step of password-based login — `/auth/login`, `/totp/verify`,
  `/totp/verify-backup-code` — returns `429` past the limit. In-memory storage, fine for one dev
  process; swap for a Redis backend before running multiple workers.
- **`security-demos/`** (see its own README) — two standalone demos, deliberately different in
  kind:
  - `attack_sim.py` — a genuine simulated credential-stuffing run against `/auth/login`, showing
    rate limiting cut it off. Its traffic can be tagged `is_simulated=true` on `auth_events` (via a
    shared `X-Attack-Sim-Token` header, checked against the backend's `ATTACK_SIM_TOKEN`), so it
    shows up as a clearly labeled spike on the analytics dashboard instead of blending into real
    login attempts.
  - `capture_assertion.mjs` + `verify_origin_binding.py` — **not** an attack demo. There's no
    bypass to show for WebAuthn's origin binding, so instead of faking one, this proves the
    property structurally: one real signed assertion, accepted against the origin it was signed
    for and rejected against a different one, using the app's actual verification code.

## Known Limitations / Fixes

- **Passkey "resident/discoverable" status is stored, not inferred.** An earlier version stored a
  `device_type` ("resident"/"non-resident") on each `PasskeyCredential`, guessed from the
  authenticator's backup-eligible/backup-state (BE/BS) flags via py_webauthn's
  `credential_device_type` / `credential_backed_up`. That's wrong: BE/BS describe whether a
  credential *can sync* and *is currently synced* across devices (e.g. iCloud Keychain, a password
  manager) — a different axis from whether it was registered as a resident/discoverable credential.
  This was caught in testing: a virtual authenticator configured with `hasResidentKey: true` was
  still reported "non-resident" because the code was reading sync flags, not the actual
  resident-key registration outcome.

  Fixed by storing what we *know* at registration time instead of guessing after the fact:
  `resident_key_policy` (the `residentKey` value we explicitly requested — always `"required"` now,
  see `RESIDENT_KEY_REQUIREMENT` in `app/services/webauthn_service.py`) and `is_discoverable`
  (derived from that policy, not from the verification response). `backup_eligible` and
  `backup_state` are kept as their own honestly-labeled columns — the sync-status signal is still
  useful, it's just no longer used to answer a question it can't actually answer.

- **`password_token` is reusable, not single-use.** Once `/totp/verify` (or `/totp/verify-backup-code`)
  issues a `password_token`, it's a stateless JWT valid for 5 minutes — nothing currently
  invalidates it after a failed `/auth/login` attempt, so it can be tried against multiple
  passwords within that window. `security-demos/attack_sim.py` demonstrates this directly: one
  phished TOTP pass, then several password guesses against the same token. Rate limiting (above)
  bounds the exposure to a handful of guesses per minute, but a stronger fix would be marking the
  token consumed after its first use (or first failure) — not done here, since the explicit ask was
  rate limiting as the mitigation, not a token-lifecycle change.

## Notes / production TODOs

- The WebAuthn challenge store in `app/services/webauthn_service.py` is an in-memory dict — fine for
  one dev process, but swap it for Redis (or a DB table with a TTL) before running multiple workers
  or in production.
- `Base.metadata.create_all` runs on FastAPI startup for dev convenience; Alembic (`alembic upgrade
  head`) is the source of truth for schema changes.
