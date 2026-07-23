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

## Notes / production TODOs

- The WebAuthn challenge store in `app/services/webauthn_service.py` is an in-memory dict — fine for
  one dev process, but swap it for Redis (or a DB table with a TTL) before running multiple workers
  or in production.
- `Base.metadata.create_all` runs on FastAPI startup for dev convenience; Alembic (`alembic upgrade
  head`) is the source of truth for schema changes.
