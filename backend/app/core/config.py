from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str = (
        "postgresql+psycopg2://passkey_user:passkey_pass@localhost:5432/passkey_vs_totp"
    )

    JWT_SECRET: str = "change-me-to-a-long-random-string"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60

    WEBAUTHN_RP_ID: str = "localhost"
    WEBAUTHN_RP_NAME: str = "PassKey vs TOTP"
    WEBAUTHN_ORIGIN: str = "http://localhost:5173"

    FRONTEND_ORIGIN: str = "http://localhost:5173"

    # Shared secret that security-demos/attack_sim.py sends as the
    # X-Attack-Sim-Token header, so the resulting auth_events rows can be
    # tagged is_simulated=true. Knowing this token doesn't bypass anything
    # (rate limiting and password checks still apply in full) - it only
    # controls a label on an audit-log row, so real traffic can't be
    # mislabeled as a demo and vice versa without it.
    ATTACK_SIM_TOKEN: str = "change-me-attack-sim-token"


settings = Settings()
