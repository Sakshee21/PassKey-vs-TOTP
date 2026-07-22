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


settings = Settings()
