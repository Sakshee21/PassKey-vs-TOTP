from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import models  # noqa: F401  (registers models on Base.metadata)
from app.api.routes import analytics, auth, register, totp, webauthn
from app.core.config import settings
from app.core.database import Base, engine

app = FastAPI(title=settings.WEBAUTHN_RP_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(register.router)
app.include_router(totp.router)
app.include_router(webauthn.router)
app.include_router(analytics.router)


@app.on_event("startup")
def on_startup() -> None:
    # Dev convenience only; use Alembic migrations in production.
    Base.metadata.create_all(bind=engine)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
