from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app import models  # noqa: F401  (registers models on Base.metadata)
from app.api.routes import analytics, auth, register, totp, webauthn
from app.core.config import settings
from app.core.database import Base, engine
from app.core.rate_limit import limiter

app = FastAPI(title=settings.WEBAUTHN_RP_NAME)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

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
