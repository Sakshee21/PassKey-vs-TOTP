from fastapi import APIRouter, Depends
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.core.database import get_db
from app.models.auth_event import AuthEvent, AuthMethod
from app.schemas.analytics import AnalyticsSummary, FailureReason, MethodStat, TimeBucket

# require_admin at the router level so every endpoint under /api/analytics -
# not just /summary - is admin-gated, including any added later.
router = APIRouter(
    prefix="/api/analytics", tags=["analytics"], dependencies=[Depends(require_admin)]
)


@router.get("/summary", response_model=AnalyticsSummary)
def analytics_summary(db: Session = Depends(get_db)) -> AnalyticsSummary:
    """Admin-only: this aggregates auth_events across ALL accounts, not just
    the caller's own - regular users must not see other accounts' attempt
    data (see require_admin on the router)."""

    by_method_rows = (
        db.query(
            AuthEvent.method,
            func.count().label("total"),
            func.sum(case((AuthEvent.success.is_(True), 1), else_=0)).label("successes"),
            func.avg(AuthEvent.latency_ms).label("avg_latency"),
        )
        .group_by(AuthEvent.method)
        .all()
    )
    stats_by_method: dict[AuthMethod, MethodStat] = {}
    for row in by_method_rows:
        total = row.total or 0
        successes = int(row.successes or 0)
        stats_by_method[row.method] = MethodStat(
            method=row.method.value,
            total_attempts=total,
            successful_attempts=successes,
            success_rate=round(successes / total * 100, 1) if total else 0.0,
            avg_latency_ms=round(float(row.avg_latency), 1) if row.avg_latency is not None else None,
        )
    # Always include every method, even with zero events, so the "passkey vs
    # totp_password" bar charts compare consistently rather than dropping bars.
    by_method = [
        stats_by_method.get(
            method,
            MethodStat(
                method=method.value,
                total_attempts=0,
                successful_attempts=0,
                success_rate=0.0,
                avg_latency_ms=None,
            ),
        )
        for method in AuthMethod
    ]

    bucket = func.date_trunc("hour", AuthEvent.timestamp)
    time_rows = (
        db.query(
            bucket.label("bucket"),
            func.count().label("attempts"),
            func.sum(case((AuthEvent.is_simulated.is_(True), 1), else_=0)).label("simulated"),
        )
        .group_by(bucket)
        .order_by(bucket)
        .all()
    )
    attempts_over_time = [
        TimeBucket(
            bucket=row.bucket.isoformat(),
            attempts=row.attempts,
            simulated_attempts=int(row.simulated or 0),
        )
        for row in time_rows
    ]

    failure_rows = (
        db.query(
            func.coalesce(AuthEvent.failure_reason, "unknown").label("reason"),
            func.count().label("count"),
        )
        .filter(AuthEvent.success.is_(False))
        .group_by("reason")
        .order_by(func.count().desc())
        .all()
    )
    failure_reasons = [FailureReason(reason=row.reason, count=row.count) for row in failure_rows]

    total_events = db.query(func.count(AuthEvent.id)).scalar() or 0
    simulated_events = (
        db.query(func.count(AuthEvent.id)).filter(AuthEvent.is_simulated.is_(True)).scalar() or 0
    )

    return AnalyticsSummary(
        by_method=by_method,
        attempts_over_time=attempts_over_time,
        failure_reasons=failure_reasons,
        total_events=total_events,
        simulated_events=simulated_events,
    )
