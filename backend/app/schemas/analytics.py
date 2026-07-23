from pydantic import BaseModel


class MethodStat(BaseModel):
    method: str
    total_attempts: int
    successful_attempts: int
    success_rate: float
    avg_latency_ms: float | None


class TimeBucket(BaseModel):
    bucket: str
    attempts: int


class FailureReason(BaseModel):
    reason: str
    count: int


class AnalyticsSummary(BaseModel):
    by_method: list[MethodStat]
    attempts_over_time: list[TimeBucket]
    failure_reasons: list[FailureReason]
    total_events: int
