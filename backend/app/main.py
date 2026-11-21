from datetime import datetime, timezone

from fastapi import FastAPI, Query

from app.detection import DetectionEngine, load_rules
from app.models import Alert, LogEntry, LogIngestResponse, Severity,StoredLog

app = FastAPI(
    title="Vigía API",
    version="0.1.0",
    description="Lightweight attack detection for small businesses.",
)

# In-memory storage (PostgreSQL comes later)
log_database: list[StoredLog] = []
engine = DetectionEngine(load_rules())


@app.get("/health")
def health():
    return {"status": "ok", "rules_loaded": len(engine.rules)}


@app.post("/api/v1/logs", response_model=LogIngestResponse, status_code=201)
def ingest_log(entry: LogEntry):
    stored = StoredLog(
        **entry.model_dump(),
        id=len(log_database) + 1,
        received_at=datetime.now(timezone.utc),
    )
    log_database.append(stored)
    new_alerts = engine.process(stored, log_database)
    return LogIngestResponse(
        id=stored.id,
        message="Log ingested successfully",
        alerts_triggered=len(new_alerts),
    )


@app.get("/api/v1/logs", response_model=list[StoredLog])
def list_logs(limit: int = Query(100, ge=1, le=500)):
    return log_database[-limit:]


@app.get("/api/v1/alerts", response_model=list[Alert])
def list_alerts(severity: Severity | None = None):
    if severity is None:
        return engine.alerts
    return [alert for alert in engine.alerts if alert.severity == severity]


@app.get("/api/v1/rules")
def list_rules():
    return engine.rules
