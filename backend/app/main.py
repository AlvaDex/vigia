from fastapi import FastAPI, HTTPException
from datetime import datetime, timezone
from app.models import LogEntry, LogIngestResponse

app = FastAPI(
    title="Vigía API",
    description="Lightweight attack detection platform",
    version="0.1.0",
)

# in-memory database (temporary; I'll switch to PostgreSQL later)
log_database: list[LogEntry] = []

@app.get("/health")
def health_check():
    return {"status": "ok", "service":"vigia", "timestamp":datetime.now(timezone.utc)}

@app.post("/api/v1/logs", response_model=LogIngestResponse, status_code=201)
def ingest_log(log: LogEntry):
    """It receives a log, assigns it an ID and a timestamp, and saves it."""
    entry = log.model_copy(update={
        "id": len(log_database) + 1,
        "received_at": datetime.now(timezone.utc),
    })
    log_database.append(entry)
    return LogIngestResponse(id=entry.id, message="Log ingested sucessfully")

@app.get("/api/v1/logs", response_model=list[LogEntry])
def list_logs(limit: int = 50):
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 500")
    return log_database[-limit:]