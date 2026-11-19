from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class LogSource(str, Enum):
    nginx = "nginx"
    ssh = "ssh"
    app = "app"


class LogLevel(str, Enum):
    info = "info"
    warning = "warning"
    error = "error"
    critical = "critical"


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class LogEntry(BaseModel):
    """What a client sends to the API."""
    source: LogSource
    level: LogLevel = LogLevel.info
    message: str = Field(min_length=1, max_length=5000)
    source_ip: str | None = None
    raw: str | None = None
    event_time: datetime | None = None


class StoredLog(LogEntry):
    """A log once Vigía has saved it."""
    id: int
    received_at: datetime


class LogIngestResponse(BaseModel):
    id: int
    message: str
    alerts_triggered: int = 0


class Alert(BaseModel):
    id: int
    rule_id: str
    title: str
    severity: Severity
    mitre_tactic: str
    mitre_technique: str
    mitre_technique_name: str
    source_ip: str
    event_count: int
    first_seen: datetime
    last_seen: datetime
    created_at: datetime