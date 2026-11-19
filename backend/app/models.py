from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field

class LogSource(str, Enum):
    NGINX = "nginx"
    SSH = "ssh"
    APP = "app"

class LogLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class LogEntry(BaseModel):
    """A log event that Vigía ingests and then analyzes."""
    id: int | None = None
    source: LogSource
    level: LogLevel = LogLevel.INFO
    message: str = Field(..., min_length=1, max_length=2000)
    source_ip: str | None = None
    raw: str | None = None
    event_time: datetime | None = None
    received_at: datetime | None = None

class LogIngestResponse(BaseModel):
    id: int
    message: str