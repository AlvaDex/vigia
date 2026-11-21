from datetime import datetime, timedelta, timezone

from app.detection import DetectionEngine, load_rules
from app.models import LogSource, StoredLog

BASE = datetime(2026, 11, 21, 22, 0, tzinfo=timezone.utc)
RULE_ID = "VIG-0002"


def make_log(log_id: int, ip: str, path: str, seconds: int = 0) -> StoredLog:
    moment = BASE + timedelta(seconds=seconds)
    return StoredLog(
        id=log_id,
        source=LogSource.nginx,
        level="warning",
        message=f"GET {path} HTTP/1.1 404",
        source_ip=ip,
        event_time=moment,
        received_at=moment,
    )


def run(logs: list[StoredLog]) -> list:
    """Feed logs one by one, like the API does. Return VIG-0002 alerts."""
    engine = DetectionEngine(load_rules())
    stored = []
    alerts = []
    for log in logs:
        stored.append(log)
        alerts += engine.process(log, stored)
    return [alert for alert in alerts if alert.rule_id == RULE_ID]


def test_four_probes_do_not_alert():
    logs = [make_log(i, "203.0.113.10", "/admin", i) for i in range(4)]
    assert run(logs) == []


def test_fifth_probe_creates_alert():
    logs = [make_log(i, "203.0.113.11", "/admin", i) for i in range(5)]
    alerts = run(logs)
    assert len(alerts) == 1
    assert alerts[0].mitre_technique == "T1595.003"
    assert alerts[0].severity == "medium"
    assert alerts[0].event_count == 5


def test_probes_from_different_ips_are_not_grouped():
    logs = [make_log(i, f"203.0.113.{20 + i}", "/admin", i) for i in range(5)]
    assert run(logs) == []


def test_probes_outside_time_window_do_not_alert():
    # One request every 30 s: never 5 inside the same 60 s window
    logs = [make_log(i, "203.0.113.30", "/admin", i * 30) for i in range(5)]
    assert run(logs) == []


def test_normal_paths_do_not_alert():
    logs = [make_log(i, "203.0.113.40", "/index.html", i) for i in range(10)]
    assert run(logs) == []


def test_mixed_sensitive_paths_count_together():
    paths = ["/admin", "/.env", "/wp-login.php", "/.git/config", "/phpmyadmin"]
    logs = [make_log(i, "203.0.113.50", path, i) for i, path in enumerate(paths)]
    assert len(run(logs)) == 1
