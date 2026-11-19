from datetime import datetime, timedelta, timezone

from app.detection import DetectionEngine, load_rules
from app.models import StoredLog

BASE_TIME = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
FAILED = "Failed password for root from 203.0.113.5 port 22 ssh2"


def make_log(i, ip="203.0.113.5", message=FAILED, seconds=0):
    return StoredLog(
        id=i, source="ssh", level="warning", message=message,
        source_ip=ip, received_at=BASE_TIME + timedelta(seconds=seconds),
    )


def run(logs):
    engine = DetectionEngine(load_rules())
    store, alerts = [], []
    for log in logs:
        store.append(log)
        alerts += engine.process(log, store)
    return engine, alerts


def test_five_failures_in_window_trigger_alert():
    _, alerts = run([make_log(i, seconds=i) for i in range(5)])
    assert len(alerts) == 1
    assert alerts[0].mitre_technique == "T1110.001"
    assert alerts[0].source_ip == "203.0.113.5"


def test_four_failures_do_not_trigger():
    _, alerts = run([make_log(i, seconds=i) for i in range(4)])
    assert alerts == []


def test_slow_attempts_outside_window_do_not_trigger():
    _, alerts = run([make_log(i, seconds=i * 30) for i in range(5)])
    assert alerts == []


def test_failures_from_different_ips_do_not_trigger():
    _, alerts = run([make_log(i, ip=f"198.51.100.{i}") for i in range(5)])
    assert alerts == []


def test_ongoing_attack_is_deduplicated():
    engine, alerts = run([make_log(i, seconds=i) for i in range(10)])
    assert len(alerts) == 1
    assert engine.alerts[0].event_count == 10


def test_successful_logins_are_ignored():
    ok = "Accepted password for root from 203.0.113.5 port 22 ssh2"
    _, alerts = run([make_log(i, message=ok) for i in range(10)])
    assert alerts == []
