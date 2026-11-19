"""Vigía detection engine: loads YAML rules and evaluates them against incoming logs."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from app.models import Alert, StoredLog

# backend/app/detection.py -> parents[2] = repo root (vigia/)
RULES_DIR = Path(__file__).resolve().parents[2] / "detections"


def load_rules(rules_dir: Path = RULES_DIR) -> list[dict]:
    """Read every .yml file in the detections folder."""
    rules = []
    for path in sorted(rules_dir.glob("*.yml")):
        with path.open(encoding="utf-8") as file:
            rules.append(yaml.safe_load(file))
    return rules


def event_time(log: StoredLog) -> datetime:
    """Use when the event happened if know, otherwise when we received it."""
    moment = log.event_time or log.received_at
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def matches_rule(log: StoredLog, rule: dict) -> bool:
    return (
        log.source.value == rule ["logsource"]
        and rule["detection"]["message_contains"] in log.message
    )


class DetectionEngine:
    def __init__(self, rules: list[dict]):
        self.rules = rules
        self.alerts: list[Alert] = []

    def process(self, new_log: StoredLog, logs: list[StoredLog]) -> list[Alert]:
        """Evaluate every rule against the new log. Returns only NEW alerts."""
        new_alerts = []
        for rule in self.rules:
            if not matches_rule(new_log, rule):
                continue

            detection = rule["detection"]
            group_field = detection["group_by"]
            group_value = getattr(new_log, group_field)
            if group_value is None:
                continue

            now = event_time(new_log)
            windows_start = now - timedelta(seconds=detection["timeframe_seconds"])
            hits = [
                log for log in logs
                if matches_rule(log, rule)
                and getattr(log, group_field) == group_value
                and windows_start <= event_time(log) <= now
            ]
            if len(hits) < detection["threshold"]:
                continue

            # Deduplication: same attack still going -> update, don't spam alerts
            open_alert = self._find_open_alert(rule["id"], group_value, windows_start)
            if open_alert:
                open_alert.event_count += 1
                open_alert.last_seen = now
                continue

            alert = Alert(
                id=len(self.alerts) + 1,
                rule_id=rule["id"],
                title=rule["title"],
                severity=rule["severity"],
                mitre_tactic=rule["mitre"]["tactic"],
                mitre_technique=rule["mitre"]["technique"],
                mitre_technique_name=rule["mitre"]["technique_name"],
                source_ip=str(group_value),
                event_count=len(hits),
                first_seen=min(event_time(log) for log in hits),
                last_seen=now,
                created_at=datetime.now(timezone.utc),
            )
            self.alerts.append(alert)
            new_alerts.append(alert)
        return new_alerts

    def _find_open_alert(self, rule_id: str, group_value: str, window_start: datetime):
        for alert in self.alerts:
            if (
                alert.rule_id == rule_id
                and alert.source_ip == group_value
                and alert.last_seen >= window_start
            ):
                return alert
        return None