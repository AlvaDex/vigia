from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_reports_rules_loaded():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["rules_loaded"] >= 1


def test_ingest_valid_log_returns_201():
    response = client.post("/api/v1/logs", json={
        "source": "app", "level": "info", "message": "User session created",
    })
    assert response.status_code == 201
    assert "id" in response.json()


def test_ingest_rejects_unknown_source():
    response = client.post("/api/v1/logs", json={"source": "facebook", "message": "x"})
    assert response.status_code == 422


def test_brute_force_through_api_creates_alert():
    ip = "198.51.100.99"
    for i in range(5):
        client.post("/api/v1/logs", json={
            "source": "ssh", "level": "warning",
            "message": f"Failed password for admin from {ip} port {40000 + i} ssh2",
            "source_ip": ip,
        })
    alerts = client.get("/api/v1/alerts").json()
    assert any(a["source_ip"] == ip and a["mitre_technique"] == "T1110.001" for a in alerts)


def test_admin_probe_through_api_creates_alert():
    ip = "203.0.113.77"
    for path in ["/admin", "/.env", "/wp-login.php", "/.git/config", "/phpmyadmin"]:
        client.post("/api/v1/logs", json={
            "source": "nginx", "level": "warning",
            "message": f"GET {path} HTTP/1.1 404",
            "source_ip": ip,
        })
    alerts = client.get("/api/v1/alerts").json()
    assert any(a["source_ip"] == ip and a["rule_id"] == "VIG-0002" for a in alerts)


def test_filter_alerts_by_severity():
    response = client.get("/api/v1/alerts?severity=medium")
    assert response.status_code == 200
    assert all(a["severity"] == "medium" for a in response.json())


def test_filter_rejects_unknown_severity():
    response = client.get("/api/v1/alerts?severity=apocalyptic")
    assert response.status_code == 422
