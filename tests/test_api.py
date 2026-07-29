from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


ADMIN = "test-admin-token"
INGEST = "test-ingest-key"


def _headers():
    return {"Authorization": f"Bearer {ADMIN}"}


def test_end_to_end_ingest_incident_approval_and_audit(tmp_path: Path):
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'soc-test.db'}",
        api_key=INGEST,
        admin_token=ADMIN,
        syslog_enabled=False,
        data_dir=Path("data"),
        knowledge_dir=Path("knowledge"),
        response_mode="dry_run",
    )
    with TestClient(create_app(settings)) as client:
        assert client.get("/health").status_code == 200
        unauthorized = client.post(
            "/api/v1/ingest", json={"source": "apache", "event": "test"}
        )
        assert unauthorized.status_code == 401

        payload = {
            "source": "suricata",
            "event": {
                "event_type": "alert",
                "src_ip": "93.184.216.34",
                "dest_ip": "192.168.1.100",
                "dest_port": 80,
                "alert": {
                    "severity": 2,
                    "signature": "ET SCAN Nmap test signature",
                    "category": "Attempted Information Leak",
                },
            },
        }
        result = client.post(
            "/api/v1/ingest",
            headers={"X-API-Key": INGEST},
            json=payload,
        )
        assert result.status_code == 200
        alert_id = result.json()["results"][0]["alert_id"]

        hec = client.post(
            "/services/collector/event",
            headers={"Authorization": f"Splunk {INGEST}"},
            json={
                "source": "suricata",
                "sourcetype": "suricata:eve",
                "event": payload["event"],
            },
        )
        assert hec.status_code == 200
        assert hec.json() == {"text": "Success", "code": 0}

        alerts = client.get("/api/v1/alerts", headers=_headers()).json()
        assert alerts[0]["id"] == alert_id
        assert alerts[0]["severity"] == "high"
        assert alerts[0]["event_count"] == 2
        events = client.get(
            f"/api/v1/alerts/{alert_id}/events", headers=_headers()
        ).json()
        assert len(events) == 2
        incidents = client.get("/api/v1/incidents", headers=_headers()).json()
        assert len(incidents) == 1

        actions = client.get(
            "/api/v1/actions?status=pending", headers=_headers()
        ).json()
        block = next(item for item in actions if item["action_type"] == "block_ip")
        decision = client.post(
            f"/api/v1/actions/{block['id']}/decision",
            headers=_headers(),
            json={
                "decision": "approve",
                "analyst": "Test Analyst",
                "reason": "Verified lab IOC.",
            },
        )
        assert decision.status_code == 200
        assert decision.json()["status"] == "executed"
        assert decision.json()["result"]["mode"] == "dry_run"

        audit = client.get("/api/v1/audit", headers=_headers()).json()
        assert any(item["action"] == "response.approved" for item in audit)

        knowledge = client.post(
            "/api/v1/knowledge/search",
            headers=_headers(),
            json={"query": "suricata web scan opnsense block", "limit": 2},
        )
        assert knowledge.status_code == 200
        assert knowledge.json()

        automation_audit = client.post(
            "/api/v1/automation/audit",
            headers=_headers(),
            json={
                "actor": "n8n",
                "action": "automation.notification_sent",
                "object_type": "alert",
                "object_id": alert_id,
                "outcome": "success",
                "detail": {"workflow": "A11 SOC Local Automation"},
            },
        )
        assert automation_audit.status_code == 200
        assert automation_audit.json()["actor"] == "n8n"
