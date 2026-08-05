from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.models import Alert, utcnow_iso
from app.parsers import normalize_event


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


def test_existing_high_alert_is_not_downgraded_by_later_lower_signal(tmp_path: Path):
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'soc-test.db'}",
        api_key=INGEST,
        admin_token=ADMIN,
        syslog_enabled=False,
        data_dir=Path("data"),
        knowledge_dir=Path("knowledge"),
        response_mode="dry_run",
    )
    raw_event = (
        "<134>Jul 30 08:49:24 filterlog: "
        "69,,,0,em1,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,60,"
        "192.168.228.128,192.168.228.142,52411,22,0,S,1234567890,,64240,,mss"
    )

    with TestClient(create_app(settings)) as client:
        normalized = normalize_event(raw_event, source_hint="syslog")
        now = utcnow_iso()
        with client.app.state.database.session_factory() as db:
            db.add(
                Alert(
                    fingerprint=normalized["fingerprint"],
                    source=normalized["source"],
                    event_type=normalized["event_type"],
                    title="Probable network scan / reconnaissance",
                    description="Existing high-confidence scan alert.",
                    severity="high",
                    confidence=0.9,
                    event_count=1,
                    src_ip=normalized["src_ip"],
                    dst_ip=normalized["dst_ip"],
                    dst_port=normalized["dst_port"],
                    mitre=[{"id": "T1046", "name": "Network Service Discovery"}],
                    normalized_event=normalized,
                    raw_event=normalized["raw"],
                    triage={
                        "severity": "high",
                        "confidence": 0.9,
                        "title": "Probable network scan / reconnaissance",
                        "description": "Existing high-confidence scan alert.",
                        "reasons": ["Previous high-confidence correlation."],
                        "mitre": [{"id": "T1046", "name": "Network Service Discovery"}],
                        "recommendations": ["Keep the alert escalated."],
                    },
                    recommendations=["Keep the alert escalated."],
                    first_seen=now,
                    last_seen=now,
                    created_at=now,
                    updated_at=now,
                )
            )
            db.commit()

        response = client.post(
            "/api/v1/ingest",
            headers={"X-API-Key": INGEST},
            json={"source": "syslog", "event": raw_event},
        )

        assert response.status_code == 200
        assert response.json()["results"][0]["severity"] == "high"
        alerts = client.get("/api/v1/alerts", headers=_headers()).json()
        assert alerts[0]["severity"] == "high"
        assert alerts[0]["title"] == "Probable network scan / reconnaissance"
        assert alerts[0]["event_count"] == 2
