from pathlib import Path

from app.agents.ml_detector import MLDetectionAgent
from app.agents.triage import triage_event
from app.parsers import normalize_event


def test_ml_agent_detects_opnsense_http_flood():
    agent = MLDetectionAgent(Path("models/attack_classifier.json"))
    event = normalize_event(
        "<134>Jul 30 08:49:24 filterlog: "
        "69,,,0,em1,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,60,"
        "192.168.228.128,192.168.228.142,52411,80,0,S,1234567890,,64240,,mss",
        source_hint="syslog",
    )

    prediction = agent.detect(event, event_count=75)

    assert prediction["enabled"] is True
    assert prediction["attack_type"] == "http_flood_dos"
    assert prediction["severity"] == "high"


def test_ml_prediction_is_used_by_triage_for_sqlmap():
    agent = MLDetectionAgent(Path("models/attack_classifier.json"))
    event = normalize_event(
        {
            "method": "GET",
            "path": "/login.php?id=1%27",
            "status": 404,
            "agent": "sqlmap/1.7",
            "src_ip": "203.0.113.66",
        },
        source_hint="apache",
    )
    event["ml_prediction"] = agent.detect(event)

    triage = triage_event(event)

    assert event["ml_prediction"]["attack_type"] == "sql_injection_probe"
    assert triage["severity"] == "high"
    assert any(item["id"] == "T1190" for item in triage["mitre"])
    assert any("ML Detection Agent predicted" in reason for reason in triage["reasons"])
