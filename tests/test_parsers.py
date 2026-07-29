from app.agents.triage import triage_event
from app.parsers import normalize_event


def test_apache_combined_log_is_normalized_and_triaged():
    event = normalize_event(
        '203.0.113.66 - - [28/Jul/2026:15:31:11 +0000] '
        '"GET /.env HTTP/1.1" 404 512 "-" "dirb/2.22"',
        source_hint="apache",
    )
    assert event["event_type"] == "web.suspicious_request"
    assert event["src_ip"] == "203.0.113.66"
    assert event["path"] == "/.env"
    triage = triage_event(event, event_count=5)
    assert triage["severity"] == "high"
    assert triage["mitre"][0]["id"] == "T1190"


def test_suricata_alert_maps_sensor_severity():
    event = normalize_event(
        {
            "event_type": "alert",
            "src_ip": "198.51.100.42",
            "dest_ip": "192.168.1.100",
            "dest_port": 80,
            "alert": {
                "severity": 1,
                "signature": "ET EXPLOIT test signature",
                "category": "Web Application Attack",
            },
        },
        source_hint="suricata",
    )
    triage = triage_event(event)
    assert triage["severity"] == "critical"
    assert event["dst_port"] == 80


def test_windows_audit_clear_is_critical():
    event = normalize_event(
        {
            "EventID": 1102,
            "Computer": "WIN-ENDPOINT-01",
            "Message": "The audit log was cleared.",
        },
        source_hint="windows",
    )
    triage = triage_event(event)
    assert event["event_type"] == "windows.1102"
    assert triage["severity"] == "critical"
    assert triage["mitre"][0]["id"] == "T1070.001"
