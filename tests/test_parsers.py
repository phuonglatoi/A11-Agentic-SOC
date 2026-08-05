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


def test_opnsense_filterlog_http_flood_is_high():
    event = normalize_event(
        "<134>Jul 30 08:49:24 filterlog: "
        "69,,,0,em1,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,60,"
        "192.168.228.128,192.168.228.142,52411,80,0,S,1234567890,,64240,,mss",
        source_hint="syslog",
    )
    assert event["source"] == "opnsense"
    assert event["event_type"] == "opnsense.firewall_block"
    assert event["src_ip"] == "192.168.228.128"
    assert event["dst_ip"] == "192.168.228.142"
    assert event["dst_port"] == 80

    triage = triage_event(event, event_count=75)
    assert triage["severity"] == "high"
    assert "HTTP flood" in triage["title"]
    assert triage["mitre"][0]["id"] == "T1498"


def test_opnsense_repeated_tcp_deny_is_high_reconnaissance():
    event = normalize_event(
        "<134>Jul 30 08:49:24 filterlog: "
        "69,,,0,em1,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,60,"
        "192.168.228.128,192.168.228.142,52411,22,0,S,1234567890,,64240,,mss",
        source_hint="syslog",
    )

    triage = triage_event(event, event_count=25)

    assert triage["severity"] == "high"
    assert "network scan" in triage["title"].lower()
    assert any(item["id"] == "T1046" for item in triage["mitre"])
    assert any(item["id"] == "T1595.002" for item in triage["mitre"])
