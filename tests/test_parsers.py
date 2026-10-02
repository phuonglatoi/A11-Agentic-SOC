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


def test_opnsense_lab_tcp_deny_escalates_quickly_for_demo():
    event = normalize_event(
        "<134>Jul 30 08:49:24 filterlog: "
        "69,,,0,em1,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,60,"
        "192.168.228.128,192.168.228.142,52411,80,0,S,1234567890,,64240,,mss",
        source_hint="syslog",
    )

    triage = triage_event(event, event_count=5, enrichment={"lab_source": True})

    assert triage["severity"] == "high"
    assert "network scan" in triage["title"].lower() or "http flood" in triage["title"].lower()


def test_opnsense_outbound_pass_is_not_http_flood():
    event = normalize_event(
        "<134>Jul 30 08:49:24 filterlog: "
        "69,,,0,em1,match,pass,out,4,0x0,,64,12345,0,DF,6,tcp,60,"
        "192.168.1.10,192.168.1.1,52411,80,0,S,1234567890,,64240,,mss",
        source_hint="syslog",
    )
    event["ml_prediction"] = {
        "enabled": True,
        "status": "ok",
        "attack_type": "http_flood_dos",
        "confidence": 0.91,
        "severity": "high",
        "mitre": [{"id": "T1498", "name": "Network Denial of Service"}],
    }

    triage = triage_event(
        event,
        event_count=150,
        enrichment={"source_is_infrastructure": False},
    )

    assert triage["severity"] == "low"
    assert "HTTP flood" not in triage["title"]
    assert any("suppressed" in reason for reason in triage["reasons"])


def test_opnsense_infrastructure_source_is_not_promoted_by_ml():
    event = normalize_event(
        "<134>Jul 30 08:49:24 filterlog: "
        "69,,,0,em1,match,pass,in,4,0x0,,64,12345,0,DF,6,tcp,60,"
        "192.168.228.142,192.168.1.10,52411,80,0,S,1234567890,,64240,,mss",
        source_hint="syslog",
    )
    event["ml_prediction"] = {
        "enabled": True,
        "status": "ok",
        "attack_type": "http_flood_dos",
        "confidence": 0.91,
        "severity": "high",
    }

    triage = triage_event(
        event,
        event_count=150,
        enrichment={
            "source_is_infrastructure": True,
            "source_asset": {"name": "opnsense-gateway", "type": "firewall"},
        },
    )

    assert triage["severity"] == "low"
    assert any("opnsense-gateway" in reason for reason in triage["reasons"])


def test_opnsense_generic_record_without_action_is_not_escalated():
    event = {
        "event_type": "opnsense.firewall_event",
        "title": "OPNsense firewall observed TCP traffic",
        "protocol": "TCP",
        "dst_port": 80,
        "firewall_action": None,
        "firewall_direction": "in",
        "src_ip": "192.168.228.128",
        "dst_ip": "192.168.228.142",
        "ml_prediction": {
            "enabled": True,
            "status": "ok",
            "attack_type": "http_flood_dos",
            "confidence": 0.9,
            "severity": "high",
        },
    }

    triage = triage_event(event, event_count=100)

    assert triage["severity"] == "low"
    assert any("no validated" in reason for reason in triage["reasons"])


def test_apache_high_volume_from_remote_source_is_high_http_flood():
    event = normalize_event(
        '192.168.228.128 - - [28/Jul/2026:15:31:11 +0000] '
        '"GET / HTTP/1.1" 200 512 "-" "GoldenEye"',
        source_hint="apache",
    )

    triage = triage_event(
        event,
        event_count=120,
        enrichment={"source_ip": {"loopback": False}},
    )

    assert triage["severity"] == "high"
    assert "HTTP flood" in triage["title"]
    assert any(item["id"] == "T1499" for item in triage["mitre"])


def test_dhcp_broadcast_is_not_promoted_to_network_scan():
    event = normalize_event(
        "<134>Jul 30 08:49:24 filterlog: "
        "69,,,0,em1,match,block,in,4,0x0,,64,12345,0,DF,17,udp,328,"
        "0.0.0.0,255.255.255.255,68,67,288",
        source_hint="syslog",
    )
    event["ml_prediction"] = {
        "enabled": True,
        "status": "ok",
        "attack_type": "network_scan",
        "confidence": 0.92,
        "severity": "high",
    }

    triage = triage_event(
        event,
        event_count=100,
        enrichment={
            "source_ip": {"unspecified": True},
            "destination_ip": {"broadcast": True},
        },
    )

    assert triage["severity"] == "low"
    assert "network scan" not in triage["title"].lower()
    assert any("broadcast" in reason for reason in triage["reasons"])


def test_ubuntu_ssh_failures_are_normalized_and_detected():
    event = normalize_event(
        "<86>Oct  2 18:00:00 ubuntu sshd[4321]: Failed password for invalid user "
        "demo from 198.51.100.42 port 42424 ssh2",
        source_hint="syslog",
    )

    assert event["source"] == "ubuntu"
    assert event["event_type"] == "linux.ssh_auth_failure"
    assert event["src_ip"] == "198.51.100.42"
    assert event["username"] == "demo"
    assert event["dst_port"] == 22

    triage = triage_event(event, event_count=3)
    assert triage["severity"] == "medium"
    assert any(item["id"] == "T1110.001" for item in triage["mitre"])


def test_ubuntu_sudo_sensitive_command_is_flagged_conservatively():
    event = normalize_event(
        "<85>Oct  2 18:00:00 ubuntu sudo[4321]: "
        "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/useradd demo",
        source_hint="syslog",
    )

    assert event["source"] == "ubuntu"
    assert event["event_type"] == "linux.sudo_command"
    assert event["username"] == "alice"
    assert event["target_user"] == "root"
    triage = triage_event(event)
    assert triage["severity"] == "medium"
    assert any(item["id"] == "T1548.003" for item in triage["mitre"])


def test_ubuntu_sudo_auth_failure_is_low_until_repeated():
    event = normalize_event(
        "<85>Oct  2 18:00:00 ubuntu sudo[4321]: pam_unix(sudo:auth): "
        "authentication failure; logname=alice ruser=alice user=alice",
        source_hint="syslog",
    )

    assert event["event_type"] == "linux.sudo_auth_failure"
    assert event["username"] == "alice"
    assert triage_event(event, event_count=1)["severity"] == "low"
    assert triage_event(event, event_count=5)["severity"] == "medium"
