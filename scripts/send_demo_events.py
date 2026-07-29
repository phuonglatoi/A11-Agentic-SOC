from __future__ import annotations

import os

import httpx


base_url = os.getenv("SOC_URL", "http://127.0.0.1:8000").rstrip("/")
api_key = os.getenv("SOC_API_KEY", "change-me-ingest-key")
events = [
    (
        "apache",
        '203.0.113.66 - - [28/Jul/2026:15:31:11 +0000] '
        '"GET /.env HTTP/1.1" 404 512 "-" "dirb/2.22"',
    ),
    (
        "suricata",
        {
            "timestamp": "2026-07-28T15:31:12.000000+00:00",
            "event_type": "alert",
            "src_ip": "93.184.216.34",
            "dest_ip": "192.168.1.100",
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "severity": 2,
                "signature_id": 2009582,
                "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
                "category": "Attempted Information Leak",
            },
        },
    ),
]

with httpx.Client(timeout=20) as client:
    for source, event in events:
        response = client.post(
            f"{base_url}/api/v1/ingest",
            headers={"X-API-Key": api_key},
            json={"source": source, "event": event},
        )
        response.raise_for_status()
        print(response.json())
