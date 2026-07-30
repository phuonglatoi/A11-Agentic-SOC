from __future__ import annotations

import ipaddress
from typing import Any


def is_safe_block_target(value: str | None) -> bool:
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(ip.is_global and not (ip.is_loopback or ip.is_multicast or ip.is_unspecified))


def propose_actions(
    alert_id: str,
    event: dict[str, Any],
    triage: dict[str, Any],
    enrichment: dict[str, Any],
) -> list[dict[str, Any]]:
    severity = triage["severity"]
    if severity not in {"high", "critical"}:
        return []

    proposals: list[dict[str, Any]] = [
        {
            "alert_id": alert_id,
            "action_type": "notify_soc",
            "target": "soc-analyst",
            "risk": "low",
            "approval_required": False,
            "payload": {
                "alert_id": alert_id,
                "severity": severity,
                "title": triage["title"],
                "description": triage.get("description"),
                "confidence": triage.get("confidence"),
                "attack_type": (triage.get("ml_prediction") or {}).get("attack_type"),
                "ml_prediction": triage.get("ml_prediction"),
                "mitre": triage.get("mitre"),
                "reasons": triage.get("reasons"),
                "recommendations": triage.get("recommendations"),
                "src_ip": event.get("src_ip"),
                "dst_ip": event.get("dst_ip"),
                "dst_port": event.get("dst_port"),
                "event_type": event.get("event_type"),
                "asset": enrichment.get("asset"),
            },
        }
    ]

    source_ip = event.get("src_ip")
    if is_safe_block_target(source_ip):
        proposals.append(
            {
                "alert_id": alert_id,
                "action_type": "block_ip",
                "target": source_ip,
                "risk": "high",
                "approval_required": True,
                "payload": {
                    "alert_id": alert_id,
                    "reason": triage["title"],
                    "severity": severity,
                    "attack_type": (triage.get("ml_prediction") or {}).get("attack_type"),
                    "mitre": triage.get("mitre"),
                    "destination_asset": enrichment.get("asset"),
                },
            }
        )

    if severity == "critical" and event.get("host"):
        proposals.append(
            {
                "alert_id": alert_id,
                "action_type": "isolate_host",
                "target": event["host"],
                "risk": "critical",
                "approval_required": True,
                "payload": {
                    "alert_id": alert_id,
                    "reason": triage["title"],
                    "severity": severity,
                    "attack_type": (triage.get("ml_prediction") or {}).get("attack_type"),
                    "mitre": triage.get("mitre"),
                },
            }
        )
    return proposals
