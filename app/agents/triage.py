from __future__ import annotations

import re
from typing import Any


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
POWERSHELL_RISK = re.compile(
    r"(?i)(?:powershell|pwsh).*(?:-enc(?:odedcommand)?\b|frombase64string|downloadstring|invoke-expression|\biex\b)"
)


def max_severity(*values: str) -> str:
    known = [value.lower() for value in values if value and value.lower() in SEVERITY_RANK]
    return max(known, key=SEVERITY_RANK.get) if known else "low"


def _append_mitre(
    mitre: list[dict[str, str]],
    entries: list[dict[str, str]] | None,
) -> None:
    for entry in entries or []:
        technique_id = entry.get("id")
        if technique_id and not any(item.get("id") == technique_id for item in mitre):
            mitre.append({"id": technique_id, "name": entry.get("name", technique_id)})


def triage_event(
    event: dict[str, Any],
    event_count: int = 1,
    enrichment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    enrichment = enrichment or {}
    event_type = event.get("event_type", "generic.event")
    severity = "low"
    confidence = 0.58
    reasons: list[str] = []
    mitre: list[dict[str, str]] = []
    recommendations: list[str] = [
        "Validate the alert against raw telemetry before closing it."
    ]
    title_override: str | None = None
    description_override: str | None = None
    ml_prediction = event.get("ml_prediction") or {}

    if event_type.startswith("suricata."):
        sensor_severity = event.get("sensor_severity")
        severity = {1: "critical", 2: "high", 3: "medium"}.get(
            sensor_severity, "medium"
        )
        confidence = 0.78
        reasons.append("Suricata produced a signature-based network alert.")
        category = str(event.get("category") or "").lower()
        signature = str(event.get("signature") or "").lower()
        if "scan" in category or "scan" in signature or "nmap" in signature:
            mitre.append({"id": "T1046", "name": "Network Service Discovery"})
        elif "web" in category or "exploit" in signature:
            mitre.append({"id": "T1190", "name": "Exploit Public-Facing Application"})

    elif event_type == "web.suspicious_request":
        severity = "high" if event_count >= 5 else "medium"
        confidence = min(0.95, 0.68 + event_count * 0.02)
        reasons.append("The request path contains a known attack or exposure pattern.")
        mitre.append({"id": "T1190", "name": "Exploit Public-Facing Application"})
        recommendations.extend(
            [
                "Review the matching Apache access and error log entries.",
                "Check whether the source belongs to an approved security test.",
            ]
        )
    elif event_type == "web.failed_request":
        severity = "high" if event_count >= 20 else ("medium" if event_count >= 5 else "low")
        confidence = min(0.92, 0.52 + event_count * 0.02)
        reasons.append("Repeated failed HTTP responses can indicate enumeration.")
        if event_count >= 5:
            mitre.append({"id": "T1595.002", "name": "Vulnerability Scanning"})
    elif event_type == "web.access":
        severity = "medium" if event_count >= 100 else "low"
        confidence = 0.45 if event_count < 100 else 0.7
        if event_count >= 100:
            reasons.append("A high request volume was correlated in a short window.")
            mitre.append({"id": "T1498", "name": "Network Denial of Service"})

    elif event_type.startswith("opnsense.firewall_"):
        action = str(event.get("firewall_action") or "").lower()
        direction = str(event.get("firewall_direction") or "").lower()
        protocol = str(event.get("protocol") or "").lower()
        dst_port = event.get("dst_port")
        web_ports = {80, 443, 8000, 8080, 8443}
        if event_count >= 50 and protocol == "tcp" and dst_port in web_ports:
            severity = "high"
            confidence = min(0.96, 0.74 + event_count * 0.002)
            title_override = "Possible HTTP flood / DoS traffic"
            description_override = (
                f"{event_count} correlated OPNsense firewall events from "
                f"{event.get('src_ip') or 'an unknown source'} to "
                f"{event.get('dst_ip') or 'the WAN address'}:{dst_port} "
                "were observed in the correlation window."
            )
            reasons.append(
                "A high volume of TCP firewall events targeted a web-facing port "
                "from the same source in a short time window."
            )
            if action in {"block", "reject"}:
                reasons.append(
                    "OPNsense blocked or rejected the traffic, indicating the firewall "
                    "absorbed the flood attempt before it reached the protected service."
                )
            elif action == "pass":
                reasons.append(
                    "OPNsense allowed the traffic; validate web access logs and service "
                    "health to determine impact."
                )
            if direction:
                reasons.append(f"The firewall logged the traffic direction as {direction}.")
            mitre.append({"id": "T1498", "name": "Network Denial of Service"})
            recommendations.extend(
                [
                    "Confirm the traffic is an approved lab DoS test before taking action.",
                    "Check OPNsense live log, firewall states and interface throughput.",
                    "Review Apache access.log for matching HTTP requests and user agents.",
                    "Rate-limit or block the source at OPNsense if the activity is not authorized.",
                ]
            )
        elif action in {"block", "reject"} and protocol == "tcp" and event_count >= 20:
            severity = "high"
            confidence = min(0.94, 0.68 + event_count * 0.004)
            title_override = "Probable network scan / reconnaissance"
            description_override = (
                f"{event_count} denied TCP firewall events from "
                f"{event.get('src_ip') or 'an unknown source'} to "
                f"{event.get('dst_ip') or 'the protected network'} "
                "were correlated in the analysis window."
            )
            reasons.append(
                "Repeated denied TCP firewall events from the same source indicate "
                "port scan, service discovery, or vulnerability scanning activity."
            )
            if dst_port:
                reasons.append(f"The current correlated destination port is {dst_port}.")
            mitre.extend(
                [
                    {"id": "T1046", "name": "Network Service Discovery"},
                    {"id": "T1595.002", "name": "Vulnerability Scanning"},
                ]
            )
            recommendations.extend(
                [
                    "Confirm whether the source is the authorized Kali lab scanner.",
                    "Review OPNsense live firewall logs for the full destination port spread.",
                    "If unauthorized, block or rate-limit the source after analyst approval.",
                ]
            )
        elif action in {"block", "reject"} and event_count >= 8:
            severity = "medium"
            confidence = min(0.88, 0.55 + event_count * 0.01)
            title_override = "Repeated firewall deny events"
            reasons.append(
                "Multiple blocked firewall events from the same source were correlated."
            )
            mitre.append({"id": "T1046", "name": "Network Service Discovery"})
            recommendations.append(
                "Check whether the source is a known scanner or approved test host."
            )

    elif event_type == "windows.4625":
        severity = "high" if event_count >= 10 else ("medium" if event_count >= 3 else "low")
        confidence = min(0.94, 0.55 + event_count * 0.03)
        reasons.append("Windows reported a failed logon.")
        mitre.append({"id": "T1110", "name": "Brute Force"})
        recommendations.append("Search for a successful logon after the failure burst.")
    elif event_type == "windows.4688":
        command = f"{event.get('process') or ''} {event.get('command_line') or ''}"
        if POWERSHELL_RISK.search(command):
            severity = "high"
            confidence = 0.9
            reasons.append("The process command line matches encoded or download-capable PowerShell.")
            mitre.append({"id": "T1059.001", "name": "PowerShell"})
    elif event_type == "windows.4720":
        severity = "high"
        confidence = 0.82
        reasons.append("A new local or domain user was created.")
        mitre.append({"id": "T1136.001", "name": "Local Account"})
    elif event_type == "windows.1102":
        severity = "critical"
        confidence = 0.97
        reasons.append("The Windows security audit log was cleared.")
        mitre.append({"id": "T1070.001", "name": "Clear Windows Event Logs"})

    sensor_value = str(event.get("sensor_severity") or "").lower()
    if sensor_value in SEVERITY_RANK:
        severity = max_severity(severity, sensor_value)
        reasons.append("The upstream sensor supplied a severity value.")

    if ml_prediction.get("enabled") and ml_prediction.get("status") == "ok":
        attack_type = str(ml_prediction.get("attack_type") or "")
        ml_confidence = float(ml_prediction.get("confidence") or 0.0)
        ml_severity = str(ml_prediction.get("severity") or "low")
        if attack_type and attack_type != "benign" and ml_confidence >= 0.65:
            severity = max_severity(severity, ml_severity)
            confidence = max(confidence, min(0.97, ml_confidence))
            reasons.append(
                "ML Detection Agent predicted "
                f"{attack_type} with confidence {ml_confidence:.0%}."
            )
            _append_mitre(mitre, ml_prediction.get("mitre"))
            if ml_prediction.get("recommended_title") and SEVERITY_RANK[ml_severity] >= 3:
                title_override = title_override or ml_prediction["recommended_title"]
            if ml_prediction.get("recommended_description"):
                description_override = (
                    description_override or ml_prediction["recommended_description"]
                )
            recommendations.append(
                "Review the ML prediction together with raw telemetry and RAG playbooks."
            )

    if enrichment.get("ioc_matches"):
        severity = max_severity(severity, "high")
        confidence = max(confidence, 0.9)
        reasons.append("The source or destination matched the local IOC feed.")

    asset = enrichment.get("asset") or {}
    if asset.get("criticality") == "critical" and SEVERITY_RANK[severity] >= 2:
        severity = max_severity(severity, "high")
        reasons.append("The target is registered as a critical asset.")

    if not reasons:
        reasons.append("No high-confidence malicious indicator was found.")

    title = title_override or event.get("title") or "Security event"
    description = description_override or event.get("message") or title
    disposition = "escalate" if severity in {"high", "critical"} else "monitor"
    return {
        "severity": severity,
        "confidence": round(confidence, 2),
        "title": title,
        "description": str(description)[:2000],
        "reasons": reasons,
        "mitre": mitre,
        "recommendations": list(dict.fromkeys(recommendations)),
        "disposition": disposition,
        "engine": "deterministic",
    }
