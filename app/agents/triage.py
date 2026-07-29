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

    title = event.get("title") or "Security event"
    description = event.get("message") or title
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
