#!/usr/bin/env python3
"""Measure one real Apache -> A11 SOC demo trial.

Run this on the Ubuntu SOC host, then execute the printed curl command on Kali.
The script does not generate telemetry itself. It waits for the unique marker to
arrive through Apache access.log and the configured log shipper, then records
the actual alert, incident, response, n8n audit, email delta and latency.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def env_file_value(name: str, path: Path = Path(".env")) -> str | None:
    if not path.exists():
        return None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == name:
            return value.strip()
    return None


def http_json(
    url: str,
    *,
    token: str | None = None,
    timeout: float = 5.0,
) -> Any:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} from {url}: {body[:300]}") from exc
    except (URLError, TimeoutError) as exc:
        raise RuntimeError(f"Cannot reach {url}: {exc}") from exc


def object_ids(values: Any) -> set[str]:
    if isinstance(values, list):
        items = values
    elif isinstance(values, dict):
        items = next(
            (value for value in values.values() if isinstance(value, list)), []
        )
    else:
        items = []
    result: set[str] = set()
    for item in items:
        if isinstance(item, dict):
            value = item.get("id") or item.get("ID") or item.get("Id")
            if value is not None:
                result.add(str(value))
    return result


def fetch_mail_ids(mailpit_url: str) -> tuple[bool, set[str]]:
    try:
        payload = http_json(
            f"{mailpit_url.rstrip('/')}/api/v1/messages?limit=200", timeout=3
        )
        return True, object_ids(payload)
    except (RuntimeError, json.JSONDecodeError):
        return False, set()


def find_alert(alerts: list[dict[str, Any]], marker: str) -> dict[str, Any] | None:
    marker_lower = marker.lower()
    for alert in alerts:
        evidence = json.dumps(
            {
                "raw_event": alert.get("raw_event"),
                "normalized_event": alert.get("normalized_event"),
                "triage": alert.get("triage"),
            },
            ensure_ascii=False,
        ).lower()
        if marker_lower in evidence:
            return alert
    return None


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def outcome(expected_positive: bool, predicted_positive: bool) -> str:
    if expected_positive and predicted_positive:
        return "TP"
    if expected_positive and not predicted_positive:
        return "FN"
    if not expected_positive and predicted_positive:
        return "FP"
    return "TN"


def print_kali_command(expected: str, target_url: str, marker: str) -> None:
    base = target_url.rstrip("/")
    if expected == "benign":
        query = urlencode({"a11_marker": marker})
        print("\nRun this command ON KALI (one normal request):\n")
        print(
            f'curl -sS -A "Mozilla/5.0 A11-BENIGN/{marker}" '
            f'"{base}/?{query}" >/dev/null'
        )
    else:
        query = f"id=1%27&a11_marker={marker}"
        print("\nRun this command ON KALI (controlled suspicious requests):\n")
        print(
            "for i in $(seq 1 5); do "
            f'curl -sS -A "sqlmap/1.7 A11-ATTACK/{marker}" '
            f'"{base}/login.php?{query}" >/dev/null; '
            "done"
        )
    print("\nWaiting for the marker to arrive through Apache access.log -> A11...\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Measure a labeled live HTTP trial through the A11 SOC pipeline."
    )
    parser.add_argument("--expected", choices=("attack", "benign"), required=True)
    parser.add_argument("--target-url", default="http://192.168.228.142")
    parser.add_argument("--soc-url", default="http://127.0.0.1:8000")
    parser.add_argument("--mailpit-url", default="http://127.0.0.1:8025")
    parser.add_argument(
        "--admin-token",
        default=os.getenv("SOC_ADMIN_TOKEN") or env_file_value("SOC_ADMIN_TOKEN"),
    )
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--settle-seconds", type=float, default=5.0)
    parser.add_argument("--marker", default=None)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("demo_results/live_trials.jsonl"),
    )
    args = parser.parse_args()

    if not args.admin_token:
        raise SystemExit("SOC_ADMIN_TOKEN is missing from the environment or .env")

    soc_url = args.soc_url.rstrip("/")
    try:
        health = http_json(f"{soc_url}/health")
        baseline_incidents = http_json(
            f"{soc_url}/api/v1/incidents?limit=500", token=args.admin_token
        )
        baseline_actions = http_json(
            f"{soc_url}/api/v1/actions?limit=500", token=args.admin_token
        )
        baseline_audit = http_json(
            f"{soc_url}/api/v1/audit?limit=500", token=args.admin_token
        )
    except (RuntimeError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc)) from exc

    mailpit_available, baseline_mail_ids = fetch_mail_ids(args.mailpit_url)
    marker = args.marker or f"a11-{args.expected}-{uuid.uuid4().hex[:10]}"
    started_epoch = time.monotonic()
    started_at = iso_now()
    print(f"A11 health: {health.get('status', 'unknown')}")
    print(f"Trial marker: {marker}")
    print(f"Ground truth: {args.expected.upper()} (declared before traffic)")
    print_kali_command(args.expected, args.target_url, marker)

    observed: dict[str, Any] | None = None
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        try:
            alerts = http_json(
                f"{soc_url}/api/v1/alerts?limit=500", token=args.admin_token
            )
            observed = find_alert(alerts, marker)
        except (RuntimeError, json.JSONDecodeError) as exc:
            print(f"Transient API error while polling: {exc}", file=sys.stderr)
        if observed:
            break
        time.sleep(1)

    if not observed:
        result = {
            "schema_version": 1,
            "trial_id": marker,
            "started_at": started_at,
            "finished_at": iso_now(),
            "input_mode": "live_apache_access_log",
            "ground_truth": args.expected,
            "outcome": "NO_EVIDENCE",
            "passed": False,
            "reason": (
                "No event containing the predeclared marker reached A11 before timeout. "
                "This trial is excluded from TPR/FPR because ingestion was not proven."
            ),
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(result, ensure_ascii=False) + "\n")
        print(json.dumps(result, indent=2, ensure_ascii=False))
        raise SystemExit(2)

    detection_latency = round(time.monotonic() - started_epoch, 3)
    time.sleep(max(args.settle_seconds, 0.0))
    alert_id = str(observed["id"])
    # Refresh after the settle period so correlation and automation have time to finish.
    alert = http_json(
        f"{soc_url}/api/v1/alerts/{alert_id}", token=args.admin_token
    )
    incidents = http_json(
        f"{soc_url}/api/v1/incidents?limit=500", token=args.admin_token
    )
    actions = http_json(
        f"{soc_url}/api/v1/actions?limit=500", token=args.admin_token
    )
    audits = http_json(f"{soc_url}/api/v1/audit?limit=500", token=args.admin_token)
    current_mailpit_available, current_mail_ids = fetch_mail_ids(args.mailpit_url)

    related_incidents = [item for item in incidents if item.get("alert_id") == alert_id]
    related_actions = [item for item in actions if item.get("alert_id") == alert_id]
    related_audits = [
        item
        for item in audits
        if item.get("object_id") == alert_id
        or alert_id in json.dumps(item.get("detail") or {}, ensure_ascii=False)
    ]
    new_mail_ids = (
        sorted(current_mail_ids - baseline_mail_ids)
        if mailpit_available and current_mailpit_available
        else None
    )
    severity = str(alert.get("severity") or "unknown").lower()
    predicted_positive = severity in {"high", "critical"}
    expected_positive = args.expected == "attack"
    measured_outcome = outcome(expected_positive, predicted_positive)
    expected_automation = bool(expected_positive and predicted_positive)
    notify_actions = [
        item for item in related_actions if item.get("action_type") == "notify_soc"
    ]
    notification_policy_pass = (
        bool(related_incidents) and bool(notify_actions)
        if expected_automation
        else not related_incidents and not related_actions
    )

    result = {
        "schema_version": 1,
        "trial_id": marker,
        "started_at": started_at,
        "finished_at": iso_now(),
        "input_mode": "live_apache_access_log",
        "target_url": args.target_url,
        "ground_truth": args.expected,
        "decision_threshold": "severity is HIGH or CRITICAL",
        "outcome": measured_outcome,
        "passed": measured_outcome in {"TP", "TN"} and notification_policy_pass,
        "detection_latency_seconds": detection_latency,
        "alert": {
            "id": alert_id,
            "severity": severity,
            "confidence": alert.get("confidence"),
            "title": alert.get("title"),
            "source": alert.get("source"),
            "event_type": alert.get("event_type"),
            "event_count": alert.get("event_count"),
            "src_ip": alert.get("src_ip"),
            "dst_ip": alert.get("dst_ip"),
            "attack_type": (alert.get("triage", {}).get("ml_prediction") or {}).get(
                "attack_type"
            ),
        },
        "automation": {
            "incident_ids": [item.get("id") for item in related_incidents],
            "actions": [
                {
                    "id": item.get("id"),
                    "type": item.get("action_type"),
                    "status": item.get("status"),
                }
                for item in related_actions
            ],
            "n8n_audit_ids": [
                item.get("id")
                for item in related_audits
                if str(item.get("actor", "")).lower() == "n8n"
            ],
            "mailpit_available": mailpit_available and current_mailpit_available,
            "new_mail_ids_during_trial": new_mail_ids,
            "notification_policy_pass": notification_policy_pass,
        },
        "baseline_counts": {
            "incidents": len(baseline_incidents),
            "actions": len(baseline_actions),
            "audit": len(baseline_audit),
            "mail": len(baseline_mail_ids) if mailpit_available else None,
        },
        "notes": (
            "Counts and identifiers were queried from the running A11 API and "
            "Mailpit. This record contains no hard-coded performance percentage."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(result, ensure_ascii=False) + "\n")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"Appended measured trial to: {args.output}")
    if not result["passed"]:
        raise SystemExit(3)


if __name__ == "__main__":
    main()
