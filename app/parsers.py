from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any


APACHE_COMBINED = re.compile(
    r'(?P<src_ip>\S+) \S+ (?P<user>\S+) \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>[^"]*?)(?: HTTP/\S+)?" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?'
)
SYSLOG_PREFIX = re.compile(
    r"^(?:<(?P<priority>\d+)>)?(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+"
    r"(?P<host>\S+)\s+(?P<program>[\w./-]+)(?:\[\d+\])?:\s*(?P<message>.*)$"
)
SUSPICIOUS_PATH = re.compile(
    r"(?i)(?:\.\./|/\.env|/wp-admin|/phpmyadmin|/etc/passwd|union(?:\s+all)?\s+select|<script|cmd=|powershell)"
)


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _timestamp(value: Any) -> str:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    if isinstance(value, str) and value:
        normalized = value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat()
        except ValueError:
            return value
    return datetime.now(timezone.utc).isoformat()


def _parse_text(raw: str) -> dict[str, Any]:
    stripped = raw.strip()
    try:
        decoded = json.loads(stripped)
        if isinstance(decoded, dict):
            return decoded
    except json.JSONDecodeError:
        pass

    apache = APACHE_COMBINED.search(stripped)
    if apache:
        parsed = apache.groupdict()
        parsed["status"] = _as_int(parsed["status"])
        parsed["message"] = stripped
        parsed["_format"] = "apache"
        return parsed

    syslog = SYSLOG_PREFIX.match(stripped)
    if syslog:
        parsed = syslog.groupdict()
        parsed["_format"] = "syslog"
        return parsed

    return {"message": stripped, "_format": "text"}


def _suricata(data: dict[str, Any]) -> dict[str, Any]:
    alert = data.get("alert") or {}
    signature = alert.get("signature") or data.get("signature") or "Suricata alert"
    category = alert.get("category") or "Network threat"
    return {
        "source": "suricata",
        "timestamp": _timestamp(data.get("timestamp")),
        "event_type": f"suricata.{data.get('event_type', 'alert')}",
        "title": signature,
        "message": category,
        "src_ip": data.get("src_ip"),
        "dst_ip": data.get("dest_ip") or data.get("dst_ip"),
        "src_port": _as_int(data.get("src_port")),
        "dst_port": _as_int(data.get("dest_port") or data.get("dst_port")),
        "protocol": data.get("proto"),
        "signature": signature,
        "signature_id": alert.get("signature_id"),
        "category": category,
        "sensor_severity": _as_int(alert.get("severity")),
        "host": data.get("host"),
    }


def _apache(data: dict[str, Any]) -> dict[str, Any]:
    path = str(data.get("path") or data.get("uri") or "/")
    status_code = _as_int(data.get("status") or data.get("status_code"))
    suspicious = bool(SUSPICIOUS_PATH.search(path))
    failed = status_code in {401, 403, 404}
    event_type = "web.suspicious_request" if suspicious else "web.access"
    if failed and not suspicious:
        event_type = "web.failed_request"
    return {
        "source": "apache",
        "timestamp": _timestamp(data.get("timestamp") or data.get("time")),
        "event_type": event_type,
        "title": (
            "Suspicious web request"
            if suspicious
            else f"Web request {status_code or '-'}"
        ),
        "message": data.get("message") or f"{data.get('method', 'GET')} {path}",
        "src_ip": data.get("src_ip") or data.get("client_ip") or data.get("remote_addr"),
        "dst_ip": data.get("dst_ip") or data.get("server_ip"),
        "dst_port": _as_int(data.get("dst_port") or data.get("server_port") or 80),
        "method": data.get("method") or "GET",
        "path": path,
        "status_code": status_code,
        "username": None if data.get("user") in {None, "-"} else data.get("user"),
        "user_agent": data.get("agent") or data.get("user_agent"),
        "host": data.get("host"),
        "suspicious_path": suspicious,
    }


def _windows(data: dict[str, Any]) -> dict[str, Any]:
    event_id = _as_int(
        data.get("EventID")
        or data.get("event_id")
        or data.get("EventCode")
        or data.get("winlog", {}).get("event_id")
    )
    event_data = data.get("EventData") or data.get("event_data") or {}
    username = (
        data.get("TargetUserName")
        or event_data.get("TargetUserName")
        or data.get("user")
    )
    src_ip = (
        data.get("IpAddress")
        or event_data.get("IpAddress")
        or data.get("src_ip")
    )
    message = str(data.get("Message") or data.get("message") or "")
    titles = {
        4624: "Successful Windows logon",
        4625: "Failed Windows logon",
        4688: "Windows process created",
        4720: "Windows user account created",
        1102: "Windows audit log cleared",
    }
    return {
        "source": "windows",
        "timestamp": _timestamp(data.get("TimeCreated") or data.get("@timestamp")),
        "event_type": f"windows.{event_id or 'event'}",
        "title": titles.get(event_id, f"Windows event {event_id or 'unknown'}"),
        "message": message,
        "event_id": event_id,
        "src_ip": src_ip,
        "dst_ip": data.get("dst_ip"),
        "dst_port": _as_int(data.get("dst_port")),
        "username": username,
        "host": data.get("Computer") or data.get("host"),
        "process": (
            data.get("NewProcessName")
            or event_data.get("NewProcessName")
            or data.get("process")
        ),
        "command_line": (
            data.get("CommandLine")
            or event_data.get("CommandLine")
            or data.get("command_line")
        ),
    }


def normalize_event(
    raw: dict[str, Any] | str,
    source_hint: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metadata = metadata or {}
    data = _parse_text(raw) if isinstance(raw, str) else dict(raw)
    source_text = " ".join(
        str(value)
        for value in (
            source_hint,
            metadata.get("sourcetype"),
            data.get("source"),
            data.get("sourcetype"),
            data.get("_format"),
        )
        if value
    ).lower()

    if "alert" in data and (
        data.get("event_type") or "suricata" in source_text or "eve" in source_text
    ):
        normalized = _suricata(data)
    elif any(word in source_text for word in ("apache", "access_combined", "httpd")):
        normalized = _apache(data)
    elif data.get("_format") == "apache" or {"method", "path", "status"} <= data.keys():
        normalized = _apache(data)
    elif any(word in source_text for word in ("windows", "winevent", "winlog")):
        normalized = _windows(data)
    elif any(key in data for key in ("EventID", "EventCode", "winlog")):
        normalized = _windows(data)
    else:
        normalized = {
            "source": source_hint or str(data.get("source") or "generic"),
            "timestamp": _timestamp(data.get("timestamp") or data.get("@timestamp")),
            "event_type": str(data.get("event_type") or "generic.event"),
            "title": str(data.get("title") or "Security event"),
            "message": str(data.get("message") or data.get("event") or data),
            "src_ip": data.get("src_ip") or data.get("source_ip"),
            "dst_ip": data.get("dst_ip") or data.get("destination_ip"),
            "dst_port": _as_int(data.get("dst_port") or data.get("destination_port")),
            "username": data.get("username") or data.get("user"),
            "host": data.get("host") or metadata.get("host"),
            "sensor_severity": data.get("severity"),
        }

    if source_hint and source_hint.lower() not in {"syslog", "udp-syslog"}:
        normalized["source"] = source_hint
    normalized["transport"] = (
        "syslog" if source_hint and "syslog" in source_hint.lower() else "http"
    )
    normalized["host"] = normalized.get("host") or metadata.get("host")
    normalized["raw"] = data
    normalized["fingerprint"] = fingerprint(normalized)
    return normalized


def fingerprint(event: dict[str, Any]) -> str:
    stable_parts = [
        str(event.get("source") or ""),
        str(event.get("event_type") or ""),
        str(event.get("src_ip") or ""),
        str(event.get("dst_ip") or ""),
        str(event.get("dst_port") or ""),
        str(event.get("signature") or event.get("event_id") or ""),
    ]
    return hashlib.sha256("|".join(stable_parts).encode("utf-8")).hexdigest()
