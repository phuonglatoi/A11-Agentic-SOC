from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from app.agents.flow_features import canonical_flow_features


APACHE_COMBINED = re.compile(
    r'(?P<src_ip>\S+) \S+ (?P<user>\S+) \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>[^"]*?)(?: HTTP/\S+)?" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?'
)
SYSLOG_PREFIX = re.compile(
    r"^(?:<(?P<priority>\d+)>)?(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+"
    r"(?P<host>\S+)\s+(?P<program>[\w./-]+)(?:\[\d+\])?:\s*(?P<message>.*)$"
)
SYSLOG_PREFIX_NO_HOST = re.compile(
    r"^(?:<(?P<priority>\d+)>)?(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+"
    r"(?P<program>[\w./-]+)(?:\[\d+\])?:\s*(?P<message>.*)$"
)
SYSLOG_RFC5424_PREFIX = re.compile(
    r"^<(?P<priority>\d+)>(?P<version>\d+)\s+(?P<timestamp>\S+)\s+"
    r"(?P<host>\S+)\s+(?P<program>\S+)\s+(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+(?P<structured_data>-|\[.*?\])(?:\s+(?P<message>.*))?$"
)
SUSPICIOUS_PATH = re.compile(
    r"(?i)(?:\.\./|/\.env|/wp-admin|/phpmyadmin|/etc/passwd|union(?:\s+all)?\s+select|<script|cmd=|powershell)"
)
SSH_FAILURE = re.compile(
    r"Failed\s+(?:password|publickey|keyboard-interactive(?:/pam)?)\s+for\s+"
    r"(?:(?:invalid user)\s+)?(?P<username>\S+)\s+from\s+"
    r"(?P<src_ip>[0-9a-fA-F:.]+)(?:\s+port\s+(?P<src_port>\d+))?",
    re.IGNORECASE,
)
SSH_SUCCESS = re.compile(
    r"Accepted\s+\S+\s+for\s+(?P<username>\S+)\s+from\s+"
    r"(?P<src_ip>[0-9a-fA-F:.]+)(?:\s+port\s+(?P<src_port>\d+))?",
    re.IGNORECASE,
)
SSH_INVALID_USER = re.compile(
    r"Invalid user\s+(?P<username>\S+)\s+from\s+(?P<src_ip>[0-9a-fA-F:.]+)"
    r"(?:\s+port\s+(?P<src_port>\d+))?",
    re.IGNORECASE,
)
SUDO_COMMAND = re.compile(
    r"^(?P<username>[^\s:]+)\s*:\s+.*?\bUSER=(?P<target_user>[^;\s]+)"
    r"\s*;\s+COMMAND=(?P<command>.*)$"
)
SUDO_FAILURE_USER = re.compile(r"\buser=(?P<username>[^\s;]+)")


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

    syslog = SYSLOG_RFC5424_PREFIX.match(stripped)
    if syslog:
        parsed = syslog.groupdict()
        parsed["_format"] = "syslog"
        return parsed

    syslog = SYSLOG_PREFIX.match(stripped)
    if not syslog:
        syslog = SYSLOG_PREFIX_NO_HOST.match(stripped)
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


def _opnsense_filterlog(data: dict[str, Any]) -> dict[str, Any]:
    message = str(data.get("message") or "")
    fields = [item.strip() for item in message.split(",")]
    action = fields[6].lower() if len(fields) > 6 else ""
    direction = fields[7].lower() if len(fields) > 7 else ""
    protocol = fields[16].lower() if len(fields) > 16 else ""
    src_ip = fields[18] if len(fields) > 18 else None
    dst_ip = fields[19] if len(fields) > 19 else None
    src_port = _as_int(fields[20] if len(fields) > 20 else None)
    dst_port = _as_int(fields[21] if len(fields) > 21 else None)
    interface = fields[4] if len(fields) > 4 else data.get("interface")

    if action in {"block", "reject"}:
        event_type = "opnsense.firewall_block"
        verb = "blocked"
    elif action == "pass":
        event_type = "opnsense.firewall_pass"
        verb = "allowed"
    else:
        event_type = "opnsense.firewall_event"
        verb = "observed"

    title_protocol = protocol.upper() if protocol else "network"
    return {
        "source": "opnsense",
        "timestamp": _timestamp(data.get("timestamp")),
        "event_type": event_type,
        "title": f"OPNsense firewall {verb} {title_protocol} traffic",
        "message": message,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol.upper() if protocol else None,
        "host": data.get("host") or "opnsense",
        "program": data.get("program"),
        "interface": interface,
        "firewall_action": action or None,
        "firewall_direction": direction or None,
        "filterlog_fields": fields,
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


def _ubuntu_syslog(data: dict[str, Any]) -> dict[str, Any]:
    program = str(data.get("program") or "").lower()
    message = str(data.get("message") or "")
    common = {
        "source": "ubuntu",
        "timestamp": _timestamp(data.get("timestamp")),
        "message": message,
        "host": data.get("host"),
        "program": program,
    }

    if program == "sshd":
        match = SSH_FAILURE.search(message) or SSH_INVALID_USER.search(message)
        if match:
            return {
                **common,
                "event_type": "linux.ssh_auth_failure",
                "title": "Ubuntu SSH authentication failure",
                "username": match.group("username"),
                "src_ip": match.group("src_ip"),
                "src_port": _as_int(match.groupdict().get("src_port")),
                "dst_port": 22,
            }
        match = SSH_SUCCESS.search(message)
        if match:
            return {
                **common,
                "event_type": "linux.ssh_auth_success",
                "title": "Ubuntu SSH authentication success",
                "username": match.group("username"),
                "src_ip": match.group("src_ip"),
                "src_port": _as_int(match.groupdict().get("src_port")),
                "dst_port": 22,
            }
        return {
            **common,
            "event_type": "linux.sshd_event",
            "title": "Ubuntu SSH service event",
        }

    if program == "sudo":
        command_match = SUDO_COMMAND.search(message)
        if command_match:
            return {
                **common,
                "event_type": "linux.sudo_command",
                "title": "Ubuntu sudo command executed",
                "username": command_match.group("username"),
                "target_user": command_match.group("target_user"),
                "command": command_match.group("command"),
            }
        lower_message = message.lower()
        if "authentication failure" in lower_message or "incorrect password" in lower_message:
            user_match = SUDO_FAILURE_USER.search(message)
            return {
                **common,
                "event_type": "linux.sudo_auth_failure",
                "title": "Ubuntu sudo authentication failure",
                "username": user_match.group("username") if user_match else None,
            }

    return {
        **common,
        "event_type": "linux.syslog_event",
        "title": f"Ubuntu {program or 'system'} log event",
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

    if "cicids_flow" in source_text or "cicids2017" in source_text:
        normalized = {
            "source": source_hint or "cicids_flow",
            "timestamp": _timestamp(data.get("timestamp") or data.get("Timestamp")),
            "event_type": "network.flow",
            "title": "CICIDS2017 network flow",
            "message": "Labeled flow telemetry received from the CICIDS2017 dataset replay.",
            "src_ip": data.get("src_ip") or data.get("Source IP"),
            "dst_ip": data.get("dst_ip") or data.get("Destination IP"),
            "dst_port": _as_int(data.get("dst_port") or data.get("Destination Port")),
            "flow_features": canonical_flow_features(data),
            "sensor_severity": None,
        }
    elif "alert" in data and (
        data.get("event_type") or "suricata" in source_text or "eve" in source_text
    ):
        normalized = _suricata(data)
    elif data.get("_format") == "syslog" and str(data.get("program", "")).lower() in {
        "sshd",
        "sudo",
    }:
        normalized = _ubuntu_syslog(data)
    elif data.get("_format") == "syslog" and data.get("program") == "filterlog":
        normalized = _opnsense_filterlog(data)
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
            "program": data.get("program"),
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
    signature = event.get("signature") or event.get("event_id")
    if not signature and str(event.get("event_type") or "").startswith("generic."):
        # Generic records have no network or detector identifiers. Include their
        # emitter and message so unrelated syslog lines do not merge into one alert.
        signature = "|".join(
            str(value or "")
            for value in (
                event.get("program"),
                event.get("title"),
                event.get("message"),
            )
        )
    stable_parts = [
        str(event.get("source") or ""),
        str(event.get("event_type") or ""),
        str(event.get("src_ip") or ""),
        str(event.get("dst_ip") or ""),
        str(event.get("dst_port") or ""),
        str(signature or ""),
    ]
    return hashlib.sha256("|".join(stable_parts).encode("utf-8")).hexdigest()
