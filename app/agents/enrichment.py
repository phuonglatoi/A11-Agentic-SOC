from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any


class EnrichmentAgent:
    def __init__(self, data_dir: Path):
        self.assets = self._load(data_dir / "assets.json")
        self.iocs = self._load(data_dir / "iocs.json")
        self.assets_by_ip = {
            ip: asset for asset in self.assets for ip in asset.get("ips", [])
        }
        self.iocs_by_value = {ioc.get("value"): ioc for ioc in self.iocs}

    @staticmethod
    def _load(path: Path) -> list[dict[str, Any]]:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def enrich(self, event: dict[str, Any]) -> dict[str, Any]:
        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")
        matches = [
            self.iocs_by_value[value]
            for value in (src_ip, dst_ip)
            if value in self.iocs_by_value
        ]
        asset = self.assets_by_ip.get(dst_ip) or self.assets_by_ip.get(
            event.get("host")
        )
        return {
            "source_ip": self._ip_context(src_ip),
            "destination_ip": self._ip_context(dst_ip),
            "asset": asset,
            "ioc_matches": matches,
            "lab_source": bool(
                src_ip and self.assets_by_ip.get(src_ip, {}).get("type") == "security-test"
            ),
        }

    @staticmethod
    def _ip_context(value: str | None) -> dict[str, Any] | None:
        if not value:
            return None
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return {"value": value, "valid": False}
        return {
            "value": value,
            "valid": True,
            "version": ip.version,
            "private": ip.is_private,
            "global": ip.is_global,
            "loopback": ip.is_loopback,
            "multicast": ip.is_multicast,
            "reserved": ip.is_reserved,
        }
