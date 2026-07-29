from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from app.agents.response import is_safe_block_target
from app.config import Settings


class ResponseExecutor:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def execute(
        self, action_type: str, target: str | None, payload: dict[str, Any]
    ) -> dict[str, Any]:
        if action_type == "notify_soc":
            return await self._notify(payload)
        mode = self.settings.response_mode
        if mode not in {"dry_run", "webhook", "opnsense"}:
            mode = "dry_run"

        if action_type == "block_ip" and not is_safe_block_target(target):
            return {
                "ok": False,
                "mode": mode,
                "error": "Refused unsafe, private, or invalid block target.",
            }

        if mode == "dry_run":
            return {
                "ok": True,
                "mode": "dry_run",
                "message": f"Validated {action_type}; no external change was made.",
                "target": target,
            }
        if mode == "webhook":
            return await self._webhook(action_type, target, payload)
        if mode == "opnsense" and action_type == "block_ip":
            return await self._opnsense_block(target)
        return {
            "ok": False,
            "mode": mode,
            "error": f"{action_type} is not supported by the selected response adapter.",
        }

    async def _notify(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.settings.notification_webhook_url:
            return {
                "ok": True,
                "mode": "local",
                "message": "Notification recorded in the local action and audit log.",
            }
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                response = await client.post(
                    self.settings.notification_webhook_url, json=payload
                )
                response.raise_for_status()
                return {
                    "ok": True,
                    "mode": "webhook",
                    "status_code": response.status_code,
                }
        except httpx.HTTPError as exc:
            return {"ok": False, "mode": "webhook", "error": str(exc)[:300]}

    async def _webhook(
        self, action_type: str, target: str | None, payload: dict[str, Any]
    ) -> dict[str, Any]:
        if not self.settings.response_webhook_url:
            return {"ok": False, "mode": "webhook", "error": "Webhook URL is empty."}
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                response = await client.post(
                    self.settings.response_webhook_url,
                    json={
                        "action_type": action_type,
                        "target": target,
                        "payload": payload,
                    },
                )
                response.raise_for_status()
                return {
                    "ok": True,
                    "mode": "webhook",
                    "status_code": response.status_code,
                    "body": response.text[:500],
                }
        except httpx.HTTPError as exc:
            return {"ok": False, "mode": "webhook", "error": str(exc)[:300]}

    async def _opnsense_block(self, target: str | None) -> dict[str, Any]:
        if not all(
            [
                self.settings.opnsense_url,
                self.settings.opnsense_key,
                self.settings.opnsense_secret,
            ]
        ):
            return {
                "ok": False,
                "mode": "opnsense",
                "error": "OPNsense URL or API credentials are missing.",
            }
        base = self.settings.opnsense_url.rstrip("/")
        alias = quote(self.settings.opnsense_alias, safe="")
        url = f"{base}/api/firewall/alias_util/add/{alias}"
        try:
            async with httpx.AsyncClient(
                timeout=20,
                verify=self.settings.opnsense_verify_tls,
                auth=(self.settings.opnsense_key, self.settings.opnsense_secret),
            ) as client:
                response = await client.post(url, json={"address": target})
                response.raise_for_status()
                body = response.json()
                success = str(body.get("status", "")).lower() in {
                    "done",
                    "ok",
                    "success",
                } or body.get("result") == "saved"
                return {
                    "ok": success,
                    "mode": "opnsense",
                    "alias": self.settings.opnsense_alias,
                    "target": target,
                    "response": body,
                }
        except (httpx.HTTPError, ValueError) as exc:
            return {"ok": False, "mode": "opnsense", "error": str(exc)[:300]}
