from __future__ import annotations

import asyncio
import json
import logging
import os

import httpx

logger = logging.getLogger("splunk-poller")
logging.basicConfig(level=logging.INFO)


def _setting(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


async def poll_once(client: httpx.AsyncClient) -> int:
    splunk_url = _setting("SPLUNK_URL").rstrip("/")
    splunk_token = _setting("SPLUNK_TOKEN")
    search = _setting(
        "SPLUNK_SEARCH",
        "search index=main earliest=-90s | head 500",
    )
    auth_scheme = _setting("SPLUNK_AUTH_SCHEME", "Bearer")
    soc_url = _setting("SOC_API_URL", "http://api:8000").rstrip("/")
    soc_key = _setting("SOC_API_KEY", "change-me-ingest-key")
    if not splunk_url or not splunk_token:
        raise RuntimeError("SPLUNK_URL and SPLUNK_TOKEN are required.")

    response = await client.post(
        f"{splunk_url}/services/search/v2/jobs/export",
        headers={"Authorization": f"{auth_scheme} {splunk_token}"},
        data={
            "search": search,
            "output_mode": "json",
            "preview": "false",
        },
    )
    response.raise_for_status()
    events = []
    for line in response.text.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        result = row.get("result")
        if not result:
            continue
        raw = result.get("_raw")
        events.append(raw if raw else result)
    if not events:
        return 0
    forward = await client.post(
        f"{soc_url}/api/v1/ingest",
        headers={"X-API-Key": soc_key},
        json={"source": "splunk", "events": events},
    )
    forward.raise_for_status()
    return len(events)


async def main() -> None:
    interval = int(_setting("SPLUNK_POLL_INTERVAL_SECONDS", "60"))
    verify_tls = _setting("SPLUNK_VERIFY_TLS", "true").lower() in {
        "1",
        "true",
        "yes",
    }
    async with httpx.AsyncClient(timeout=90, verify=verify_tls) as client:
        while True:
            try:
                count = await poll_once(client)
                logger.info("Forwarded %s Splunk results to the SOC pipeline.", count)
            except Exception:
                logger.exception("Splunk polling cycle failed.")
            await asyncio.sleep(max(15, interval))


if __name__ == "__main__":
    asyncio.run(main())
