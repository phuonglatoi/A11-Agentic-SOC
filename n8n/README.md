# A11 SOC n8n workflow

This folder contains the local n8n automation workflow used by the A11 SOC lab.
It is intentionally self-contained, so the demo does not require Gmail, Slack,
Telegram, or any cloud account.

## Workflow file

- `workflows/a11_soc_local_automation.json`

The workflow exposes two production webhooks after it is imported and activated:

- `POST /webhook/a11-soc-alert`
  - Called by `NOTIFICATION_WEBHOOK_URL`.
  - Records the alert notification back into the A11 SOC audit log.
- `POST /webhook/a11-soc-response`
  - Called by `RESPONSE_WEBHOOK_URL` when an approved response action runs in
    `RESPONSE_MODE=webhook`.
  - Validates the local action type and records the automation result back into
    the A11 SOC audit log.

## Run on Ubuntu

From the repository root:

```bash
cp .env.example .env
docker compose --profile automation up -d --build
```

Open n8n at:

```text
http://127.0.0.1:5678
```

Import the workflow from the mounted path:

```text
/workflows/a11_soc_local_automation.json
```

Activate the workflow in the n8n UI. Then edit `.env` and set:

```env
NOTIFICATION_WEBHOOK_URL=http://n8n:5678/webhook/a11-soc-alert
RESPONSE_MODE=webhook
RESPONSE_WEBHOOK_URL=http://n8n:5678/webhook/a11-soc-response
```

Restart the API container after changing `.env`:

```bash
docker compose --profile automation up -d --build api n8n
```

## Test the alert webhook from inside Docker

```bash
docker compose exec api python - <<'PY'
import httpx

payload = {
    "alert_id": "alt_manual_test",
    "severity": "high",
    "title": "Manual n8n alert webhook test",
    "src_ip": "93.184.216.34",
}
response = httpx.post(
    "http://n8n:5678/webhook/a11-soc-alert",
    json=payload,
    timeout=10,
)
print(response.status_code)
print(response.text)
PY
```

Then open the A11 SOC dashboard and check the audit log.

## Security notes

- Keep n8n bound to `127.0.0.1` unless it sits behind a protected reverse proxy.
- Change `SOC_ADMIN_TOKEN`, `SOC_API_KEY`, `POSTGRES_PASSWORD`, and
  `N8N_ENCRYPTION_KEY` before any non-lab use.
- The local workflow records approved actions. Real blocking remains controlled
  by the SOC approval gate and by the selected response adapter.
