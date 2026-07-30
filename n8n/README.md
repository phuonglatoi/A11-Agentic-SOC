# A11 SOC n8n workflow

This folder contains the local n8n automation workflow used by the A11 SOC lab.
It is intentionally self-contained, so the demo does not require Gmail, Slack,
Telegram, or any cloud account.

## Workflow file

- `workflows/a11_soc_local_automation.json`

The workflow exposes two production webhooks after it is imported and activated:

- `POST /webhook/a11-soc-alert`
  - Called by `NOTIFICATION_WEBHOOK_URL`.
  - Performs a second n8n-stage attack classification from the alert payload.
  - Sends a local email notification to Mailpit.
  - Records the alert notification back into the A11 SOC audit log.
- `POST /webhook/a11-soc-response`
  - Called by `RESPONSE_WEBHOOK_URL` when an approved response action runs in
    `RESPONSE_MODE=webhook`.
  - Validates the local action type, sends a response email to Mailpit and
    records the automation result back into the A11 SOC audit log.

The lab email inbox is Mailpit:

```text
http://127.0.0.1:8025
```

This is intentionally local-only. It gives you email evidence for the thesis
without using Gmail, Outlook or storing SMTP passwords in the repository.

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

For the thesis demo, prefer the **production** webhook URLs:

```text
http://127.0.0.1:5678/webhook/a11-soc-alert
http://127.0.0.1:5678/webhook/a11-soc-response
```

Do not use `/webhook-test/...` for the final demo. Test URLs are temporary and
only exist while the editor is explicitly waiting for a test event. Production
executions do not animate on the canvas; check `n8n -> Executions` instead.

Fast host-side smoke test:

```bash
bash scripts/test_n8n_webhooks.sh
```

Expected proof in A11 SOC:

```text
Audit trail -> actor: n8n -> automation.notification_received
Audit trail -> actor: n8n -> automation.response_webhook
```

Expected proof in Mailpit:

```text
Inbox -> [A11 SOC][HIGH][http_flood_dos] ...
Email body -> Attack type, MITRE, source IP, destination and recommendations
```

If the script returns 404, the workflow is not published or the URL path is
wrong. The correct paths in this project are:

```text
a11-soc-alert
a11-soc-response
```

If the script returns 500 or times out, n8n received the webhook but a later
node failed. Open `n8n -> Executions`, click the failed execution and inspect
`Write Alert Audit to A11 SOC` or `Write Response Audit to A11 SOC`.

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
