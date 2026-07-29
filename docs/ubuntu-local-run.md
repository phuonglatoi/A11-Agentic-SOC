# Ubuntu local deployment guide

This guide runs the full A11 Agentic SOC lab on one Ubuntu server after cloning
the repository from GitHub.

## 1. Install dependencies

```bash
sudo apt update
sudo apt install -y git curl ca-certificates
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"
newgrp docker
docker compose version
```

## 2. Clone and configure

```bash
git clone <your-github-repo-url> A11-Agentic-SOC
cd A11-Agentic-SOC
cp .env.example .env
```

Edit `.env` and change at least:

```env
SOC_API_KEY=<strong-ingest-key>
SOC_ADMIN_TOKEN=<strong-admin-token>
POSTGRES_PASSWORD=<strong-db-password>
N8N_ENCRYPTION_KEY=<long-random-string>
```

For a local Ubuntu demo with n8n enabled:

```env
NOTIFICATION_WEBHOOK_URL=http://n8n:5678/webhook/a11-soc-alert
RESPONSE_MODE=webhook
RESPONSE_WEBHOOK_URL=http://n8n:5678/webhook/a11-soc-response
```

Keep `RESPONSE_MODE=dry_run` if you want to demonstrate approval and audit
without calling the response workflow.

## 3. Start the SOC stack

```bash
docker compose --profile automation up -d --build
```

Services:

- A11 SOC dashboard/API: `http://127.0.0.1:8000`
- n8n: `http://127.0.0.1:5678`
- Syslog collector: UDP `5514`
- HEC-compatible collector: TCP `8000`

If the dashboard must be opened from another machine in the lab, set
`SOC_HTTP_BIND=0.0.0.0` and protect the port with the Ubuntu firewall or a
reverse proxy. Do not expose the dashboard directly to the Internet.

## 4. Import n8n workflow

Open n8n and import:

```text
/workflows/a11_soc_local_automation.json
```

Activate the workflow. The SOC container reaches n8n through Docker DNS using:

```text
http://n8n:5678/webhook/a11-soc-alert
http://n8n:5678/webhook/a11-soc-response
```

## 5. Generate demo events

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/demo/generate \
  -H "Authorization: Bearer <strong-admin-token>"
```

Or call the API manually:

```bash
curl -s http://127.0.0.1:8000/api/v1/ingest \
  -H "X-API-Key: <strong-ingest-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "apache",
    "event": "203.0.113.66 - - [28/Jul/2026:15:31:11 +0000] \"GET /.env HTTP/1.1\" 404 512 \"-\" \"dirb/2.22\""
  }'
```

## 6. Query the RAG agent

```bash
curl -s http://127.0.0.1:8000/api/v1/knowledge/search \
  -H "Authorization: Bearer <strong-admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"query":"web attack .env opnsense block source ip","limit":3}'
```

The RAG agent reads only local Markdown playbooks from `knowledge/`. It does
not require a vector database or an Internet connection for the lab workflow.

## 7. Ingest real lab telemetry

Use these local paths for the thesis lab:

- Apache access log shipper: send lines to `POST /services/collector/raw` on
  TCP `8000`.
- Suricata EVE JSON: send events to `POST /services/collector/event` on TCP
  `8000`.
- OPNsense/syslog: send remote syslog to Ubuntu UDP `5514`.
- Splunk: optional observation layer only. Do not make Splunk the primary log
  path for the local-first demo.

## 8. Operational checks

```bash
docker compose ps
docker compose logs -f api
docker compose logs -f n8n
curl http://127.0.0.1:8000/health
```

The expected complete flow is:

```text
Attacker -> OPNsense/Web/Windows logs -> A11 SOC collectors
-> normalize -> enrich -> correlate -> RAG/triage/optional Ollama
-> alert/incident/report/action -> analyst approval
-> n8n webhook or OPNsense adapter -> audit/dashboard
```
