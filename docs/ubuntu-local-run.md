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
- Syslog collector: UDP `5514`; host UDP `514` is also forwarded to the same
  collector for OPNsense/pfSense versions that use the default syslog port.
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

### Kali -> OPNsense -> A11 SOC restart checklist

Use this checklist after Kali can ping the OPNsense WAN address, for example
`192.168.228.142`.

1. Confirm the SOC stack exposes both syslog ports:

   ```bash
   docker compose --profile automation up -d --build
   docker compose ps
   ```

   The API service should publish:

   ```text
   0.0.0.0:8000->8000/tcp
   0.0.0.0:5514->5514/udp
   0.0.0.0:514->5514/udp
   ```

2. Configure OPNsense remote syslog:

   ```text
   System -> Settings -> Logging
   Enable Remote Logging: checked
   Remote Syslog Server 1: 192.168.1.10
   Remote Syslog Contents: Firewall events
   Source Address: LAN or Any
   IP Protocol: IPv4
   ```

   OPNsense 19.1 may send to UDP `514` even when the UI does not show a port
   field. The Docker mapping above forwards host `514/udp` to the SOC collector.

3. Turn on logging for the WAN lab rules:

   ```text
   Firewall -> Rules -> WAN
   Log packets that are handled by this rule: checked
   ```

4. Prove that Ubuntu receives the syslog packets before checking the dashboard:

   ```bash
   sudo tcpdump -ni any 'udp port 514 or udp port 5514'
   ```

5. Generate traffic from Kali:

   ```bash
   ping -c 5 192.168.228.142
   nmap -sS -Pn -p 22,80,443,8000 192.168.228.142
   ```

6. Watch A11 SOC:

   ```bash
   docker compose logs -f api
   ```

   A successful syslog packet now appears as:

   ```text
   Received syslog datagram from 192.168.1.1; alert_id=... severity=...
   ```

7. Open the SOC dashboard and check `Alert queue`, `Incidents`, `Response` and
   `Audit trail`. If an action is pending, approve it and verify n8n in
   `A11 SOC Local Automation -> Executions`.

### Apache access.log shipper for web attack evidence

If the lab has a Web target at `192.168.1.100`, first create an OPNsense NAT
rule:

```text
WAN address:80 -> 192.168.1.100:80
```

Then run the included access-log shipper on the Web target:

```bash
python3 scripts/ship_apache_access.py \
  --soc-url http://192.168.1.10:8000 \
  --api-key <strong-ingest-key>
```

From Kali:

```bash
curl http://192.168.228.142/.env
curl http://192.168.228.142/admin
dirb http://192.168.228.142
```

This produces the cleanest thesis evidence:

```text
Kali web attack -> OPNsense NAT -> Web access.log
-> shipper -> A11 SOC REST ingest -> RAG/triage
-> incident/report/action -> analyst approval -> n8n audit callback
```

## 8. Operational checks

```bash
docker compose ps
docker compose logs -f api
docker compose logs -f n8n
curl http://127.0.0.1:8000/health
```

If the API cannot start and the log contains `connection failed: server closed
the connection unexpectedly`, wait for PostgreSQL to become healthy and restart
the API:

```bash
docker compose ps
docker compose restart api
```

For a fresh lab where previous `.env` database values were wrong, reset only the
PostgreSQL volume and rebuild:

```bash
docker compose down
docker volume rm a11-agentic-soc_postgres_data
docker compose --profile automation up -d --build
```

The expected complete flow is:

```text
Attacker -> OPNsense/Web/Windows logs -> A11 SOC collectors
-> normalize -> enrich -> correlate -> RAG/triage/optional Ollama
-> alert/incident/report/action -> analyst approval
-> n8n webhook or OPNsense adapter -> audit/dashboard
```
