# Ubuntu local deployment guide

This guide runs the full A11 Agentic SOC lab on one Ubuntu server after cloning
the repository from GitHub.

## 1. Install dependencies

```bash
sudo apt update
sudo apt install -y git git-lfs curl ca-certificates
git lfs install
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"
newgrp docker
docker compose version
```

## 2. Clone and configure

```bash
git clone https://github.com/phuonglatoi/A11-Agentic-SOC.git A11-Agentic-SOC
cd A11-Agentic-SOC
git lfs pull
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
- Mailpit local email inbox: `http://127.0.0.1:8025`
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

If you already imported an older workflow before running `git pull`, import the
file again or delete the old workflow and import the new one. n8n stores the
workflow in its own database; it does not live-update from the mounted JSON
file.

If n8n execution fails at `Build Alert Automation Payload` with `access to env
vars denied`, rebuild the n8n container and re-import the workflow. The Compose
file sets `N8N_BLOCK_ENV_ACCESS_IN_NODE=false`, and the current workflow avoids
using `$env` inside Code nodes for maximum compatibility.

Activate the workflow. The SOC container reaches n8n through Docker DNS using:

```text
http://n8n:5678/webhook/a11-soc-alert
http://n8n:5678/webhook/a11-soc-response
```

In n8n 2.x the old `Active` switch is shown as `Published`. For the lab report,
use production webhook URLs, not temporary test URLs:

```text
http://127.0.0.1:5678/webhook/a11-soc-alert
http://127.0.0.1:5678/webhook/a11-soc-response
```

Run an end-to-end smoke test:

```bash
bash scripts/test_n8n_webhooks.sh
```

Successful n8n evidence appears in two places:

- `n8n -> Executions`
- `A11 SOC -> Audit trail`, with `actor=n8n`
- `Mailpit -> Inbox`, with an `[A11 SOC]` alert email

The webhook returns HTTP 200 immediately when n8n accepts the event. The email
and audit callback are side effects that can appear a few seconds later, so use
`bash scripts/test_n8n_webhooks.sh` for the cleanest verification.

The n8n workflow performs its own lightweight attack classification before
sending email. The email subject contains the n8n-stage attack type, for
example:

```text
[A11 SOC][HIGH][http_flood_dos] Possible HTTP flood / DoS traffic
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

Before querying RAG, you can verify the local ML Detection Agent. It sits in the
analysis chain before triage:

```text
normalize -> enrich -> ML Detection Agent -> triage -> RAG -> report/action
```

The bundled model is stored at:

```text
models/attack_classifier.json
```

It is trained from `datasets/a11_seed_labeled_events.jsonl` so the lab can run
immediately after cloning. CICIDS2017 is an optional, older benchmark, not a
recent production dataset. Its CICFlowMeter adapter is intended for flow-feature
classification; it does not claim generalization to raw Apache, Windows or
OPNsense logs. Numeric flow values are bucketed and flow IDs, IPs, timestamps,
and labels are excluded from model features. Replayed original rows remain raw
evidence.

Retrain the built-in seed model:

```bash
python3 scripts/train_attack_classifier.py \
  --input datasets/a11_seed_labeled_events.jsonl \
  --output models/attack_classifier.json
```

The seven CICIDS2017 CSV files are included in `datasets/cicids2017/` using Git
LFS. After `git lfs pull`, train against the bundled directory. The CSV reader
streams rows and keeps a bounded reservoir (250 rows per class per CSV in this
example). Use matching deterministic row split settings for train and
benchmark; identical raw rows are assigned to the same split:

```bash
python3 scripts/train_attack_classifier.py \
  --input datasets/a11_seed_labeled_events.jsonl \
  --csv-dir datasets/cicids2017 \
  --sample-per-class 250 \
  --split train --holdout-percent 20 \
  --output models/attack_classifier.json
```

The benchmark takes a bounded stratified sample without replacement. Review
macro metrics and per-class support; this sample is for lab comparison and is
not a production SLA.

```bash
python3 scripts/benchmark_attack_classifier.py \
  --csv-dir datasets/cicids2017 \
  --split test --holdout-percent 20 \
  --max-per-class 250 --sample-size 1000 \
  --output work/cicids2017_holdout.json
```

The replay adapter strips the target label before ingestion. To send a small
DoS-labeled sample into the local lab collector, set `SOC_API_KEY` and run:

```bash
export SOC_API_KEY="<your-ingest-key>"
python3 scripts/replay_cicids_flows.py \
  datasets/cicids2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv \
  --label http_flood_dos --rows 120 --interval-ms 100
```

A flow prediction alone does not raise severity. A deterministic rule requires
100 correlated web-service flows on one fingerprint before an incident and
notification action can be proposed; ensure `NOTIFICATION_WEBHOOK_URL` points
to the active production n8n alert webhook. If source/destination/port vary, the
events remain separate and the volume threshold may not be reached.

After pulling this update, the trained model is already in the repository, so
you do not need to install ML packages or train again just to run the SOC:

```bash
git pull --ff-only
docker compose up -d --build api
docker compose --profile automation up -d
```

To replay from the Windows host where the CSV folder exists, set the same
ingestion key as the A11 `.env` and point at the Ubuntu VM API address (adjust
the address if your VMware network uses another one):

```powershell
$env:SOC_API_KEY = "<same-value-as-SOC_API_KEY-in-.env>"
python scripts/replay_cicids_flows.py `
  "C:\Users\Admin\Documents\MachineLearningCVE\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv" `
  --url http://192.168.1.10:8000/api/v1/ingest `
  --label http_flood_dos --rows 120 --interval-ms 100
```

This requires the Windows host to reach port 8000 on Ubuntu and the ingestion
key to match. If replaying inside Ubuntu instead, mount/copy the external dataset
there and use the default `127.0.0.1` URL. A11 still creates a high/critical
incident/email only when deterministic triage criteria are met; model prediction
alone does not promote severity.

Check that the model is loaded:

```bash
curl -s http://127.0.0.1:8000/api/v1/runtime \
  -H "Authorization: Bearer <strong-admin-token>"
```

The dashboard should show `RULES + ML + RAG` when the model is available. In an
alert detail panel, the `ML Detection Agent` section shows the predicted attack
type, confidence and top labels.

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
- Ubuntu host authentication events (`sshd` and `sudo`): install the included
  rsyslog forwarder; it forwards only `auth`/`authpriv` to the local collector.
- Splunk: optional observation layer only. Do not make Splunk the primary log
  path for the local-first demo.

Install and smoke-test Ubuntu host authentication collection on the SOC VM:

```bash
sudo apt update && sudo apt install -y rsyslog
sudo bash scripts/install_ubuntu_syslog_forwarder.sh
bash scripts/test_ubuntu_syslog.sh
```

The forwarder defaults to `127.0.0.1:5514`, so authentication logs stay on the
Ubuntu SOC host until they enter the local collector. The smoke test emits at
most five synthetic SSH failure messages, one per second, from a reserved
documentation IP; it does not attempt real logins or generate a flood. Three
matching failures should create a Medium alert named **Ubuntu SSH
authentication failure**. The parser also recognizes successful SSH logins,
sudo authentication failures and selected sensitive root commands. Ordinary
Ubuntu system/journal messages outside `auth`/`authpriv` are not forwarded by
this default config.

The Docker services have memory/CPU ceilings and rotating local container logs
to limit resource and disk growth during a lab run. Inspect operational
container output with `docker compose logs`; the API container's own stdout is
deliberately not sent back into its own syslog collector, which would create a
feedback loop. Docker stdout is therefore bounded locally, not yet treated as
SOC telemetry.

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

In the current one-server lab, Apache and A11 SOC share Ubuntu IP
`192.168.1.10`. Create a source-restricted OPNsense NAT rule:

```text
Interface: WAN
Protocol: TCP
Source: 192.168.228.128/32 (Kali only)
Destination: WAN address:80
Redirect target: 192.168.1.10:80
Filter rule association: Pass
Log: enabled
```

Do not publish A11 `8000`, n8n `5678`, Mailpit `8025`, or PostgreSQL `5432`
through this NAT rule. Then run the included access-log shipper on Ubuntu in a
second terminal:

```bash
sudo python3 scripts/ship_apache_access.py \
  --soc-url http://192.168.1.10:8000 \
  --api-key <strong-ingest-key>
```

For normal operation, install it once as a hardened systemd service instead of
keeping a terminal open:

```bash
sudo bash scripts/install_apache_shipper_service.sh
sudo systemctl status a11-apache-shipper
sudo journalctl -u a11-apache-shipper -f
```

The installer reads `SOC_API_KEY` from the local `.env`, stores it in a root-only
environment file, starts after Apache/Docker/network readiness, follows log
rotation, and retries delivery when A11 is temporarily unavailable. It never
commits the secret to Git.

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

### Controlled GoldenEye / HTTP flood lab

Only run this against the lab WAN address, never against public systems. A safe
starting point is a short run from Kali:

```bash
timeout -k 2s 10s python3 goldeneye.py http://192.168.228.142 -s 5 -w 1
```

This is still a real load-generating tool: use only the isolated lab, watch
`docker stats` and stop immediately if latency or memory use rises. Do not use
the previous high settings such as hundreds of sockets/workers on a VM that is
also hosting the SOC. For repeatable rule/parser validation without load, use
`bash scripts/test_ubuntu_syslog.sh` instead.

The SOC detects the firewall side of this test from OPNsense `filterlog` syslog.
The context gate requires a validated firewall action, inbound direction, a
non-infrastructure source, TCP, a web-facing destination port, and at least 50
correlated events inside the correlation window. It then raises:

```text
Possible HTTP flood / DoS traffic
Severity: High
MITRE: T1498 Network Denial of Service
```

For blocked TCP reconnaissance, the triage agent raises `Probable network scan /
reconnaissance` as high severity after roughly 20 correlated denied TCP events
from the same source. This makes short Kali `nmap` demos easier to observe while
still requiring repeated firewall evidence rather than a single blocked packet.

For the richest evidence, also ship Apache `access.log` as described above. The
firewall log proves the network flood; the access log proves the HTTP path and
user-agent such as `GoldenEye`, `sqlmap`, `dirb` or `nikto`.

### Why normal OPNsense traffic has different source IPs

OPNsense records both inbound and outbound traffic. A source IP shown in the
Alert queue is the packet source after normalization, not automatically the
attacker. The current detection policy therefore treats the fields together:

```text
firewall_action + firewall_direction + src_ip/source_asset
+ protocol + dst_port + correlated event count
```

- `192.168.228.128`, inbound on WAN: controlled Kali attack source.
- `192.168.1.10`, outbound: Ubuntu service traffic, not an external attack.
- `192.168.1.1` or `192.168.228.142`: OPNsense infrastructure addresses.
- UDP/TCP PASS events below a detection threshold: retained as LOW telemetry.

Outbound records, infrastructure-originated records, and malformed/generic
filterlog records without a validated action are not promoted to HTTP flood by
the ML agent. The dashboard shows `PASS/BLOCK` and `IN/OUT` beside the source,
plus the normalized destination and mapped asset, so analysts can verify the
decision without opening raw JSON first.

VMware infrastructure addresses are also modeled explicitly:

```text
192.168.228.2   VMware NAT gateway
192.168.228.254 VMware network/DHCP service
0.0.0.0 -> 255.255.255.255 DHCP/bootstrap broadcast
```

These records remain available as LOW telemetry and are never presented as the
attacker. The expected attack source for the documented lab is
`kali-lab / 192.168.228.128`.

Existing alerts retain their historical peak severity for audit integrity. To
validate a rule update, generate a new event after the correlation window or
mark the old alert `closed`/`false_positive`; do not judge the new policy from
an alert that was already escalated by an older version.

## 8. Operational checks

```bash
docker compose ps
docker compose logs -f api
docker compose logs -f n8n
curl http://127.0.0.1:8000/health
```

If the dashboard keeps loading after a Kali flood or after pressing **Run lab
scenario**, first check whether the API is busy with syslog backlog:

```bash
curl -m 10 http://127.0.0.1:8000/health
docker compose logs --tail=80 api
```

The API now uses a bounded syslog queue so a log storm cannot create unlimited
background tasks. The health response includes `syslog_queue.received`,
`processed`, `dropped`, and `queue_size`. If the old container is still running,
pull and rebuild:

```bash
git pull
docker compose --profile automation up -d --build
```

For very small Ubuntu VMs, keep Ollama disabled, lower ingest pressure, and tune
`.env`:

```env
SYSLOG_QUEUE_MAXSIZE=1000
SYSLOG_WORKER_COUNT=1
WEBHOOK_TIMEOUT_SECONDS=5
```

The queue is bounded and the API clamps worker settings to 1–4 workers and
queue sizes to 100–10,000. When full, UDP syslog is dropped rather than allowed
to consume unbounded memory; monitor `received`, `processed`, `dropped` and
`queue_size` in `/health`. Ollama has a 3 GiB container cap by default so a
large local model cannot take all host memory; a 7B model may not fit under that
cap. Increase `mem_limit` only after confirming the VM has sufficient RAM and
headroom for PostgreSQL, API, n8n and the OS.

If the API is already stuck from a previous flood, restart only the API
container:

```bash
docker compose restart api
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
-> normalize -> enrich -> ML Detection Agent -> correlate -> RAG/triage/optional Ollama
-> alert/incident/report/action -> analyst approval
-> n8n webhook or OPNsense adapter -> audit/dashboard
```
