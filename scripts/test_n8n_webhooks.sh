#!/usr/bin/env bash
set -u

SOC_URL="${SOC_URL:-http://127.0.0.1:8000}"
N8N_URL="${N8N_URL:-http://127.0.0.1:5678}"
SOC_ADMIN_TOKEN="${SOC_ADMIN_TOKEN:-a11-admin-token-123456}"

alert_payload='{"alert_id":"n8n-smoke-alert","severity":"high","title":"n8n production webhook smoke test","src_ip":"192.168.228.128"}'
response_payload='{"action_type":"notify_soc","target":"soc-analyst","payload":{"alert_id":"n8n-smoke-response","severity":"high","title":"n8n response webhook smoke test","src_ip":"192.168.228.128"}}'

echo "[1/5] Checking A11 SOC API..."
if ! curl -fsS -m 5 "$SOC_URL/health" >/tmp/a11_soc_health.json; then
  echo "FAIL: A11 SOC API is not reachable at $SOC_URL"
  echo "Hint: docker compose ps && docker compose logs --tail=80 api"
  exit 1
fi
cat /tmp/a11_soc_health.json
echo

echo "[2/5] Checking n8n UI..."
if ! curl -fsS -m 5 "$N8N_URL/" >/dev/null; then
  echo "FAIL: n8n is not reachable at $N8N_URL"
  echo "Hint: docker compose --profile automation up -d n8n && docker compose logs --tail=80 n8n"
  exit 1
fi
echo "OK: n8n UI is reachable."

echo "[3/5] Calling production alert webhook..."
alert_response="$(curl -sS -m 15 -w '\nHTTP_STATUS:%{http_code}' \
  -X POST "$N8N_URL/webhook/a11-soc-alert" \
  -H 'Content-Type: application/json' \
  -d "$alert_payload")"
echo "$alert_response"
if ! printf '%s' "$alert_response" | grep -q 'HTTP_STATUS:200'; then
  echo "FAIL: production alert webhook did not return HTTP 200."
  echo "If HTTP 404: publish the workflow and use /webhook/a11-soc-alert, not /webhook-test."
  echo "If HTTP 5xx or timeout: open n8n -> Executions and inspect the failing node."
  exit 1
fi

echo "[4/5] Calling production response webhook..."
response_response="$(curl -sS -m 15 -w '\nHTTP_STATUS:%{http_code}' \
  -X POST "$N8N_URL/webhook/a11-soc-response" \
  -H 'Content-Type: application/json' \
  -d "$response_payload")"
echo "$response_response"
if ! printf '%s' "$response_response" | grep -q 'HTTP_STATUS:200'; then
  echo "FAIL: production response webhook did not return HTTP 200."
  echo "Open n8n -> Executions and inspect the failing node."
  exit 1
fi

echo "[5/5] Checking A11 SOC audit callback from n8n..."
audit_response="$(curl -fsS -m 10 "$SOC_URL/api/v1/audit?limit=20" \
  -H "Authorization: Bearer $SOC_ADMIN_TOKEN" || true)"
if printf '%s' "$audit_response" | grep -q '"actor":"n8n"'; then
  echo "OK: A11 SOC audit contains actor=n8n."
  echo "n8n production automation is working end-to-end."
else
  echo "WARN: webhook returned 200, but actor=n8n was not found in the latest audit rows."
  echo "Check SOC_ADMIN_TOKEN, n8n env A11_SOC_ADMIN_TOKEN, and n8n Executions."
fi
