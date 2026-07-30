#!/usr/bin/env bash
set -u

env_value() {
  local name="$1"
  if [ -f .env ]; then
    grep -E "^${name}=" .env | tail -n 1 | cut -d= -f2-
  fi
}

SOC_HTTP_PORT="${SOC_HTTP_PORT:-$(env_value SOC_HTTP_PORT)}"
N8N_PORT="${N8N_PORT:-$(env_value N8N_PORT)}"
MAILPIT_UI_PORT="${MAILPIT_UI_PORT:-$(env_value MAILPIT_UI_PORT)}"
SOC_URL="${SOC_URL:-http://127.0.0.1:${SOC_HTTP_PORT:-8000}}"
N8N_URL="${N8N_URL:-http://127.0.0.1:${N8N_PORT:-5678}}"
MAILPIT_URL="${MAILPIT_URL:-http://127.0.0.1:${MAILPIT_UI_PORT:-8025}}"
SOC_ADMIN_TOKEN="${SOC_ADMIN_TOKEN:-$(env_value SOC_ADMIN_TOKEN)}"
SOC_ADMIN_TOKEN="${SOC_ADMIN_TOKEN:-a11-admin-token-123456}"

alert_payload='{"alert_id":"n8n-smoke-alert","severity":"high","title":"n8n production webhook smoke test","description":"Controlled GoldenEye-like HTTP flood smoke test","attack_type":"http_flood_dos","confidence":0.96,"src_ip":"192.168.228.128","dst_ip":"192.168.228.142","dst_port":80,"event_type":"opnsense.firewall_block","mitre":[{"id":"T1498","name":"Network Denial of Service"}],"reasons":["Smoke test validates n8n attack analysis and email notification."],"recommendations":["Open Mailpit and verify the generated alert email."]}'
response_payload='{"action_type":"notify_soc","target":"soc-analyst","payload":{"alert_id":"n8n-smoke-response","severity":"high","title":"n8n response webhook smoke test","attack_type":"http_flood_dos","src_ip":"192.168.228.128"}}'

echo "[1/6] Checking A11 SOC API..."
if ! curl -fsS -m 5 "$SOC_URL/health" >/tmp/a11_soc_health.json; then
  echo "FAIL: A11 SOC API is not reachable at $SOC_URL"
  echo "Hint: docker compose ps && docker compose logs --tail=80 api"
  exit 1
fi
cat /tmp/a11_soc_health.json
echo

echo "[2/6] Checking n8n UI..."
if ! curl -fsS -m 5 "$N8N_URL/" >/dev/null; then
  echo "FAIL: n8n is not reachable at $N8N_URL"
  echo "Hint: docker compose --profile automation up -d n8n && docker compose logs --tail=80 n8n"
  exit 1
fi
echo "OK: n8n UI is reachable."

echo "[3/6] Checking Mailpit email inbox..."
if ! curl -fsS -m 5 "$MAILPIT_URL/" >/dev/null; then
  echo "FAIL: Mailpit is not reachable at $MAILPIT_URL"
  echo "Hint: docker compose --profile automation up -d mailpit && docker compose logs --tail=80 mailpit"
  exit 1
fi
echo "OK: Mailpit UI is reachable at $MAILPIT_URL."

echo "[4/6] Calling production alert webhook..."
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

echo "[5/6] Calling production response webhook..."
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

echo "[6/6] Checking A11 SOC audit callback and Mailpit email from n8n..."
audit_response="$(curl -fsS -m 10 "$SOC_URL/api/v1/audit?limit=20" \
  -H "Authorization: Bearer $SOC_ADMIN_TOKEN" || true)"
if printf '%s' "$audit_response" | grep -q '"actor":"n8n"'; then
  echo "OK: A11 SOC audit contains actor=n8n."
  echo "n8n production automation is working end-to-end."
else
  echo "WARN: webhook returned 200, but actor=n8n was not found in the latest audit rows."
  echo "Check SOC_ADMIN_TOKEN, n8n env A11_SOC_ADMIN_TOKEN, and n8n Executions."
fi

mail_response="$(curl -fsS -m 10 "$MAILPIT_URL/api/v1/messages?limit=20" || true)"
if printf '%s' "$mail_response" | grep -qi 'n8n production webhook smoke test'; then
  echo "OK: Mailpit contains the generated alert email."
  echo "Open $MAILPIT_URL and capture the email notification for the report."
else
  echo "WARN: webhook returned 200, but the expected email was not found in Mailpit."
  echo "Open n8n -> Executions and inspect 'Send Alert Email to Mailpit'."
fi
