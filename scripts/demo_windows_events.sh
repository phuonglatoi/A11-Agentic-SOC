#!/usr/bin/env bash
set -u

# Demo script for Windows Event 4625 (brute force) and 1102 (audit log cleared)
# Run on the Ubuntu machine where A11 SOC is deployed.
#
# Usage:
#   bash scripts/demo_windows_events.sh
#
# Environment variables (optional, override from .env):
#   SOC_URL=http://127.0.0.1:8000
#   SOC_API_KEY=change-me-ingest-key
#   SOC_ADMIN_TOKEN=change-me-admin-token

SOC_URL="${SOC_URL:-http://127.0.0.1:8000}"
API_KEY="${SOC_API_KEY:-change-me-ingest-key}"
ADMIN_TOKEN="${SOC_ADMIN_TOKEN:-change-me-admin-token}"

echo "========================================"
echo "Demo #5.4a: Windows Event 4625 (Brute Force)"
echo "========================================"
echo "Sending 12 Windows 4625 events to trigger HIGH severity..."
echo ""
for i in $(seq 1 12); do
  printf "  Event %2d/12: " "$i"
  curl -s -X POST "$SOC_URL/api/v1/ingest" \
    -H "X-API-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"source\":\"windows\",\"event\":{\"EventID\":4625,\"Computer\":\"WIN-ENDPOINT-01\",\"TargetUserName\":\"administrator\",\"IpAddress\":\"192.168.228.128\",\"Message\":\"An account failed to log on.\",\"TimeCreated\":\"2026-07-31T15:31:$(printf '%02d' "$i")Z\"}}" \
    2>/dev/null
  echo
done
echo ""
echo ">>> Screenshot now: SOC dashboard showing HIGH brute force alert"
echo ">>> Look for: severity=high, event_type=windows.4625, event_count=12"
echo ">>> Dashboard: $SOC_URL"
echo ""
read -r -p "Press Enter to continue to Demo #5.4b..." _

echo ""
echo "========================================"
echo "Demo #5.4b: Windows Event 1102 (Critical)"
echo "========================================"
echo "Sending Windows 1102 event (audit log cleared)..."
echo ""
curl -s -X POST "$SOC_URL/api/v1/ingest" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"source":"windows","event":{"EventID":1102,"Computer":"WIN-ENDPOINT-01","TargetUserName":"lab-admin","Message":"The audit log was cleared.","TimeCreated":"2026-07-31T15:31:13Z"}}' \
  2>/dev/null
echo ""
echo ""
echo ">>> Screenshot now: SOC dashboard showing CRITICAL alert + incident + isolate_host"
echo ">>> Look for: severity=critical, event_type=windows.1102"
echo ">>> Incident created with priority=critical"
echo ">>> Response action: isolate_host, status=pending"
echo ">>> Dashboard: $SOC_URL"
echo ""
read -r -p "Press Enter to continue to Demo #5.4c..." _

echo ""
echo "========================================"
echo "Demo #5.4c: Approve isolate_host (dry_run)"
echo "========================================"
echo "Getting pending actions..."
echo ""
ACTIONS_RAW="$(curl -s "$SOC_URL/api/v1/actions?status=pending" \
  -H "Authorization: Bearer $ADMIN_TOKEN" 2>/dev/null)"

# Try to extract isolate_host action ID with python3
ACTION_ID=""
if command -v python3 >/dev/null 2>&1; then
  ACTION_ID="$(printf '%s' "$ACTIONS_RAW" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for action in data:
        if action.get('action_type') == 'isolate_host':
            print(action['id'])
            break
except Exception:
    pass
" 2>/dev/null)"
fi

if [ -z "$ACTION_ID" ]; then
  echo "Could not auto-detect isolate_host action ID."
  echo "Pending actions:"
  printf '%s\n' "$ACTIONS_RAW"
  echo ""
  echo "Find the action with action_type=isolate_host, then run:"
  echo "  curl -X POST $SOC_URL/api/v1/actions/<ACTION_ID>/decision \\"
  echo "    -H 'Authorization: Bearer $ADMIN_TOKEN' \\"
  echo "    -H 'Content-Type: application/json' \\"
  echo "    -d '{\"decision\":\"approve\",\"analyst\":\"soc-analyst\",\"reason\":\"Approved for lab demo\"}'"
else
  echo "Found isolate_host action: $ACTION_ID"
  echo "Approving..."
  echo ""
  curl -s -X POST "$SOC_URL/api/v1/actions/$ACTION_ID/decision" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"decision":"approve","analyst":"soc-analyst","reason":"Approved for lab demo"}' \
    2>/dev/null
  echo ""
fi
echo ""
echo ">>> Screenshot now: Action status=executed, result mode=dry_run"
echo ">>> Dashboard: $SOC_URL -> Response tab"
echo ""
read -r -p "Press Enter to continue to Demo #5.4d..." _

echo ""
echo "========================================"
echo "Demo #5.4d: Audit Trail"
echo "========================================"
echo "GET /api/v1/audit?limit=50"
echo ""
curl -s "$SOC_URL/api/v1/audit?limit=50" \
  -H "Authorization: Bearer $ADMIN_TOKEN" 2>/dev/null
echo ""
echo ""
echo ">>> Screenshot now: Audit trail showing all steps"
echo ">>> Look for:"
echo "    - actor=soc-pipeline, action=alert.created / alert.correlated"
echo "    - actor=response-agent, action=response.requested"
echo "    - actor=soc-analyst, action=response.approved"
echo "    - actor=response-agent, action=response.executed"
echo ""
echo "========================================"
echo "Demo complete! All 4 screenshots captured."
echo "========================================"