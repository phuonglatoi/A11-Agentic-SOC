#!/usr/bin/env bash
set -euo pipefail

SOC_URL="${SOC_URL:-http://127.0.0.1:8000}"
COUNT="${COUNT:-3}"

if [[ ! "${SOC_URL}" =~ ^http://(127\.0\.0\.1|localhost)(:[0-9]+)?$ ]]; then
  echo "Safety stop: this smoke test only permits a local SOC_URL (127.0.0.1/localhost)." >&2
  exit 2
fi
if [[ ! "${COUNT}" =~ ^[1-5]$ ]]; then
  echo "COUNT must be 1..5. This test intentionally cannot generate a high-volume alert." >&2
  exit 2
fi
command -v logger >/dev/null || { echo "logger is required (usually provided by util-linux)." >&2; exit 2; }
command -v curl >/dev/null || { echo "curl is required." >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required." >&2; exit 2; }

get_stats() {
  curl --fail --silent --show-error --max-time 3 "${SOC_URL}/health" | python3 -c '
import json,sys
data=json.load(sys.stdin)
q=data.get("syslog_queue")
if not isinstance(q, dict):
    raise SystemExit("Syslog collector is not active; check SYSLOG_ENABLED and API logs.")
print(q["received"], q["processed"], q["dropped"])
'
}

read -r before_received before_processed before_dropped < <(get_stats)
source_ip="198.51.100.$((RANDOM % 200 + 20))"
marker="a11-safe-smoke-$(date +%s)-${RANDOM}"
echo "Sending ${COUNT} synthetic SSH failures to local rsyslog; source=${source_ip}; 1 event/second."

for ((i = 1; i <= COUNT; i++)); do
  logger -p authpriv.notice -t sshd -- \
    "Failed password for invalid user ${marker} from ${source_ip} port $((42000 + i)) ssh2"
  sleep 1
done

deadline=$((SECONDS + 30))
while (( SECONDS < deadline )); do
  read -r received processed dropped < <(get_stats)
  if (( received - before_received >= COUNT && processed - before_processed >= COUNT )); then
    echo "OK: SOC received and processed the synthetic Ubuntu auth events."
    echo "Syslog counters: received=${received}, processed=${processed}, dropped=${dropped}."
    echo "Open Alert queue and find 'Ubuntu SSH authentication failure' (the reserved TEST-NET source is synthetic)."
    if (( dropped > before_dropped )); then
      echo "WARNING: the queue drop counter increased during this smoke test." >&2
      exit 1
    fi
    exit 0
  fi
  sleep 1
done

echo "Timed out waiting for Ubuntu syslog events. Check rsyslog service/config and docker compose logs api." >&2
exit 1
