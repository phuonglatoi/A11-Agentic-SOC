#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
SOC_SYSLOG_HOST="${1:-127.0.0.1}"
SOC_SYSLOG_PORT="${2:-5514}"
CONFIG_PATH="/etc/rsyslog.d/60-a11-soc-forward.conf"

if [[ ! "${SOC_SYSLOG_HOST}" =~ ^[A-Za-z0-9.-]+$ ]]; then
  echo "Use an IPv4 address or hostname for the SOC syslog destination." >&2
  exit 2
fi
if [[ ! "${SOC_SYSLOG_PORT}" =~ ^[0-9]+$ ]] || (( SOC_SYSLOG_PORT < 1 || SOC_SYSLOG_PORT > 65535 )); then
  echo "Syslog port must be between 1 and 65535." >&2
  exit 2
fi
if ! command -v rsyslogd >/dev/null 2>&1; then
  echo "rsyslog is not installed. Install it first: sudo apt install rsyslog" >&2
  exit 2
fi

TEMP_CONFIG="$(mktemp)"
trap 'rm -f "${TEMP_CONFIG}"' EXIT
sed \
  -e "s/SOC_SYSLOG_HOST/${SOC_SYSLOG_HOST}/g" \
  -e "s/SOC_SYSLOG_PORT/${SOC_SYSLOG_PORT}/g" \
  "${REPO_DIR}/deploy/rsyslog/60-a11-soc-forward.conf" >"${TEMP_CONFIG}"

sudo install -o root -g root -m 0644 "${TEMP_CONFIG}" "${CONFIG_PATH}"
sudo rsyslogd -N1
sudo systemctl restart rsyslog
echo "Ubuntu auth/authpriv syslog forwarding enabled to ${SOC_SYSLOG_HOST}:${SOC_SYSLOG_PORT}/UDP."
echo "For a remote SOC, restrict UDP ${SOC_SYSLOG_PORT} to this Ubuntu host at the destination firewall."
