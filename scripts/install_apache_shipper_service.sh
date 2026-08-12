#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run with sudo: sudo bash scripts/install_apache_shipper_service.sh" >&2
  exit 1
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)
ENV_FILE="${REPO_DIR}/.env"
LOG_FILE="/var/log/apache2/access.log"

if [[ ! -f ${ENV_FILE} ]]; then
  echo "Missing ${ENV_FILE}. Create it from .env.example first." >&2
  exit 1
fi

if [[ ! -r ${LOG_FILE} ]]; then
  echo "Apache log is not readable: ${LOG_FILE}" >&2
  exit 1
fi

SOC_API_KEY=$(sed -n 's/^SOC_API_KEY=//p' "${ENV_FILE}" | tail -n 1)
if [[ -z ${SOC_API_KEY} ]]; then
  echo "SOC_API_KEY is missing from ${ENV_FILE}." >&2
  exit 1
fi
if [[ ! ${SOC_API_KEY} =~ ^[A-Za-z0-9._:-]+$ ]]; then
  echo "SOC_API_KEY must use only letters, digits, dot, underscore, colon, or hyphen." >&2
  exit 1
fi

install -d -m 0700 /etc/a11-soc
{
  printf 'SOC_URL=%s\n' 'http://192.168.1.10:8000'
  printf 'SOC_API_KEY=%s\n' "${SOC_API_KEY}"
  printf 'APACHE_LOG_FILE=%s\n' "${LOG_FILE}"
} > /etc/a11-soc/apache-shipper.env
chmod 0600 /etc/a11-soc/apache-shipper.env

cat > /etc/systemd/system/a11-apache-shipper.service <<EOF
[Unit]
Description=A11 SOC Apache access-log shipper
After=network-online.target apache2.service docker.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/a11-soc/apache-shipper.env
WorkingDirectory=${REPO_DIR}
ExecStart=/usr/bin/python3 ${REPO_DIR}/scripts/ship_apache_access.py
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadOnlyPaths=${REPO_DIR} /var/log/apache2

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now a11-apache-shipper.service
systemctl --no-pager --full status a11-apache-shipper.service

echo
echo "A11 Apache shipper installed. Follow it with:"
echo "  sudo journalctl -u a11-apache-shipper -f"
