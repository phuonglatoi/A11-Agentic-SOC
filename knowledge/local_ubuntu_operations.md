# Playbook: Local Ubuntu SOC operations

Trigger: deployment, health-check, or runtime investigation on the Ubuntu host
that runs the A11 SOC stack.

1. Confirm Docker and Docker Compose are running on the Ubuntu server.
2. Check container health with `docker compose ps`.
3. Check API health with `curl http://127.0.0.1:8000/health`.
4. Review API logs with `docker compose logs -f api`.
5. Review n8n workflow logs with `docker compose logs -f n8n`.
6. Keep the SOC dashboard bound to localhost unless a protected reverse proxy,
   VPN, or Tailscale path is in place.
7. Allow only the lab firewall, web server, and endpoint subnets to send syslog
   or HEC traffic to the Ubuntu server.
8. Back up PostgreSQL before deleting volumes or rebuilding the stack.

Tags: ubuntu, docker, local-first, operations, health-check.
