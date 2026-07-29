# Playbook: Authentication brute force

Trigger: Windows event 4625 or repeated web authentication failures from the
same source in a short time window.

1. Correlate failures by source IP, username, target host, and five-minute
   window.
2. Check for a successful logon after the failures.
3. Review asset criticality and whether the user is privileged.
4. For a public hostile source, request an IP block; for an internal source,
   investigate the endpoint before containment.
5. Reset the affected account only after identity verification and follow the
   organization's access-control procedure.
6. Preserve event 4624/4625, VPN, firewall, and endpoint telemetry.

MITRE ATT&CK: T1110, T1078.
