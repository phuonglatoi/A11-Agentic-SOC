# Playbook: HTTP flood / DoS response

Trigger: a single source creates a high volume of TCP firewall or web requests
against HTTP/HTTPS service ports inside the correlation window.

1. Confirm the activity is part of an approved lab test before containment.
2. Compare OPNsense firewall live log, state table and interface throughput with
   Apache access.log to determine whether traffic reached the web service.
3. Check request path, user-agent, response code and request rate. Tools such as
   GoldenEye, ab, dirb, gobuster, sqlmap and nikto can create distinctive user
   agents or burst patterns during controlled tests.
4. If the traffic is unauthorized, rate-limit or block the source at OPNsense and
   verify the rule hit counter increases.
5. Preserve evidence: attacker IP, target IP/port, time range, event_count,
   firewall action, access-log samples and SOC incident/report ID.
6. Monitor service health and recovery after mitigation.
7. Record analyst approval and automation outcome in the A11 SOC audit log.

MITRE ATT&CK: T1498, T1498.001, T1499.
Tags: dos, ddos, http_flood, goldeneye, opnsense, firewall, apache, rate_limit,
block_ip, incident_response.
