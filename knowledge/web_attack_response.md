# Playbook: Web scan, enumeration, and application attack

Trigger: repeated HTTP 401/403/404 responses, sensitive paths such as `.env`,
`phpmyadmin`, `wp-admin`, traversal strings, SQL injection strings, or a
Suricata web exploitation signature.

1. Confirm the source IP, target asset, path, response status, and request rate.
2. Check whether the source belongs to the authorized Kali lab range.
3. Preserve the Apache access/error logs and correlated firewall events.
4. If exploitation is likely, raise an incident and request approval to add the
   public source IP to the OPNsense `SOC_BLOCKLIST` alias.
5. Do not automatically block private, loopback, multicast, or unspecified IPs.
6. Review the exposed application, patch the vulnerable component, and rotate
   any credential that may have appeared in a leaked configuration file.
7. Close as false positive only when an analyst verifies an approved scan.

MITRE ATT&CK: T1595.002, T1190, T1046.
