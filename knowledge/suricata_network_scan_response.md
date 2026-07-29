# Playbook: Suricata network scan response

Trigger: Suricata EVE alert for Nmap, service discovery, vulnerability scan, or
attempted information leak.

1. Confirm source IP, destination IP, destination port, protocol, signature, and
   sensor severity from the raw EVE JSON.
2. Correlate with OPNsense firewall logs and Apache access logs in the same
   five-minute window.
3. Check whether the source is an approved Kali or vulnerability scanner in the
   lab asset inventory.
4. If the source is not approved and the target is critical, escalate to High or
   Critical depending on the Suricata severity.
5. Preserve the EVE event, related packet metadata, and correlated web logs.
6. Request analyst approval before blocking a public source IP.
7. Tune signatures only after confirming repeated false positives.

MITRE ATT&CK: T1046, T1595.002.
Tags: suricata, eve, nmap, network-scan, correlation.
