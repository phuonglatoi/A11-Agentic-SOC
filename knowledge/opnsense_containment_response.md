# Playbook: OPNsense containment

Trigger: approved `block_ip` response action for a public hostile source IP.

1. Confirm the source IP is public and is not a private, loopback, multicast,
   unspecified, or lab management address.
2. Confirm that the alert evidence includes the raw event, normalized event,
   triage reasons, and analyst approval.
3. Add the source IP only to the configured OPNsense alias, normally
   `SOC_BLOCKLIST`.
4. Confirm that a firewall rule already uses the alias on the correct interface.
5. Recheck traffic after the block to verify that the rule is effective.
6. Record the action result in the A11 SOC audit log.
7. Remove the IP from the block list only after analyst review or incident
   closure.

MITRE ATT&CK: T1190, T1046, T1595.002.
Tags: opnsense, firewall, block_ip, containment, approval.
