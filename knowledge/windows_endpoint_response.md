# Playbook: Suspicious Windows endpoint activity

High-priority triggers include audit log clearing (1102), unexpected user
creation (4720), and suspicious command interpreters in process creation (4688).

1. Record host, user, process path, command line, parent process, and timestamp.
2. Search for related authentication and process events on the same endpoint.
3. For audit clearing, treat the event as Critical unless maintenance is
   verified.
4. Propose endpoint isolation, but require analyst approval before execution.
5. Collect volatile evidence and preserve endpoint telemetry.
6. Reset affected credentials and rebuild the endpoint if compromise is
   confirmed.

MITRE ATT&CK: T1070.001, T1059.001, T1136.001.
