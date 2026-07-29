# SOC automation operating policy

The system may automatically normalize, enrich, correlate, score, notify, and
create incidents. It may not perform a disruptive action without a recorded
human decision.

Actions that always require approval:

- adding an address to a firewall block list;
- isolating an endpoint;
- disabling or resetting an account;
- deleting data, killing a process, or changing production configuration.

Every decision and execution result must be written to the audit log. Response
integrations run in dry-run mode until credentials and a non-dry-run mode are
explicitly configured. A rejected action must never be executed.
