# Playbook: n8n SOC automation handoff

Trigger: `notify_soc` action, approved `block_ip`, approved `isolate_host`, or a
generic response action sent to the local n8n workflow.

1. Verify that the n8n workflow `A11 SOC Local Automation` is imported and
   active.
2. Confirm that `NOTIFICATION_WEBHOOK_URL` points to
   `http://n8n:5678/webhook/a11-soc-alert`.
3. Confirm that `RESPONSE_WEBHOOK_URL` points to
   `http://n8n:5678/webhook/a11-soc-response` when `RESPONSE_MODE=webhook`.
4. Ensure `A11_SOC_API_URL=http://api:8000` and `A11_SOC_ADMIN_TOKEN` are set in
   the n8n container environment.
5. Confirm that every n8n execution writes an audit callback to
   `/api/v1/automation/audit`.
6. Treat n8n as orchestration and evidence routing. Do not let it bypass the SOC
   approval gate for blocking, isolation, or account actions.
7. If a workflow execution fails, keep the original alert/action in the SOC
   database and retry after fixing the workflow.

Tags: n8n, webhook, automation, audit, approval.
