import json
from pathlib import Path


WORKFLOW_PATH = Path(__file__).resolve().parents[1] / "n8n" / "workflows" / "a11_soc_local_automation.json"


def load_workflow():
    return json.loads(WORKFLOW_PATH.read_text(encoding="utf-8"))


def nodes_by_name(workflow):
    return {node["name"]: node for node in workflow["nodes"]}


def connected_targets(workflow, source_name):
    outputs = workflow["connections"][source_name]["main"][0]
    return {edge["node"] for edge in outputs}


def test_n8n_webhooks_use_immediate_production_response():
    workflow = load_workflow()
    nodes = nodes_by_name(workflow)

    assert nodes["SOC Alert Webhook"]["parameters"]["responseMode"] == "onReceived"
    assert nodes["SOC Response Webhook"]["parameters"]["responseMode"] == "onReceived"
    assert nodes["SOC Alert Webhook"]["parameters"]["path"] == "a11-soc-alert"
    assert nodes["SOC Response Webhook"]["parameters"]["path"] == "a11-soc-response"


def test_n8n_alert_branch_writes_audit_and_sends_email():
    workflow = load_workflow()
    targets = connected_targets(workflow, "Build Alert Automation Payload")

    assert "Write Alert Audit to A11 SOC" in targets
    assert "Send Alert Email to Mailpit" in targets
    assert "Respond Alert Webhook" not in nodes_by_name(workflow)


def test_n8n_response_branch_writes_audit_and_sends_email():
    workflow = load_workflow()
    targets = connected_targets(workflow, "Build Response Action Payload")

    assert "Write Response Audit to A11 SOC" in targets
    assert "Send Response Email to Mailpit" in targets
    assert "Respond Response Webhook" not in nodes_by_name(workflow)


def test_n8n_side_effect_nodes_do_not_block_the_webhook():
    workflow = load_workflow()
    nodes = nodes_by_name(workflow)

    side_effect_nodes = [
        "Write Alert Audit to A11 SOC",
        "Send Alert Email to Mailpit",
        "Write Response Audit to A11 SOC",
        "Send Response Email to Mailpit",
    ]
    for name in side_effect_nodes:
        assert nodes[name]["continueOnFail"] is True
