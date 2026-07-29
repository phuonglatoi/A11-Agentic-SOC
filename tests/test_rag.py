from pathlib import Path

from app.agents.rag import LocalKnowledgeBase


def test_local_knowledge_base_returns_relevant_playbook():
    kb = LocalKnowledgeBase(Path("knowledge"))
    results = kb.search("web attack .env HTTP source IP block OPNsense")
    assert results
    assert results[0]["name"] == "web_attack_response"
    assert results[0]["title"]
    assert "excerpt" in results[0]
