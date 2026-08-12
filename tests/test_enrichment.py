from pathlib import Path

from app.agents.enrichment import EnrichmentAgent


def test_enrichment_identifies_opnsense_wan_as_infrastructure_source():
    agent = EnrichmentAgent(Path("data"))

    enrichment = agent.enrich(
        {
            "src_ip": "192.168.228.142",
            "dst_ip": "192.168.1.10",
            "host": "opnsense",
        }
    )

    assert enrichment["source_is_infrastructure"] is True
    assert enrichment["source_asset"]["name"] == "opnsense-gateway"
    assert enrichment["destination_asset"]["name"] == "ubuntu-web"


def test_enrichment_identifies_kali_as_controlled_lab_source():
    agent = EnrichmentAgent(Path("data"))

    enrichment = agent.enrich(
        {
            "src_ip": "192.168.228.128",
            "dst_ip": "192.168.228.142",
            "host": "opnsense",
        }
    )

    assert enrichment["lab_source"] is True
    assert enrichment["source_is_infrastructure"] is False
