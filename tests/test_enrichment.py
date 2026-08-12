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


def test_enrichment_identifies_vmware_network_services():
    agent = EnrichmentAgent(Path("data"))

    enrichment = agent.enrich(
        {
            "src_ip": "192.168.228.254",
            "dst_ip": "192.168.228.128",
        }
    )

    assert enrichment["source_is_infrastructure"] is True
    assert enrichment["source_asset"]["name"] == "vmware-network-service"


def test_enrichment_marks_unspecified_and_broadcast_addresses():
    agent = EnrichmentAgent(Path("data"))

    enrichment = agent.enrich(
        {
            "src_ip": "0.0.0.0",
            "dst_ip": "255.255.255.255",
        }
    )

    assert enrichment["source_ip"]["unspecified"] is True
    assert enrichment["destination_ip"]["broadcast"] is True
