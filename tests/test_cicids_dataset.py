from app.agents.flow_features import canonical_flow_features, holdout_partition
from app.agents.ml_detector import MLDetectionAgent
from app.agents.triage import triage_event
from app.parsers import normalize_event
from scripts.train_attack_classifier import normalize_label, read_csv


def test_cicids2017_labels_map_to_supported_attack_families():
    assert normalize_label("BENIGN") == "benign"
    assert normalize_label("PortScan") == "network_scan"
    assert normalize_label("DDoS") == "http_flood_dos"
    assert normalize_label("DoS Hulk") == "http_flood_dos"
    assert normalize_label("Web Attack - Brute Force") == "brute_force"
    assert normalize_label("Web Attack - Sql Injection") == "sql_injection_probe"
    assert normalize_label("Web Attack - XSS") == "web_attack"
    assert normalize_label("Infilteration") == "infiltration"
    assert normalize_label("Bot") == "botnet_activity"
    assert normalize_label("Heartbleed") == "web_attack"


def test_flow_features_bucket_numeric_values_and_drop_identifiers_and_labels():
    features = canonical_flow_features(
        {
            " Flow Duration": "12000",
            " Destination Port": "443",
            " Source IP": "192.0.2.10",
            "Flow ID": "192.0.2.10-198.51.100.20-443",
            "Label": "DDoS",
        }
    )

    assert features["flow_duration"] == "positive_2pow_13"
    assert features["destination_port"] == "443"
    assert "source_ip" not in features
    assert "flow_id" not in features
    assert "label" not in features


def test_cicids_flow_parser_preserves_raw_row_but_excludes_label_from_ml_features():
    row = {
        "Flow Duration": "12000",
        "Destination Port": "443",
        "Source IP": "192.0.2.10",
        "Label": "DDoS",
    }

    event = normalize_event(row, source_hint="cicids_flow")

    assert event["event_type"] == "network.flow"
    assert event["raw"]["Label"] == "DDoS"
    assert "label" not in event["flow_features"]
    assert event["flow_features"]["flow_duration"] == "positive_2pow_13"


def test_training_csv_reader_uses_bounded_rows_per_class(tmp_path):
    source = tmp_path / "tiny_cicids.csv"
    source.write_text(
        " Flow Duration , Destination Port , Label\n"
        "100,80,BENIGN\n"
        "200,80,BENIGN\n"
        "300,443,DDoS\n",
        encoding="utf-8",
    )

    rows = read_csv(source, sample_per_class=1)

    assert len(rows) == 2
    assert {label for label, _ in rows} == {"benign", "http_flood_dos"}


def test_exact_duplicate_rows_never_cross_deterministic_holdout():
    row = {"Flow Duration": "12000", "Destination Port": "443", "Label": "DDoS"}

    assert holdout_partition(row, 20) == holdout_partition(dict(row), 20)
    assert holdout_partition(row, 20) in {"train", "test"}


def test_trained_flow_model_is_selected_for_cicids_source():
    model = MLDetectionAgent("models/attack_classifier.json")
    event = normalize_event(
        {"Flow Duration": "12000", "Destination Port": "443", "Protocol": "6"},
        source_hint="cicids_flow",
    )

    prediction = model.detect(event)

    assert prediction["enabled"] is True
    assert prediction["status"] == "ok"
    assert prediction["attack_type"] in model.model["flow_model"]["labels"]
    assert "severity" not in prediction


def test_ml_does_not_set_flow_severity_but_deterministic_volume_rule_can():
    event = normalize_event(
        {"Source IP": "192.0.2.20", "Destination IP": "198.51.100.10", "Destination Port": "80"},
        source_hint="cicids_flow",
    )
    event["ml_prediction"] = {
        "enabled": True,
        "status": "ok",
        "attack_type": "http_flood_dos",
        "confidence": 0.99,
        "severity": "critical",
    }

    assert triage_event(event, event_count=1)["severity"] == "low"
    aggregated = triage_event(event, event_count=100)
    assert aggregated["severity"] == "high"
    assert any(item["id"] == "T1498" for item in aggregated["mitre"])
