from collections import Counter, defaultdict

import pytest

from scripts.benchmark_attack_classifier import binary_detection_metrics, stratified_sample
from scripts.summarize_live_trials import summarize


def test_binary_detection_metrics_are_derived_from_confusion_counts():
    confusion = defaultdict(Counter)
    confusion["benign"].update({"benign": 8, "network_scan": 2})
    confusion["network_scan"].update({"network_scan": 5, "benign": 1})
    confusion["sql_injection_probe"].update(
        {"sql_injection_probe": 2, "network_scan": 0, "benign": 2}
    )

    result = binary_detection_metrics(
        confusion, ["benign", "network_scan", "sql_injection_probe"]
    )

    assert result["confusion"] == {"tp": 7, "fn": 3, "fp": 2, "tn": 8}
    assert result["tpr"] == 0.7
    assert result["fpr"] == 0.2
    assert result["specificity"] == 0.8


def test_live_summary_does_not_invent_rate_without_required_support():
    result = summarize(
        [
            {"outcome": "TP", "detection_latency_seconds": 1.5},
            {"outcome": "NO_EVIDENCE"},
        ]
    )

    assert result["trial_count"] == 1
    assert result["tpr"] == 1.0
    assert result["fpr"] is None
    assert result["support"]["negative_trials"] == 0


def test_live_summary_uses_only_measured_confusion_outcomes():
    result = summarize(
        [
            {"outcome": "TP", "detection_latency_seconds": 2.0},
            {"outcome": "FN", "detection_latency_seconds": 4.0},
            {"outcome": "TN", "detection_latency_seconds": 1.0},
            {"outcome": "FP", "detection_latency_seconds": 3.0},
        ]
    )

    assert result["tpr"] == 0.5
    assert result["fpr"] == 0.5
    assert result["average_detection_latency_seconds"] == 2.5


def test_stratified_sample_selects_exact_rows_without_duplication():
    rows = [
        (label, {"row_id": f"{label}-{index}"})
        for label, count in (("benign", 4), ("network_scan", 8), ("http_flood_dos", 8))
        for index in range(count)
    ]

    selected, metadata = stratified_sample(rows, sample_size=12, seed=17)

    assert len(selected) == 12
    assert len({event["row_id"] for _, event in selected}) == 12
    assert metadata["selected_by_label"] == {
        "benign": 4,
        "http_flood_dos": 4,
        "network_scan": 4,
    }
    assert metadata["seed"] == 17


def test_stratified_sample_refuses_to_duplicate_rows():
    rows = [("benign", {"row_id": index}) for index in range(3)]

    with pytest.raises(ValueError, match="only 3 independent labeled events"):
        stratified_sample(rows, sample_size=500, seed=11)
