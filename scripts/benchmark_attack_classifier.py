#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from scripts.train_attack_classifier import LABEL_COLUMNS, normalize_label
except ModuleNotFoundError:
    # Keep direct execution (`python3 scripts/benchmark_attack_classifier.py`)
    # compatible with importing this module from pytest.
    from train_attack_classifier import LABEL_COLUMNS, normalize_label

from app.agents.ml_detector import MLDetectionAgent


def read_jsonl(path: Path) -> list[tuple[str, dict[str, Any]]]:
    examples: list[tuple[str, dict[str, Any]]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            record = json.loads(line)
            expected = normalize_label(record.pop("label", None))
            record.pop("severity", None)
            if not record:
                raise ValueError(f"{path}:{line_number} has no event fields")
            examples.append((expected, record))
    return examples


def read_csv(path: Path) -> list[tuple[str, dict[str, Any]]]:
    examples: list[tuple[str, dict[str, Any]]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return examples
        label_column = next(
            (column for column in LABEL_COLUMNS if column in reader.fieldnames),
            reader.fieldnames[-1],
        )
        for row in reader:
            expected = normalize_label(row.pop(label_column, None))
            event = {key: value for key, value in row.items() if value not in {None, ""}}
            if event:
                examples.append((expected, event))
    return examples


def safe_div(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def stratified_sample(
    examples: Iterable[tuple[str, dict[str, Any]]],
    sample_size: int,
    seed: int,
) -> tuple[list[tuple[str, dict[str, Any]]], dict[str, Any]]:
    """Select exactly ``sample_size`` rows with a balanced label allocation.

    Smaller classes are exhausted first and the remaining quota is redistributed
    over classes that still contain rows. No row is duplicated.
    """

    rows = list(examples)
    if sample_size <= 0:
        raise ValueError("sample_size must be greater than zero")
    if sample_size > len(rows):
        raise ValueError(
            f"Requested {sample_size} benchmark events, but only {len(rows)} "
            "independent labeled events are available. Rows will not be duplicated."
        )

    buckets: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for example in rows:
        buckets[example[0]].append(example)

    rng = random.Random(seed)
    for bucket in buckets.values():
        rng.shuffle(bucket)

    allocation = {label: 0 for label in sorted(buckets)}
    selected_count = 0
    while selected_count < sample_size:
        progressed = False
        for label in sorted(buckets):
            if selected_count >= sample_size:
                break
            if allocation[label] >= len(buckets[label]):
                continue
            allocation[label] += 1
            selected_count += 1
            progressed = True
        if not progressed:
            raise RuntimeError("Unable to allocate the requested benchmark sample")

    selected = [
        example
        for label in sorted(buckets)
        for example in buckets[label][: allocation[label]]
    ]
    rng.shuffle(selected)
    return selected, {
        "method": "stratified_without_replacement",
        "requested_samples": sample_size,
        "available_samples": len(rows),
        "selected_samples": len(selected),
        "seed": seed,
        "available_by_label": {
            label: len(bucket) for label, bucket in sorted(buckets.items())
        },
        "selected_by_label": allocation,
    }


def binary_detection_metrics(
    confusion: dict[str, Counter[str]],
    labels: Iterable[str],
    negative_label: str = "benign",
) -> dict[str, Any]:
    """Collapse multiclass results into attack-vs-benign detection metrics.

    TPR/FPR are only meaningful when their corresponding denominator exists.
    Returning ``None`` instead of 0 avoids presenting a fabricated perfect or
    failed rate when the benchmark contains no positive or negative samples.
    """

    expected_labels = list(labels)
    true_positive = false_negative = false_positive = true_negative = 0
    for expected in expected_labels:
        for predicted, count in confusion[expected].items():
            expected_positive = expected != negative_label
            predicted_positive = predicted != negative_label
            if expected_positive and predicted_positive:
                true_positive += count
            elif expected_positive and not predicted_positive:
                false_negative += count
            elif not expected_positive and predicted_positive:
                false_positive += count
            else:
                true_negative += count

    positive_support = true_positive + false_negative
    negative_support = true_negative + false_positive

    def optional_rate(numerator: int, denominator: int) -> float | None:
        return round(numerator / denominator, 4) if denominator else None

    return {
        "positive_class": "attack (every label except benign)",
        "negative_class": negative_label,
        "confusion": {
            "tp": true_positive,
            "fn": false_negative,
            "fp": false_positive,
            "tn": true_negative,
        },
        "support": {
            "positive_samples": positive_support,
            "negative_samples": negative_support,
        },
        "tpr": optional_rate(true_positive, positive_support),
        "recall": optional_rate(true_positive, positive_support),
        "sensitivity": optional_rate(true_positive, positive_support),
        "fpr": optional_rate(false_positive, negative_support),
        "tnr": optional_rate(true_negative, negative_support),
        "specificity": optional_rate(true_negative, negative_support),
        "fnr": optional_rate(false_negative, positive_support),
        "precision": optional_rate(true_positive, true_positive + false_positive),
    }


def evaluate(
    agent: MLDetectionAgent,
    examples: Iterable[tuple[str, dict[str, Any]]],
) -> dict[str, Any]:
    rows = list(examples)
    labels = sorted({expected for expected, _ in rows})
    confusion: dict[str, Counter[str]] = defaultdict(Counter)
    failures: list[dict[str, Any]] = []
    confidence_sum = 0.0

    for index, (expected, event) in enumerate(rows, 1):
        event_count = int(event.pop("event_count", 1) or 1)
        prediction = agent.detect(event, event_count=event_count)
        predicted = str(prediction.get("attack_type") or "unclassified")
        confidence = float(prediction.get("confidence") or 0.0)
        confusion[expected][predicted] += 1
        confidence_sum += confidence
        if predicted != expected:
            failures.append(
                {
                    "row": index,
                    "expected": expected,
                    "predicted": predicted,
                    "confidence": round(confidence, 4),
                    "event": event,
                }
            )

    predicted_labels = sorted(
        {predicted for counts in confusion.values() for predicted in counts}
    )
    all_labels = sorted(set(labels) | set(predicted_labels))
    per_class: dict[str, dict[str, Any]] = {}
    for label in labels:
        true_positive = confusion[label][label]
        false_negative = sum(confusion[label].values()) - true_positive
        false_positive = sum(
            confusion[other][label] for other in labels if other != label
        )
        precision = safe_div(true_positive, true_positive + false_positive)
        recall = safe_div(true_positive, true_positive + false_negative)
        f1 = safe_div(2 * precision * recall, precision + recall)
        per_class[label] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": sum(confusion[label].values()),
        }

    total = len(rows)
    correct = sum(confusion[label][label] for label in labels)
    macro_precision = safe_div(
        sum(item["precision"] for item in per_class.values()), len(per_class)
    )
    macro_recall = safe_div(
        sum(item["recall"] for item in per_class.values()), len(per_class)
    )
    macro_f1 = safe_div(sum(item["f1"] for item in per_class.values()), len(per_class))
    return {
        "summary": {
            "samples": total,
            "correct": correct,
            "accuracy": round(safe_div(correct, total), 4),
            "macro_precision": round(macro_precision, 4),
            "macro_recall": round(macro_recall, 4),
            "macro_f1": round(macro_f1, 4),
            "average_confidence": round(safe_div(confidence_sum, total), 4),
        },
        "per_class": per_class,
        "confusion_matrix": {
            "labels": all_labels,
            "rows_are_expected_columns_are_predicted": [
                [confusion[expected][predicted] for predicted in all_labels]
                for expected in all_labels
            ],
        },
        "binary_detection": binary_detection_metrics(confusion, labels),
        "failures": failures,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark the local A11 SOC attack classifier."
    )
    parser.add_argument(
        "--input",
        action="append",
        type=Path,
        default=[],
        help="Held-out JSONL file containing a label field. Can be repeated.",
    )
    parser.add_argument(
        "--csv",
        action="append",
        type=Path,
        default=[],
        help="Held-out CIC/DataSense CSV. Do not reuse training rows.",
    )
    parser.add_argument(
        "--model",
        type=Path,
        default=Path("models/attack_classifier.json"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmark_results.json"),
    )
    parser.add_argument("--min-accuracy", type=float, default=0.0)
    parser.add_argument("--min-macro-f1", type=float, default=0.0)
    parser.add_argument(
        "--min-tpr",
        type=float,
        default=None,
        help="Optional minimum attack-vs-benign true-positive rate.",
    )
    parser.add_argument(
        "--max-fpr",
        type=float,
        default=None,
        help="Optional maximum attack-vs-benign false-positive rate.",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=None,
        help=(
            "Evaluate exactly this many rows using deterministic stratified "
            "sampling without replacement. Fails if the inputs contain fewer rows."
        ),
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=11,
        help="Random seed recorded with stratified benchmark sampling.",
    )
    args = parser.parse_args()

    if not args.input and not args.csv:
        args.input = [Path("datasets/a11_benchmark_labeled_events.jsonl")]

    agent = MLDetectionAgent(args.model)
    if not agent.stats().get("enabled"):
        raise SystemExit(f"Model is not available: {args.model}")

    examples: list[tuple[str, dict[str, Any]]] = []
    for path in args.input:
        examples.extend(read_jsonl(path))
    for path in args.csv:
        examples.extend(read_csv(path))
    if not examples:
        raise SystemExit("No benchmark examples were found.")

    if args.sample_size is not None:
        try:
            examples, sampling = stratified_sample(
                examples, args.sample_size, args.seed
            )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
    else:
        distribution = Counter(label for label, _ in examples)
        sampling = {
            "method": "all_input_rows",
            "requested_samples": None,
            "available_samples": len(examples),
            "selected_samples": len(examples),
            "seed": None,
            "available_by_label": dict(sorted(distribution.items())),
            "selected_by_label": dict(sorted(distribution.items())),
        }

    results = evaluate(agent, examples)
    results["generated_at"] = datetime.now(timezone.utc).isoformat()
    results["model"] = agent.stats()
    results["datasets"] = [str(path) for path in [*args.input, *args.csv]]
    results["sampling"] = sampling
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(results, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    summary = results["summary"]
    print(f"Samples:          {summary['samples']}")
    print(f"Sampling:         {sampling['method']}")
    if sampling["seed"] is not None:
        print(f"Sampling seed:    {sampling['seed']}")
    print(f"Accuracy:         {summary['accuracy']:.4f}")
    print(f"Macro precision:  {summary['macro_precision']:.4f}")
    print(f"Macro recall:     {summary['macro_recall']:.4f}")
    print(f"Macro F1:         {summary['macro_f1']:.4f}")
    binary = results["binary_detection"]
    confusion = binary["confusion"]
    tpr = "N/A" if binary["tpr"] is None else f"{binary['tpr']:.4f}"
    fpr = "N/A" if binary["fpr"] is None else f"{binary['fpr']:.4f}"
    print(f"Binary TP/FN:     {confusion['tp']}/{confusion['fn']}")
    print(f"Binary FP/TN:     {confusion['fp']}/{confusion['tn']}")
    print(f"TPR (attack):     {tpr}")
    print(f"FPR (benign):     {fpr}")
    print(f"Failures:         {len(results['failures'])}")
    print(f"Wrote:            {args.output}")

    if summary["accuracy"] < args.min_accuracy:
        raise SystemExit(2)
    if summary["macro_f1"] < args.min_macro_f1:
        raise SystemExit(3)
    if args.min_tpr is not None:
        if binary["tpr"] is None or binary["tpr"] < args.min_tpr:
            raise SystemExit(4)
    if args.max_fpr is not None:
        if binary["fpr"] is None or binary["fpr"] > args.max_fpr:
            raise SystemExit(5)


if __name__ == "__main__":
    main()
