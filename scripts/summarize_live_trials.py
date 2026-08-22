#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable


VALID_OUTCOMES = {"TP", "TN", "FP", "FN"}


def safe_rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def summarize(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    accepted = [record for record in records if record.get("outcome") in VALID_OUTCOMES]
    counts = {name: 0 for name in sorted(VALID_OUTCOMES)}
    latencies: list[float] = []
    for record in accepted:
        counts[record["outcome"]] += 1
        value = record.get("detection_latency_seconds")
        if isinstance(value, (int, float)):
            latencies.append(float(value))

    positive_support = counts["TP"] + counts["FN"]
    negative_support = counts["TN"] + counts["FP"]
    return {
        "trial_count": len(accepted),
        "confusion": {
            "tp": counts["TP"],
            "fn": counts["FN"],
            "fp": counts["FP"],
            "tn": counts["TN"],
        },
        "support": {
            "positive_trials": positive_support,
            "negative_trials": negative_support,
        },
        "tpr": safe_rate(counts["TP"], positive_support),
        "fpr": safe_rate(counts["FP"], negative_support),
        "precision": safe_rate(counts["TP"], counts["TP"] + counts["FP"]),
        "specificity": safe_rate(counts["TN"], negative_support),
        "average_detection_latency_seconds": (
            round(sum(latencies) / len(latencies), 3) if latencies else None
        ),
        "notice": (
            "TPR requires at least one labeled attack trial; FPR requires at "
            "least one labeled benign trial. Missing rates are null, not zero."
        ),
    }


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number} is not a JSON object")
            records.append(value)
    return records


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Summarize measured A11 live demo trials without invented rates."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("demo_results/live_trials.jsonl"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("demo_results/live_summary.json"),
    )
    args = parser.parse_args()

    result = summarize(read_jsonl(args.input))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"Wrote: {args.output}")


if __name__ == "__main__":
    main()
