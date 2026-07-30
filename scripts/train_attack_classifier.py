#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import random
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TOKEN_RE = re.compile(r"[a-z0-9_.:/%-]+", re.IGNORECASE)
LABEL_COLUMNS = (
    "label",
    "Label",
    "class",
    "Class",
    "attack",
    "Attack",
    "attack_type",
    "Attack_type",
    "Attack Type",
    "category",
    "Category",
)

LABEL_METADATA: dict[str, dict[str, Any]] = {
    "benign": {
        "severity": "low",
        "title": "Benign / normal activity",
        "description": "The ML model classified the event as normal activity.",
        "mitre": [],
    },
    "network_scan": {
        "severity": "medium",
        "title": "Network scan / reconnaissance",
        "description": "The ML model detected behavior similar to port scan, OS scan or vulnerability scan telemetry.",
        "mitre": [
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1595.002", "name": "Vulnerability Scanning"},
        ],
    },
    "http_flood_dos": {
        "severity": "high",
        "title": "Possible HTTP flood / DoS traffic",
        "description": "The ML model detected repeated HTTP/DDoS/DoS flood-like telemetry against a web-facing service.",
        "mitre": [
            {"id": "T1498", "name": "Network Denial of Service"},
            {"id": "T1499", "name": "Endpoint Denial of Service"},
        ],
    },
    "sql_injection_probe": {
        "severity": "high",
        "title": "SQL injection probe",
        "description": "The ML model detected SQL injection indicators such as sqlmap, quotes, UNION SELECT or time-based payloads.",
        "mitre": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
    },
    "web_sensitive_path": {
        "severity": "medium",
        "title": "Sensitive web path discovery",
        "description": "The ML model detected probing for sensitive paths such as .env, phpMyAdmin or admin panels.",
        "mitre": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
    },
    "brute_force": {
        "severity": "high",
        "title": "Brute force authentication activity",
        "description": "The ML model detected repeated failed authentication or brute-force-like telemetry.",
        "mitre": [{"id": "T1110", "name": "Brute Force"}],
    },
    "windows_log_cleared": {
        "severity": "critical",
        "title": "Windows audit log cleared",
        "description": "The ML model detected Windows audit log clearing behavior.",
        "mitre": [{"id": "T1070.001", "name": "Clear Windows Event Logs"}],
    },
    "powershell_execution": {
        "severity": "high",
        "title": "Suspicious PowerShell execution",
        "description": "The ML model detected encoded, download-capable or obfuscated PowerShell behavior.",
        "mitre": [{"id": "T1059.001", "name": "PowerShell"}],
    },
    "mitm_spoofing": {
        "severity": "high",
        "title": "MITM / spoofing activity",
        "description": "The ML model detected ARP spoofing, impersonation or IP spoofing indicators.",
        "mitre": [{"id": "T1557", "name": "Adversary-in-the-Middle"}],
    },
    "mirai_malware": {
        "severity": "high",
        "title": "Mirai-like IoT malware activity",
        "description": "The ML model detected IoT botnet or Mirai-like flood/scanning telemetry.",
        "mitre": [{"id": "T1498", "name": "Network Denial of Service"}],
    },
}


def normalize_label(value: Any) -> str:
    text = str(value or "benign").strip().lower()
    collapsed = re.sub(r"[^a-z0-9]+", " ", text).strip()
    if not collapsed or collapsed in {"benign", "normal", "background"}:
        return "benign"
    if "mirai" in collapsed:
        return "mirai_malware"
    if "brute" in collapsed or "ssh brute" in collapsed or "telnet brute" in collapsed:
        return "brute_force"
    if "audit log" in collapsed or "1102" in collapsed or "log cleared" in collapsed:
        return "windows_log_cleared"
    if "powershell" in collapsed:
        return "powershell_execution"
    if "sql" in collapsed:
        return "sql_injection_probe"
    if "xss" in collapsed or "cross site" in collapsed or "command injection" in collapsed or "backdoor upload" in collapsed:
        return "web_sensitive_path"
    if "arp spoof" in collapsed or "ip spoof" in collapsed or "impersonation" in collapsed or "mitm" in collapsed:
        return "mitm_spoofing"
    if "ddos" in collapsed or "dos" in collapsed or "flood" in collapsed or "slowloris" in collapsed:
        return "http_flood_dos"
    if "scan" in collapsed or "recon" in collapsed or "ping sweep" in collapsed or "host discovery" in collapsed:
        return "network_scan"
    return re.sub(r"[^a-z0-9]+", "_", collapsed).strip("_") or "benign"


def flatten(value: Any, prefix: str = "") -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        output: list[str] = []
        for key, nested in value.items():
            if key in {"label", "severity", "mitre"}:
                continue
            output.extend(flatten(nested, f"{prefix}{key}."))
        return output
    if isinstance(value, list):
        return [item for nested in value[:50] for item in flatten(nested, prefix)]
    return [f"{prefix}{value}"]


def tokenize(text: str) -> list[str]:
    tokens = [token.lower() for token in TOKEN_RE.findall(text)]
    bigrams = [f"{left}_{right}" for left, right in zip(tokens, tokens[1:])]
    return tokens + bigrams


def read_jsonl(path: Path) -> list[tuple[str, str]]:
    examples: list[tuple[str, str]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            record = json.loads(line)
            label = normalize_label(record.get("label"))
            text = " ".join(flatten(record))
            if text:
                examples.append((label, text))
            else:
                raise ValueError(f"{path}:{line_number} has no trainable fields")
    return examples


def read_csv(path: Path, sample_per_class: int | None = None) -> list[tuple[str, str]]:
    buckets: dict[str, list[tuple[str, str]]] = defaultdict(list)
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return []
        label_column = next(
            (column for column in LABEL_COLUMNS if column in reader.fieldnames),
            reader.fieldnames[-1],
        )
        for row in reader:
            label = normalize_label(row.get(label_column))
            text = " ".join(
                f"{key}={value}"
                for key, value in row.items()
                if key != label_column and value not in {None, ""}
            )
            if text:
                buckets[label].append((label, text))

    examples: list[tuple[str, str]] = []
    rng = random.Random(11)
    for label, rows in buckets.items():
        if sample_per_class and len(rows) > sample_per_class:
            rows = rng.sample(rows, sample_per_class)
        examples.extend(rows)
    return examples


def train(examples: list[tuple[str, str]]) -> dict[str, Any]:
    if not examples:
        raise ValueError("No training examples were found.")

    class_doc_counts: Counter[str] = Counter()
    class_total_tokens: Counter[str] = Counter()
    class_token_counts: dict[str, Counter[str]] = defaultdict(Counter)
    vocabulary: set[str] = set()

    for label, text in examples:
        tokens = tokenize(text)
        if not tokens:
            continue
        class_doc_counts[label] += 1
        token_counts = Counter(tokens)
        class_token_counts[label].update(token_counts)
        class_total_tokens[label] += sum(token_counts.values())
        vocabulary.update(token_counts)

    labels = sorted(class_doc_counts)
    return {
        "model_type": "multinomial_naive_bayes",
        "version": datetime.now(timezone.utc).strftime("a11-nb-%Y%m%d%H%M%S"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "alpha": 1.0,
        "labels": labels,
        "label_metadata": {
            label: LABEL_METADATA.get(label, {"severity": "medium", "mitre": []})
            for label in labels
        },
        "total_docs": sum(class_doc_counts.values()),
        "class_doc_counts": dict(class_doc_counts),
        "class_total_tokens": dict(class_total_tokens),
        "class_token_counts": {
            label: dict(counter) for label, counter in class_token_counts.items()
        },
        "vocabulary": sorted(vocabulary),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train the local A11 SOC attack classifier."
    )
    parser.add_argument(
        "--input",
        action="append",
        type=Path,
        default=[],
        help="JSONL labeled event file. Can be passed multiple times.",
    )
    parser.add_argument(
        "--csv",
        action="append",
        type=Path,
        default=[],
        help="External CIC/DataSense CSV file with a label column.",
    )
    parser.add_argument(
        "--sample-per-class",
        type=int,
        default=None,
        help="Optional max rows per class when importing large CSV datasets.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("models/attack_classifier.json"),
        help="Output JSON model path.",
    )
    args = parser.parse_args()

    examples: list[tuple[str, str]] = []
    for path in args.input:
        examples.extend(read_jsonl(path))
    for path in args.csv:
        examples.extend(read_csv(path, sample_per_class=args.sample_per_class))

    model = train(examples)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        json.dump(model, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    print(
        f"Wrote {args.output} with {model['total_docs']} examples "
        f"and {len(model['labels'])} labels."
    )


if __name__ == "__main__":
    main()
