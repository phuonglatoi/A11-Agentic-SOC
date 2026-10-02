#!/usr/bin/env python3
"""Replay a small, label-filtered CICIDS2017 flow sample into a local A11 SOC."""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.train_attack_classifier import LABEL_COLUMNS, normalize_label


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path, help="One CICIDS2017 labeled CSV file")
    parser.add_argument("--label", help="Only replay this canonical class, e.g. http_flood_dos")
    parser.add_argument("--rows", type=int, default=20, help="Maximum events to send (default: 20)")
    parser.add_argument("--interval-ms", type=int, default=100, help="Delay between POSTs (default: 100 ms)")
    parser.add_argument("--url", default="http://127.0.0.1:8000/api/v1/ingest")
    parser.add_argument("--api-key", default=os.getenv("SOC_API_KEY", ""))
    args = parser.parse_args()
    if args.rows < 1 or args.interval_ms < 0:
        parser.error("--rows must be >= 1 and --interval-ms must be >= 0")
    if not args.api_key:
        parser.error("Provide --api-key or set SOC_API_KEY in the environment")
    if not args.csv.is_file():
        parser.error(f"CSV not found: {args.csv}")

    sent = 0
    labels_seen: dict[str, int] = {}
    with args.csv.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            parser.error("CSV has no header row")
        reader.fieldnames = [str(name or "").strip() for name in reader.fieldnames]
        label_column = next(
            (name for name in LABEL_COLUMNS if name.strip() in reader.fieldnames),
            reader.fieldnames[-1],
        )
        for row in reader:
            row = {str(key or "").strip(): value for key, value in row.items()}
            label = normalize_label(row.pop(label_column, None))
            labels_seen[label] = labels_seen.get(label, 0) + 1
            if args.label and label != normalize_label(args.label):
                continue
            # Ground-truth Label is intentionally removed before ingestion to prevent leakage.
            payload = json.dumps(
                {"source": "cicids_flow", "event": row},
                ensure_ascii=False,
            ).encode("utf-8")
            request = Request(
                args.url,
                data=payload,
                headers={"Content-Type": "application/json", "X-API-Key": args.api_key},
                method="POST",
            )
            try:
                with urlopen(request, timeout=10) as response:
                    result = json.loads(response.read().decode("utf-8"))
            except (HTTPError, URLError, TimeoutError) as exc:
                raise SystemExit(f"Ingest failed after {sent} rows: {exc}") from exc
            sent += 1
            print(f"{sent}/{args.rows}: dataset_label={label}, response={result}")
            if sent >= args.rows:
                break
            if args.interval_ms:
                time.sleep(args.interval_ms / 1000)

    if sent == 0:
        raise SystemExit(f"No rows matched --label={args.label!r}; labels scanned: {labels_seen}")
    print(f"Finished: sent {sent} flow events from {args.csv}; ground-truth labels were not ingested.")


if __name__ == "__main__":
    main()
