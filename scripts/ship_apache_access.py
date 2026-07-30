from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def post_event(base_url: str, api_key: str, line: str) -> None:
    payload = json.dumps({"source": "apache", "event": line}).encode("utf-8")
    request = Request(
        f"{base_url.rstrip('/')}/api/v1/ingest",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
        },
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        response.read()


def follow(path: Path, from_end: bool):
    with path.open("r", encoding="utf-8", errors="replace") as file:
        if from_end:
            file.seek(0, os.SEEK_END)
        while True:
            line = file.readline()
            if line:
                yield line.rstrip("\n")
                continue
            time.sleep(0.5)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Tail Apache access.log and send each line to A11 SOC ingest API. "
            "Run this on the Web target during the lab demo."
        )
    )
    parser.add_argument(
        "--log-file",
        default="/var/log/apache2/access.log",
        help="Apache access.log path on the Web target.",
    )
    parser.add_argument(
        "--soc-url",
        default=os.getenv("SOC_URL", "http://192.168.1.10:8000"),
        help="A11 SOC base URL, for example http://192.168.1.10:8000.",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("SOC_API_KEY", "change-me-ingest-key"),
        help="SOC ingest API key.",
    )
    parser.add_argument(
        "--from-beginning",
        action="store_true",
        help="Send existing lines first. By default only new lines are shipped.",
    )
    args = parser.parse_args()

    log_path = Path(args.log_file)
    if not log_path.exists():
        raise SystemExit(f"Log file does not exist: {log_path}")

    print(f"Shipping {log_path} to {args.soc_url.rstrip('/')}/api/v1/ingest")
    for line in follow(log_path, from_end=not args.from_beginning):
        if not line.strip():
            continue
        try:
            post_event(args.soc_url, args.api_key, line)
            print(f"sent: {line[:120]}")
        except (HTTPError, URLError, TimeoutError) as exc:
            print(f"failed: {exc}; line={line[:120]}")
            time.sleep(2)


if __name__ == "__main__":
    main()
