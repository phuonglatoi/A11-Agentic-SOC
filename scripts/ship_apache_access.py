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
    """Follow a log file across truncation and normal logrotate replacement."""
    first_open = True
    while True:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as file:
                if first_open and from_end:
                    file.seek(0, os.SEEK_END)
                first_open = False
                inode = os.fstat(file.fileno()).st_ino
                while True:
                    line = file.readline()
                    if line:
                        yield line.rstrip("\n")
                        continue
                    try:
                        current = path.stat()
                    except FileNotFoundError:
                        break
                    if current.st_ino != inode or current.st_size < file.tell():
                        break
                    time.sleep(0.5)
        except FileNotFoundError:
            time.sleep(1)


def send_with_retry(base_url: str, api_key: str, line: str) -> None:
    delay = 1
    while True:
        try:
            post_event(base_url, api_key, line)
            return
        except (HTTPError, URLError, TimeoutError) as exc:
            print(f"send failed: {exc}; retrying in {delay}s", flush=True)
            time.sleep(delay)
            delay = min(30, delay * 2)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Tail Apache access.log and send each line to A11 SOC ingest API. "
            "Run this on the Web target during the lab demo."
        )
    )
    parser.add_argument(
        "--log-file",
        default=os.getenv("APACHE_LOG_FILE", "/var/log/apache2/access.log"),
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
        send_with_retry(args.soc_url, args.api_key, line)
        print(f"sent: {line[:120]}", flush=True)


if __name__ == "__main__":
    main()
