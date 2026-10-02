from __future__ import annotations

import math
import re
import hashlib
from typing import Any


def _key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


_EXCLUDED_KEYS = {
    "flow_id",
    "source_ip",
    "src_ip",
    "destination_ip",
    "dst_ip",
    "timestamp",
    "label",
    "class",
    "attack",
    "attack_type",
    "category",
}
_EXACT_NUMERIC_KEYS = {"source_port", "src_port", "destination_port", "dst_port", "protocol"}


def _numeric_feature(key: str, value: float) -> str:
    if not math.isfinite(value):
        return "non_finite"
    if key in _EXACT_NUMERIC_KEYS:
        return str(int(value)) if value.is_integer() else str(value)
    if value == 0:
        return "zero"
    sign = "negative" if value < 0 else "positive"
    magnitude = int(math.floor(math.log2(abs(value))))
    return f"{sign}_2pow_{magnitude}"


def canonical_flow_features(row: dict[str, Any]) -> dict[str, str]:
    """Create bounded-cardinality CICFlowMeter features; never include labels or IDs."""
    features: dict[str, str] = {}
    for original_key, raw_value in row.items():
        key = _key(original_key)
        if not key or key in _EXCLUDED_KEYS or raw_value is None:
            continue
        value = str(raw_value).strip()
        if not value:
            continue
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            features[key] = value.lower()[:128]
        else:
            features[key] = _numeric_feature(key, numeric)
    return features


def holdout_partition(row: dict[str, Any], holdout_percent: int = 20) -> str:
    """Assign identical raw CSV rows to the same deterministic train/test partition."""
    encoded = "\x1f".join(f"{key}={value}" for key, value in row.items())
    bucket = int.from_bytes(
        hashlib.blake2s(encoded.encode("utf-8"), digest_size=4).digest(), "big"
    ) % 100
    return "test" if bucket < holdout_percent else "train"
