from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any


TOKEN_RE = re.compile(r"[a-z0-9_.:/%-]+", re.IGNORECASE)


def _flatten(value: Any, prefix: str = "") -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        output: list[str] = []
        for key, nested in value.items():
            if key in {"raw", "filterlog_fields", "flow_features"}:
                continue
            output.extend(_flatten(nested, f"{prefix}{key}."))
        return output
    if isinstance(value, list):
        return [item for nested in value[:20] for item in _flatten(nested, prefix)]
    return [f"{prefix}{value}"]


def event_to_text(event: dict[str, Any], event_count: int = 1) -> str:
    parts = _flatten(event)
    raw = event.get("raw")
    is_flow_dataset = str(event.get("source") or "").lower() in {
        "cicids_flow", "cicids2017"
    }
    if is_flow_dataset and isinstance(event.get("flow_features"), dict):
        parts.extend(
            f"{key}={value}" for key, value in event["flow_features"].items()
        )
    if isinstance(raw, dict) and not is_flow_dataset:
        parts.extend(_flatten(raw))
    elif raw and not is_flow_dataset:
        parts.append(str(raw))
    parts.append(f"event_count:{event_count}")
    if event_count >= 50:
        parts.append("event_volume:high")
    elif event_count >= 20:
        parts.append("event_volume:medium")
    event_type = str(event.get("event_type") or "")
    dst_port = event.get("dst_port")
    protocol = str(event.get("protocol") or "").lower()
    action = str(event.get("firewall_action") or "").lower()
    direction = str(event.get("firewall_direction") or "").lower()
    web_ports = {80, 443, 8000, 8080, 8443}
    if (
        event_type.startswith("opnsense.firewall_")
        and event_count >= 50
        and protocol == "tcp"
        and dst_port in web_ports
        and action in {"pass", "block", "reject"}
        and direction in {"in", "inbound"}
    ):
        parts.extend(
            [
                "http flood",
                "ddos dos web-facing port",
                "GoldenEye Slowloris HTTP Flood",
            ]
        )
    return " ".join(parts)


def tokenize(text: str) -> list[str]:
    tokens = [token.lower() for token in TOKEN_RE.findall(text)]
    bigrams = [f"{left}_{right}" for left, right in zip(tokens, tokens[1:])]
    return tokens + bigrams


class MLDetectionAgent:
    """Small local attack classifier used as an extra Agentic SOC signal.

    The model is intentionally stored as JSON and uses a simple Multinomial
    Naive Bayes scorer so the lab can run offline without downloading heavy ML
    libraries during Docker build.
    """

    def __init__(self, model_path: Path):
        self.model_path = Path(model_path)
        self.model: dict[str, Any] | None = None
        self._load()

    def _load(self) -> None:
        if not self.model_path.exists():
            self.model = None
            return
        with self.model_path.open("r", encoding="utf-8") as handle:
            self.model = json.load(handle)

    def stats(self) -> dict[str, Any]:
        if not self.model:
            return {
                "enabled": False,
                "status": "model_not_found",
                "path": str(self.model_path),
            }
        return {
            "enabled": True,
            "status": "ok",
            "path": str(self.model_path),
            "version": self.model.get("version"),
            "labels": sorted(
                set(self.model.get("labels", []))
                | set((self.model.get("flow_model") or {}).get("labels", []))
            ),
            "total_docs": self.model.get("total_docs", 0)
            + (self.model.get("flow_model") or {}).get("total_docs", 0),
            "domains": self.model.get("training_domains", ["seed_events"]),
        }

    def detect(self, event: dict[str, Any], event_count: int = 1) -> dict[str, Any]:
        if str(event.get("event_type") or "").startswith("generic."):
            return {
                "enabled": False,
                "status": "insufficient_event_semantics",
                "attack_type": None,
                "confidence": 0.0,
                "top_labels": [],
            }

        if not self.model:
            return {
                "enabled": False,
                "status": "model_not_found",
                "attack_type": None,
                "confidence": 0.0,
            }

        is_flow_dataset = str(event.get("source") or "").lower() in {
            "cicids_flow", "cicids2017"
        }
        model = (self.model.get("flow_model") if is_flow_dataset else self.model) or None
        if model is None:
            return {
                "enabled": False,
                "status": "flow_model_not_found" if is_flow_dataset else "model_not_found",
                "attack_type": None,
                "confidence": 0.0,
            }

        tokens = tokenize(event_to_text(event, event_count=event_count))
        if not tokens:
            return {
                "enabled": True,
                "status": "empty_event",
                "attack_type": None,
                "confidence": 0.0,
            }

        labels: list[str] = model.get("labels", [])
        vocabulary = set(model.get("vocabulary", []))
        vocab_size = max(1, len(vocabulary))
        alpha = float(model.get("alpha", 1.0))
        total_docs = max(1, int(model.get("total_docs", 1)))
        class_docs: dict[str, int] = model.get("class_doc_counts", {})
        class_totals: dict[str, int] = model.get("class_total_tokens", {})
        class_tokens: dict[str, dict[str, int]] = model.get("class_token_counts", {})

        scores: dict[str, float] = {}
        token_counts: dict[str, int] = {}
        for token in tokens:
            if token in vocabulary:
                token_counts[token] = token_counts.get(token, 0) + 1

        if not token_counts:
            return {
                "enabled": True,
                "status": "no_known_tokens",
                "attack_type": None,
                "confidence": 0.0,
            }

        for label in labels:
            prior = (class_docs.get(label, 0) + alpha) / (
                total_docs + alpha * max(1, len(labels))
            )
            score = math.log(prior)
            denominator = class_totals.get(label, 0) + alpha * vocab_size
            label_counts = class_tokens.get(label, {})
            for token, count in token_counts.items():
                probability = (label_counts.get(token, 0) + alpha) / denominator
                score += count * math.log(probability)
            scores[label] = score

        if not scores:
            return {
                "enabled": True,
                "status": "no_labels",
                "attack_type": None,
                "confidence": 0.0,
            }

        best_label = max(scores, key=scores.get)
        max_score = scores[best_label]
        exp_scores = {
            label: math.exp(min(0.0, score - max_score)) for label, score in scores.items()
        }
        total_exp = sum(exp_scores.values()) or 1.0
        confidence = exp_scores[best_label] / total_exp
        metadata = (model.get("label_metadata") or {}).get(best_label, {})
        top_labels = sorted(
            (
                {
                    "label": label,
                    "confidence": round(value / total_exp, 3),
                }
                for label, value in exp_scores.items()
            ),
            key=lambda item: item["confidence"],
            reverse=True,
        )[:3]

        return {
            "enabled": True,
            "status": "ok",
            "attack_type": best_label,
            "confidence": round(confidence, 3),
            "mitre": metadata.get("mitre", []),
            "recommended_title": metadata.get("title"),
            "recommended_description": metadata.get("description"),
            "model_version": model.get("version"),
            "top_labels": top_labels,
        }
