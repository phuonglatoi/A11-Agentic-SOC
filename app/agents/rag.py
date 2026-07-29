from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path
from typing import Any


TOKEN = re.compile(r"[A-Za-z0-9_.-]{3,}")
HEADING = re.compile(r"^#\s+(?P<title>.+)$", re.MULTILINE)
TAGS = re.compile(r"^(?:Tags|MITRE ATT&CK):\s*(?P<tags>.+)$", re.IGNORECASE | re.MULTILINE)


def _tokens(text: str) -> Counter:
    return Counter(token.lower() for token in TOKEN.findall(text))


class LocalKnowledgeBase:
    """Small dependency-free retrieval layer suitable for an offline SOC lab."""

    def __init__(self, directory: Path):
        self.directory = directory
        self.documents: list[dict[str, Any]] = []
        self.reload()

    def reload(self) -> None:
        self.documents = []
        paths = sorted(self.directory.glob("*.md")) if self.directory.exists() else []
        for path in paths:
            text = path.read_text(encoding="utf-8")
            title = self._title(text, path)
            tags = self._tags(text)
            searchable = " ".join([path.stem, title, " ".join(tags), text])
            self.documents.append(
                {
                    "name": path.stem,
                    "title": title,
                    "path": str(path),
                    "tags": tags,
                    "text": text,
                    "tokens": _tokens(searchable),
                }
            )

    def search(self, query: str, limit: int = 3) -> list[dict]:
        limit = max(1, min(limit, 10))
        query_tokens = _tokens(query)
        if not query_tokens:
            return []
        scored: list[tuple[float, dict]] = []
        for document in self.documents:
            overlap = sum(
                min(count, document["tokens"].get(token, 0))
                for token, count in query_tokens.items()
            )
            if not overlap:
                continue
            score = overlap / math.sqrt(
                max(1, sum(document["tokens"].values()))
                * max(1, sum(query_tokens.values()))
            )
            title_tokens = _tokens(f"{document['name']} {document['title']}")
            title_overlap = sum(
                min(count, title_tokens.get(token, 0))
                for token, count in query_tokens.items()
            )
            score += title_overlap * 0.03
            scored.append((score, document))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [
            {
                "name": document["name"],
                "title": document["title"],
                "score": round(score, 4),
                "tags": document["tags"],
                "path": document["path"],
                "excerpt": self._excerpt(document["text"], query_tokens),
            }
            for score, document in scored[:limit]
        ]

    def stats(self) -> dict[str, Any]:
        return {
            "directory": str(self.directory),
            "document_count": len(self.documents),
            "documents": [
                {
                    "name": document["name"],
                    "title": document["title"],
                    "tags": document["tags"],
                }
                for document in self.documents
            ],
        }

    @staticmethod
    def _excerpt(text: str, query_tokens: Counter, limit: int = 700) -> str:
        paragraphs = [part.strip() for part in text.split("\n\n") if part.strip()]
        ranked = sorted(
            paragraphs,
            key=lambda paragraph: sum(
                _tokens(paragraph).get(token, 0) for token in query_tokens
            ),
            reverse=True,
        )
        excerpt = (ranked[0] if ranked else text).replace("\n", " ")
        return excerpt[:limit]

    @staticmethod
    def _title(text: str, path: Path) -> str:
        match = HEADING.search(text)
        return match.group("title").strip() if match else path.stem.replace("_", " ")

    @staticmethod
    def _tags(text: str) -> list[str]:
        tags: list[str] = []
        for match in TAGS.finditer(text):
            raw_tags = re.split(r"[,;]", match.group("tags"))
            tags.extend(tag.strip() for tag in raw_tags if tag.strip())
        return list(dict.fromkeys(tags))
