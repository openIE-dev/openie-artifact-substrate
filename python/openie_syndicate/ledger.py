# SPDX-License-Identifier: Apache-2.0
"""Idempotent BLAKE3 syndication ledger & bidirectional URL resolver."""

from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from openie_artifact.crypto import blake3_hex, canonical_jcs_bytes

DEFAULT_TX_UTC = "2026-11-24T18:00:00Z"
X_BACKLINK_PLACEHOLDER = "{{X_THREAD_URL}}"


def compute_bundle_blake3(payload: dict[str, Any] | str | bytes) -> str:
    """Compute deterministic 64-hex BLAKE3 over canonical JCS JSON, UTF-8 text, or bytes."""
    if isinstance(payload, bytes):
        raw = payload
    elif isinstance(payload, str):
        raw = payload.encode("utf-8")
    else:
        raw = canonical_jcs_bytes(payload)
    return blake3_hex(b"openie-syndication-v1\x00" + raw)


def default_x_search_intent_url(study_id: str, short_title: str = "") -> str:
    """Fallback X discussion search URL used before live `tweet_id` is minted."""
    query = f"research.openie.dev/tv/?study={study_id}"
    if short_title:
        query = f'"{short_title}" OR {query}'
    return f"https://x.com/search?q={urllib.parse.quote(query, safe='')}&src=typed_query"


def default_medium_canonical_import_url(study_id: str) -> str:
    """Default public canonical import bridge URL before live Medium API responds."""
    return f"https://research.openie.dev/syndication/medium/{study_id}/"


@dataclass
class SyndicationLedger:
    """Content-addressed BLAKE3 ledger preventing duplicate syndication across channels."""

    entries: dict[str, dict[str, Any]] = field(default_factory=dict)
    x_thread_urls: dict[str, str] = field(default_factory=dict)
    medium_live_urls: dict[str, str] = field(default_factory=dict)

    @staticmethod
    def make_key(channel: str, item_id: str) -> str:
        return f"{channel}:{item_id}"

    def is_duplicate(self, channel: str, item_id: str, content_blake3: str) -> bool:
        """Return True if `(channel, item_id)` was already dispatched with the same BLAKE3."""
        key = self.make_key(channel, item_id)
        existing = self.entries.get(key)
        if not existing:
            return False
        return (
            existing.get("content_blake3") == content_blake3
            and existing.get("status") in {"published", "staged"}
        )

    def has_seen_digest(self, channel: str, content_blake3: str) -> bool:
        """Return True if any entry on `channel` already recorded `content_blake3`."""
        return any(
            e.get("channel") == channel
            and e.get("content_blake3") == content_blake3
            and e.get("status") in {"published", "staged"}
            for e in self.entries.values()
        )

    def record(
        self,
        *,
        channel: str,
        item_id: str,
        direction: str,
        content_blake3: str,
        status: str,
        canonical_id: str | None = None,
        remote_id: str | None = None,
        remote_url: str | None = None,
        updated_utc: str = DEFAULT_TX_UTC,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        key = self.make_key(channel, item_id)
        entry: dict[str, Any] = {
            "ledger_key": key,
            "channel": channel,
            "item_id": item_id,
            "direction": direction,
            "content_blake3": content_blake3,
            "status": status,
            "updated_utc": updated_utc,
        }
        if canonical_id is not None:
            entry["canonical_id"] = canonical_id
        if remote_id is not None:
            entry["remote_id"] = remote_id
        if remote_url is not None:
            entry["remote_url"] = remote_url
        if metadata:
            entry["metadata"] = metadata
        self.entries[key] = entry

        if channel == "x_thread" and remote_url:
            self.x_thread_urls[item_id] = remote_url
        if channel == "medium_article" and remote_url:
            self.medium_live_urls[item_id] = remote_url
        return entry

    def resolve_x_thread_url(self, study_id: str, short_title: str = "") -> str:
        if study_id in self.x_thread_urls:
            return self.x_thread_urls[study_id]
        return default_x_search_intent_url(study_id, short_title)

    def resolve_medium_url(self, study_id: str) -> str:
        if study_id in self.medium_live_urls:
            return self.medium_live_urls[study_id]
        return default_medium_canonical_import_url(study_id)

    def ledger_blake3(self) -> str:
        return compute_bundle_blake3(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        sorted_entries = {k: self.entries[k] for k in sorted(self.entries)}
        return {
            "schema": "openie.syndication_ledger.v1",
            "entry_count": len(sorted_entries),
            "x_thread_urls": dict(sorted(self.x_thread_urls.items())),
            "medium_live_urls": dict(sorted(self.medium_live_urls.items())),
            "entries": sorted_entries,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SyndicationLedger:
        return cls(
            entries=dict(data.get("entries", {})),
            x_thread_urls=dict(data.get("x_thread_urls", {})),
            medium_live_urls=dict(data.get("medium_live_urls", {})),
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        doc = self.to_dict()
        doc["ledger_blake3"] = self.ledger_blake3()
        path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> SyndicationLedger:
        if not path.exists():
            return cls()
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))
