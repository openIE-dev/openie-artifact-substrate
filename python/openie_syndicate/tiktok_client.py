# SPDX-License-Identifier: Apache-2.0
"""TikTok Content Posting API v2 Client (`PULL_FROM_URL` + `FILE_UPLOAD` + Status Fetch).

Pure Python stdlib implementation integrated with the idempotent BLAKE3 `SyndicationLedger`.
"""

from __future__ import annotations

import json
import math
import os
from typing import Any

from .ledger import SyndicationLedger, compute_bundle_blake3
from .x_medium_bridge import HTTPTransport, RESEARCH_ORIGIN, default_urllib_transport

TIKTOK_MAX_CAPTION_UTF16 = 2200
VALID_PRIVACY_LEVELS = frozenset(
    {
        "PUBLIC_TO_EVERYONE",
        "MUTUAL_FOLLOW_FRIENDS",
        "FOLLOWER_OF_CREATOR",
        "SELF_ONLY",
    }
)


def compose_tiktok_bundle(
    study: dict[str, Any],
    substrate_record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compose a deterministic TikTok Content Posting API v2 bundle for a study."""
    study_id = str(study["id"])
    short_title = str(study.get("short_title", study["title"]))
    paper_rel = str(study["paper_url"])
    paper_url = (
        paper_rel if paper_rel.startswith("http") else f"{RESEARCH_ORIGIN}{paper_rel}"
    )
    hook_15 = str(study["tiers"]["15s"]["hook"])
    bullets = list(study["plain_bullets"])

    energy_obj = (substrate_record or {}).get("energy_cost_j") or {}
    ev_class = str(energy_obj.get("evidence_class", "unmetered"))
    cid = (
        str(substrate_record["canonical_id"])
        if substrate_record and "canonical_id" in substrate_record
        else f"blake3:tv:{study_id}"
    )

    video_uri = f"/media/tv/tiktok/{study_id}-tiktok.mp4"
    pull_video_url = f"{RESEARCH_ORIGIN}{video_uri}"
    cut_15 = study["tiers"]["15s"]

    caption = (
        f"{short_title} ({study['headline_metric']})\n"
        f"{hook_15}\n"
        f"1) {bullets[0]}\n"
        f"2) {bullets[1]}\n"
        f"3) {bullets[2]}\n"
        f"Energy class: {ev_class} ({study['energy_tier']}) · CC0-1.0 · {paper_url}\n"
        "#OpenScience #ComputerScience #VerifiedAI #Thermodynamics #OpenIE"
    )
    utf16_len = len(caption.encode("utf-16-le")) // 2
    if utf16_len > TIKTOK_MAX_CAPTION_UTF16:
        caption = caption[: TIKTOK_MAX_CAPTION_UTF16 - 4] + "..."
        utf16_len = len(caption.encode("utf-16-le")) // 2

    init_payload = {
        "post_info": {
            "title": caption,
            "privacy_level": "PUBLIC_TO_EVERYONE",
            "disable_duet": False,
            "disable_comment": False,
            "disable_stitch": False,
            "video_cover_timestamp_ms": 1000,
            "brand_content_toggle": False,
            "brand_organic_toggle": False,
            "is_aigc": True,
        },
        "source_info": {
            "source": "PULL_FROM_URL",
            "video_url": pull_video_url,
        },
    }
    validate_tiktok_init_payload(init_payload)

    bundle = {
        "schema": "openie.tiktok_post_bundle.v2",
        "study_id": study_id,
        "canonical_id": cid,
        "license": "CC0-1.0",
        "short_vertical_9x16": {
            "video_uri": video_uri,
            "fallback_video_uri": str(cut_15["video_url"]),
            "poster_uri": str(study["poster_url"]),
            "vtt_uri": str(cut_15["vtt_url"]),
            "resolution": "1080x1920",
            "fps": 60,
            "duration_s": float(cut_15["duration_s"]),
            "safe_zone_verified": True,
            "source_15s_sha256": str(cut_15["sha256"]),
        },
        "caption_utf16_chars": utf16_len,
        "api_v2_endpoint": "https://open.tiktokapis.com/v2/post/publish/video/init/",
        "api_v2_status_endpoint": "https://open.tiktokapis.com/v2/post/publish/status/fetch/",
        "api_v2_init_payload": init_payload,
    }
    bundle["content_blake3"] = compute_bundle_blake3(bundle)
    return bundle


def validate_tiktok_init_payload(payload: dict[str, Any]) -> None:
    """Validate a TikTok Content Posting API v2 `/v2/post/publish/video/init/` request payload."""
    if not isinstance(payload, dict):
        raise ValueError("TikTok init payload must be a JSON object")
    post_info = payload.get("post_info")
    source_info = payload.get("source_info")
    if not isinstance(post_info, dict) or not isinstance(source_info, dict):
        raise ValueError("TikTok init payload requires post_info and source_info objects")

    title = post_info.get("title", "")
    if not isinstance(title, str) or not title:
        raise ValueError("post_info.title must be a non-empty string")
    utf16_len = len(title.encode("utf-16-le")) // 2
    if utf16_len > TIKTOK_MAX_CAPTION_UTF16:
        raise ValueError(f"post_info.title exceeds {TIKTOK_MAX_CAPTION_UTF16} UTF-16 code units")

    priv = post_info.get("privacy_level")
    if priv not in VALID_PRIVACY_LEVELS:
        raise ValueError(f"Invalid post_info.privacy_level: {priv!r}")

    for b_key in ("disable_duet", "disable_comment", "disable_stitch", "is_aigc"):
        if b_key in post_info and not isinstance(post_info[b_key], bool):
            raise ValueError(f"post_info.{b_key} must be boolean")

    source = source_info.get("source")
    if source == "PULL_FROM_URL":
        vurl = source_info.get("video_url", "")
        if not isinstance(vurl, str) or not vurl.startswith("https://"):
            raise ValueError("PULL_FROM_URL requires https:// source_info.video_url")
    elif source == "FILE_UPLOAD":
        for i_key in ("video_size", "chunk_size", "total_chunk_count"):
            val = source_info.get(i_key)
            if not isinstance(val, int) or isinstance(val, bool) or val < 1:
                raise ValueError(f"FILE_UPLOAD requires positive integer {i_key}")
        v_size = source_info["video_size"]
        c_size = source_info["chunk_size"]
        t_cnt = source_info["total_chunk_count"]
        expected_chunks = max(1, math.ceil(v_size / c_size))
        if t_cnt != expected_chunks:
            raise ValueError(
                f"total_chunk_count={t_cnt} does not match ceil({v_size}/{c_size})={expected_chunks}"
            )
    else:
        raise ValueError(f"Unsupported TikTok source_info.source: {source!r}")


class TikTokClient:
    """Zero-dependency TikTok Content Posting API v2 client."""

    INIT_URL = "https://open.tiktokapis.com/v2/post/publish/video/init/"
    STATUS_URL = "https://open.tiktokapis.com/v2/post/publish/status/fetch/"

    def __init__(
        self,
        access_token: str | None = None,
        transport: HTTPTransport | None = None,
    ) -> None:
        self.access_token = (
            access_token
            if access_token is not None
            else os.environ.get("TIKTOK_ACCESS_TOKEN", "")
        )
        self.transport = transport or default_urllib_transport

    def _auth_headers(self) -> dict[str, str]:
        if not self.access_token:
            raise RuntimeError("TIKTOK_ACCESS_TOKEN missing in environment")
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json; charset=UTF-8",
            "Accept": "application/json",
        }

    def publish_pull_from_url(
        self,
        tiktok_bundle: dict[str, Any],
        *,
        ledger: SyndicationLedger | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Publish a staged TikTok bundle via `PULL_FROM_URL` with BLAKE3 idempotency."""
        study_id = str(tiktok_bundle["study_id"])
        digest = str(tiktok_bundle["content_blake3"])
        init_payload = dict(tiktok_bundle["api_v2_init_payload"])
        validate_tiktok_init_payload(init_payload)

        if ledger is not None and ledger.is_duplicate("tiktok", study_id, digest):
            return {
                "study_id": study_id,
                "status": "skipped_duplicate",
                "content_blake3": digest,
            }

        if dry_run:
            if ledger is not None:
                ledger.record(
                    channel="tiktok",
                    item_id=study_id,
                    direction="outbound",
                    content_blake3=digest,
                    status="staged",
                    canonical_id=tiktok_bundle.get("canonical_id"),
                )
            return {
                "study_id": study_id,
                "status": "staged",
                "content_blake3": digest,
                "payload": init_payload,
            }

        status, _, raw = self.transport(
            "POST",
            self.INIT_URL,
            self._auth_headers(),
            json.dumps(init_payload).encode("utf-8"),
        )
        if status < 200 or status >= 300:
            raise RuntimeError(
                f"TikTok video/init failed with HTTP {status}: {raw.decode('utf-8', errors='replace')}"
            )
        resp_doc = json.loads(raw.decode("utf-8"))
        err = resp_doc.get("error", {})
        if err and err.get("code") not in {None, "ok"}:
            raise RuntimeError(f"TikTok API error: {err}")
        publish_id = str(resp_doc["data"]["publish_id"])

        if ledger is not None:
            ledger.record(
                channel="tiktok",
                item_id=study_id,
                direction="outbound",
                content_blake3=digest,
                status="published",
                canonical_id=tiktok_bundle.get("canonical_id"),
                remote_id=publish_id,
            )
        return {
            "study_id": study_id,
            "status": "published",
            "publish_id": publish_id,
            "content_blake3": digest,
        }

    def upload_file_chunked(
        self,
        video_bytes: bytes,
        *,
        title: str,
        privacy_level: str = "PUBLIC_TO_EVERYONE",
        chunk_size: int = 10 * 1024 * 1024,
    ) -> str:
        """Publish raw MP4 bytes via TikTok `FILE_UPLOAD` chunked PUT transfer."""
        if not video_bytes:
            raise ValueError("video_bytes must be non-empty")
        v_size = len(video_bytes)
        eff_chunk = min(chunk_size, v_size)
        total_chunks = max(1, math.ceil(v_size / eff_chunk))

        init_payload = {
            "post_info": {
                "title": title,
                "privacy_level": privacy_level,
                "disable_duet": False,
                "disable_comment": False,
                "disable_stitch": False,
                "is_aigc": True,
            },
            "source_info": {
                "source": "FILE_UPLOAD",
                "video_size": v_size,
                "chunk_size": eff_chunk,
                "total_chunk_count": total_chunks,
            },
        }
        validate_tiktok_init_payload(init_payload)
        status, _, raw = self.transport(
            "POST",
            self.INIT_URL,
            self._auth_headers(),
            json.dumps(init_payload).encode("utf-8"),
        )
        if status < 200 or status >= 300:
            raise RuntimeError(f"TikTok FILE_UPLOAD init failed with HTTP {status}")
        data = json.loads(raw.decode("utf-8"))["data"]
        publish_id = str(data["publish_id"])
        upload_url = str(data["upload_url"])

        for idx in range(total_chunks):
            start = idx * eff_chunk
            end = min(v_size, start + eff_chunk) - 1
            chunk = video_bytes[start : end + 1]
            put_headers = {
                "Content-Type": "video/mp4",
                "Content-Length": str(len(chunk)),
                "Content-Range": f"bytes {start}-{end}/{v_size}",
            }
            p_status, _, p_raw = self.transport("PUT", upload_url, put_headers, chunk)
            if p_status < 200 or p_status >= 300:
                raise RuntimeError(
                    f"TikTok chunk PUT {idx} failed with HTTP {p_status}: {p_raw.decode('utf-8', errors='replace')}"
                )
        return publish_id

    def fetch_publish_status(self, publish_id: str) -> dict[str, Any]:
        """Poll `POST /v2/post/publish/status/fetch/` for `publish_id`."""
        status, _, raw = self.transport(
            "POST",
            self.STATUS_URL,
            self._auth_headers(),
            json.dumps({"publish_id": publish_id}).encode("utf-8"),
        )
        if status < 200 or status >= 300:
            raise RuntimeError(f"TikTok status/fetch failed with HTTP {status}")
        return dict(json.loads(raw.decode("utf-8")).get("data", {}))
