# SPDX-License-Identifier: Apache-2.0
"""Resilient Public Mirrors: Internet Archive (`IAS3`), Mastodon (`ActivityPub`), and Bluesky (`ATProto`).

Zero external dependencies; supports deterministic `dry_run` staging and live HTTPS publishing.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import urllib.parse
from typing import Any, Sequence

from .ledger import SyndicationLedger, compute_bundle_blake3
from .x_medium_bridge import HTTPTransport, default_urllib_transport

_URL_SPAN_RE = re.compile(r"https?://[^\s<>\"']+")


class InternetArchiveMirror:
    """Internet Archive S3-compatible (`IAS3`) preservation connector (`CC0-1.0`)."""

    S3_ORIGIN = "https://s3.us.archive.org"

    def __init__(
        self,
        access_key: str | None = None,
        secret_key: str | None = None,
        transport: HTTPTransport | None = None,
    ) -> None:
        self.access_key = (
            access_key if access_key is not None else os.environ.get("IA_ACCESS_KEY", "")
        )
        self.secret_key = (
            secret_key if secret_key is not None else os.environ.get("IA_SECRET_KEY", "")
        )
        self.transport = transport or default_urllib_transport

    def put_artifact(
        self,
        *,
        identifier: str,
        filename: str,
        payload_bytes: bytes,
        title: str,
        canonical_id: str,
        content_type: str = "application/octet-stream",
        mediatype: str = "texts",
        ledger: SyndicationLedger | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        digest = compute_bundle_blake3(payload_bytes)
        item_key = f"{identifier}/{filename}"
        if ledger is not None and ledger.is_duplicate("internet_archive", item_key, digest):
            return {"item_key": item_key, "status": "skipped_duplicate", "content_blake3": digest}

        url = f"{self.S3_ORIGIN}/{urllib.parse.quote(identifier)}/{urllib.parse.quote(filename)}"
        meta_headers = {
            "Content-Type": content_type,
            "x-archive-auto-make-bucket": "1",
            "x-archive-meta-mediatype": mediatype,
            "x-archive-meta-title": title,
            "x-archive-meta-creator": "Open Interface Engineering",
            "x-archive-meta-licenseurl": "https://creativecommons.org/publicdomain/zero/1.0/",
            "x-archive-meta-external-identifier": canonical_id,
        }
        if dry_run:
            if ledger is not None:
                ledger.record(
                    channel="internet_archive",
                    item_id=item_key,
                    direction="outbound",
                    content_blake3=digest,
                    status="staged",
                    canonical_id=canonical_id,
                    remote_url=f"https://archive.org/details/{identifier}",
                )
            return {
                "item_key": item_key,
                "status": "staged",
                "url": url,
                "content_blake3": digest,
            }

        if not self.access_key or not self.secret_key:
            raise RuntimeError("IA_ACCESS_KEY and IA_SECRET_KEY required for live IAS3 mirror")
        headers = {
            **meta_headers,
            "Authorization": f"LOW {self.access_key}:{self.secret_key}",
        }
        status, _, raw = self.transport("PUT", url, headers, payload_bytes)
        if status < 200 or status >= 300:
            raise RuntimeError(
                f"Internet Archive IAS3 PUT failed ({status}): {raw.decode('utf-8', errors='replace')}"
            )
        details_url = f"https://archive.org/details/{identifier}"
        if ledger is not None:
            ledger.record(
                channel="internet_archive",
                item_id=item_key,
                direction="outbound",
                content_blake3=digest,
                status="published",
                canonical_id=canonical_id,
                remote_url=details_url,
            )
        return {
            "item_key": item_key,
            "status": "published",
            "url": details_url,
            "content_blake3": digest,
        }


class MastodonMirror:
    """Mastodon / Fediverse REST v1 thread publisher with BLAKE3 `Idempotency-Key`."""

    MAX_CHARS = 500

    def __init__(
        self,
        instance_url: str | None = None,
        access_token: str | None = None,
        transport: HTTPTransport | None = None,
    ) -> None:
        raw_inst = (
            instance_url
            if instance_url is not None
            else os.environ.get("MASTODON_INSTANCE_URL", "https://fosstodon.org")
        )
        self.instance_url = raw_inst.rstrip("/")
        self.access_token = (
            access_token
            if access_token is not None
            else os.environ.get("MASTODON_ACCESS_TOKEN", "")
        )
        self.transport = transport or default_urllib_transport

    def post_thread(
        self,
        *,
        study_id: str,
        posts: Sequence[str],
        ledger: SyndicationLedger | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        for idx, p in enumerate(posts, start=1):
            if len(p) > self.MAX_CHARS:
                raise ValueError(f"Mastodon status {idx} exceeds {self.MAX_CHARS} chars")
        digest = compute_bundle_blake3({"study_id": study_id, "posts": list(posts)})
        if ledger is not None and ledger.is_duplicate("mastodon", study_id, digest):
            return {"study_id": study_id, "status": "skipped_duplicate", "content_blake3": digest}

        if dry_run:
            if ledger is not None:
                ledger.record(
                    channel="mastodon",
                    item_id=study_id,
                    direction="outbound",
                    content_blake3=digest,
                    status="staged",
                )
            return {
                "study_id": study_id,
                "status": "staged",
                "post_count": len(posts),
                "content_blake3": digest,
            }

        if not self.access_token:
            raise RuntimeError("MASTODON_ACCESS_TOKEN missing in environment")
        status_ids: list[str] = []
        status_url: str | None = None
        prev_id: str | None = None
        for idx, p in enumerate(posts):
            idem = compute_bundle_blake3(f"{digest}:{idx}")
            payload: dict[str, Any] = {"status": p, "visibility": "public"}
            if prev_id is not None:
                payload["in_reply_to_id"] = prev_id
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json",
                "Idempotency-Key": idem,
            }
            code, _, raw = self.transport(
                "POST",
                f"{self.instance_url}/api/v1/statuses",
                headers,
                json.dumps(payload).encode("utf-8"),
            )
            if code < 200 or code >= 300:
                raise RuntimeError(f"Mastodon status {idx} failed with HTTP {code}")
            doc = json.loads(raw.decode("utf-8"))
            sid = str(doc["id"])
            if idx == 0:
                status_url = str(doc.get("url", ""))
            status_ids.append(sid)
            prev_id = sid

        if ledger is not None:
            ledger.record(
                channel="mastodon",
                item_id=study_id,
                direction="outbound",
                content_blake3=digest,
                status="published",
                remote_id=status_ids[0],
                remote_url=status_url,
            )
        return {
            "study_id": study_id,
            "status": "published",
            "status_ids": status_ids,
            "url": status_url,
            "content_blake3": digest,
        }


def build_bluesky_facets(text: str) -> list[dict[str, Any]]:
    """Compute UTF-8 byte-offset `app.bsky.richtext.facet#link` entries per AT Protocol spec."""
    facets: list[dict[str, Any]] = []
    for match in _URL_SPAN_RE.finditer(text):
        url = match.group(0).rstrip(".,;:!?)")
        char_start = match.start()
        char_end = char_start + len(url)
        byte_start = len(text[:char_start].encode("utf-8"))
        byte_end = len(text[:char_end].encode("utf-8"))
        facets.append(
            {
                "index": {"byteStart": byte_start, "byteEnd": byte_end},
                "features": [
                    {
                        "$type": "app.bsky.richtext.facet#link",
                        "uri": url,
                    }
                ],
            }
        )
    return facets


class BlueskyATProtoMirror:
    """Bluesky AT Protocol (`com.atproto.repo.createRecord`) thread publisher."""

    MAX_CHARS = 300

    def __init__(
        self,
        handle: str | None = None,
        app_password: str | None = None,
        pds_url: str = "https://bsky.social",
        transport: HTTPTransport | None = None,
    ) -> None:
        self.handle = handle if handle is not None else os.environ.get("BLUESKY_HANDLE", "")
        self.app_password = (
            app_password
            if app_password is not None
            else os.environ.get("BLUESKY_APP_PASSWORD", "")
        )
        self.pds_url = pds_url.rstrip("/")
        self.transport = transport or default_urllib_transport

    def post_thread(
        self,
        *,
        study_id: str,
        posts: Sequence[str],
        ledger: SyndicationLedger | None = None,
        created_at_utc: str | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        for idx, p in enumerate(posts, start=1):
            if len(p) > self.MAX_CHARS:
                raise ValueError(f"Bluesky post {idx} exceeds {self.MAX_CHARS} chars ({len(p)})")
        digest = compute_bundle_blake3({"study_id": study_id, "posts": list(posts)})
        if ledger is not None and ledger.is_duplicate("bluesky", study_id, digest):
            return {"study_id": study_id, "status": "skipped_duplicate", "content_blake3": digest}

        staged_records = [
            {
                "$type": "app.bsky.feed.post",
                "text": p,
                "facets": build_bluesky_facets(p),
                "langs": ["en"],
            }
            for p in posts
        ]
        if dry_run:
            if ledger is not None:
                ledger.record(
                    channel="bluesky",
                    item_id=study_id,
                    direction="outbound",
                    content_blake3=digest,
                    status="staged",
                )
            return {
                "study_id": study_id,
                "status": "staged",
                "records": staged_records,
                "content_blake3": digest,
            }

        if not self.handle or not self.app_password:
            raise RuntimeError("BLUESKY_HANDLE and BLUESKY_APP_PASSWORD missing in environment")

        s_code, _, s_raw = self.transport(
            "POST",
            f"{self.pds_url}/xrpc/com.atproto.server.createSession",
            {"Content-Type": "application/json", "Accept": "application/json"},
            json.dumps({"identifier": self.handle, "password": self.app_password}).encode("utf-8"),
        )
        if s_code < 200 or s_code >= 300:
            raise RuntimeError(f"Bluesky createSession failed with HTTP {s_code}")
        sess = json.loads(s_raw.decode("utf-8"))
        jwt = str(sess["accessJwt"])
        did = str(sess["did"])

        now_iso = created_at_utc or dt.datetime.now(dt.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        root_ref: dict[str, str] | None = None
        parent_ref: dict[str, str] | None = None
        uris: list[str] = []

        for rec_template in staged_records:
            rec = dict(rec_template)
            rec["createdAt"] = now_iso
            if root_ref is not None and parent_ref is not None:
                rec["reply"] = {"root": root_ref, "parent": parent_ref}
            c_code, _, c_raw = self.transport(
                "POST",
                f"{self.pds_url}/xrpc/com.atproto.repo.createRecord",
                {
                    "Authorization": f"Bearer {jwt}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                json.dumps(
                    {
                        "repo": did,
                        "collection": "app.bsky.feed.post",
                        "record": rec,
                    }
                ).encode("utf-8"),
            )
            if c_code < 200 or c_code >= 300:
                raise RuntimeError(f"Bluesky createRecord failed with HTTP {c_code}")
            created = json.loads(c_raw.decode("utf-8"))
            ref = {"uri": str(created["uri"]), "cid": str(created["cid"])}
            if root_ref is None:
                root_ref = ref
            parent_ref = ref
            uris.append(ref["uri"])

        if ledger is not None:
            ledger.record(
                channel="bluesky",
                item_id=study_id,
                direction="outbound",
                content_blake3=digest,
                status="published",
                remote_id=uris[0],
                remote_url=uris[0],
            )
        return {
            "study_id": study_id,
            "status": "published",
            "uris": uris,
            "content_blake3": digest,
        }
