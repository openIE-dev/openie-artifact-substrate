#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Deterministic CLI for OpenIE X <-> Medium Bidirectional & Multi-Ecosystem Syndication.

Modes:
  - `stage`: Deterministically emit all 28 Medium essays (`public/syndication/medium/<id>.md`),
    28 X 5-post threads (`public/syndication/x/<id>.json`), 28 TikTok v2 bundles
    (`public/syndication/tiktok/<id>.json`), 28 `blog.openie.dev` YAML manifests
    (`public/syndication/blog-manifests/<id>.yaml`), `public/syndication/ecosystem-matrix.json`,
    and `src/data/syndication-catalog.json`, validating all 140 tweets (`<= 280` weighted chars)
    and canonical schema projections.
  - `verify`: Validate an existing staged output directory against all invariants.
  - `publish`: Publish staged bundles to X, Medium, TikTok, or Resilient Mirrors via env credentials.
  - `sync-rss-to-x`: Reverse Flow 1 — ingest Medium RSS XML and sync to X.
  - `sync-x-to-medium`: Reverse Flow 2 — ingest X timeline/pulse JSON and sync to Medium + root reply.

Usage:
  PYTHONPATH=python python3 scripts/syndicate.py --mode stage \
      --tv-catalog /path/to/research-openie-web/src/data/tv-catalog.json \
      --substrate-catalog catalog/unsiloed-artifacts.jsonl \
      --web-root /path/to/research-openie-web
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "python") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "python"))

from openie_artifact.schema_validator import validate_openie_artifact
from openie_syndicate import (
    DEFAULT_MEDIUM_RSS_FEEDS,
    MediumClient,
    SyndicationLedger,
    TikTokClient,
    X_MAX_WEIGHTED_CHARS,
    XClient,
    build_ecosystem_matrix,
    compose_blog_manifest_yaml,
    compose_medium_article,
    compose_tiktok_bundle,
    compose_x_thread,
    compute_bundle_blake3,
    resolve_medium_x_backlink,
    sync_medium_rss_to_x,
    sync_x_threads_to_medium,
    update_x_bundle_medium_url,
    validate_tiktok_init_payload,
    weighted_len,
)


def _load_tv_substrate_index(substrate_jsonl: Path) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    if not substrate_jsonl.exists():
        return index
    for line in substrate_jsonl.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if rec.get("artifact_kind") == "tv":
            slug = str(rec.get("slug", ""))
            study_id = slug[3:] if slug.startswith("tv-") else slug
            index[study_id] = rec
    return index


def _default_syndication_channels_projection() -> list[dict[str, str]]:
    return [
        {
            "ecosystem": "x-medium-bridge",
            "direction": "bidirectional",
            "protocol": "oauth1a-v2+medium-v1-rss",
            "status": "staged",
        },
        {
            "ecosystem": "tiktok",
            "direction": "outbound",
            "protocol": "tiktok-content-posting-v2",
            "status": "staged",
        },
        {
            "ecosystem": "blog-openie-dev",
            "direction": "outbound",
            "protocol": "yaml-manifest-v1",
            "status": "staged",
        },
        {
            "ecosystem": "internet-archive",
            "direction": "outbound",
            "protocol": "ias3-rest",
            "status": "staged",
        },
        {
            "ecosystem": "mastodon",
            "direction": "bidirectional",
            "protocol": "activitypub-rest-v1",
            "status": "staged",
        },
        {
            "ecosystem": "bluesky",
            "direction": "outbound",
            "protocol": "atproto-xrpc",
            "status": "staged",
        },
        {
            "ecosystem": "commons-agent-bus",
            "direction": "bidirectional",
            "protocol": "mcp+a2a+webmcp",
            "status": "live",
        },
    ]


def stage_all(
    *,
    tv_catalog_path: Path,
    substrate_jsonl_path: Path,
    web_root: Path,
) -> dict[str, Any]:
    """Deterministically generate all 28 syndication bundles and ecosystem catalogs."""
    tv_catalog = json.loads(tv_catalog_path.read_text(encoding="utf-8"))
    studies: list[dict[str, Any]] = list(tv_catalog["studies"])
    substrate_by_id = _load_tv_substrate_index(substrate_jsonl_path)

    pub_synd = web_root / "public" / "syndication"
    med_dir = pub_synd / "medium"
    x_dir = pub_synd / "x"
    tt_dir = pub_synd / "tiktok"
    blog_dir = pub_synd / "blog-manifests"
    data_dir = web_root / "src" / "data"

    for d in (med_dir, x_dir, tt_dir, blog_dir, data_dir):
        d.mkdir(parents=True, exist_ok=True)

    ledger = SyndicationLedger()
    ecosystem_matrix = build_ecosystem_matrix()
    tiktok_real_by_id: dict[str, dict[str, Any]] = {}
    tk_manifest_path = data_dir / "tiktok-snackables.json"
    if tk_manifest_path.is_file():
        tk_doc = json.loads(tk_manifest_path.read_text(encoding="utf-8"))
        for tk_item in tk_doc.get("studies", []):
            tiktok_real_by_id[str(tk_item["id"])] = tk_item
    catalog_studies: list[dict[str, Any]] = []
    total_tweets = 0
    global_max_weighted = 0

    for study in studies:
        sid = str(study["id"])
        sub_rec = substrate_by_id.get(sid)

        med_bundle = compose_medium_article(study, sub_rec, ledger=ledger)
        x_bundle = compose_x_thread(
            study, sub_rec, medium_url=f"https://research.openie.dev{med_bundle['canonical_import_uri']}"
        )
        tt_bundle = compose_tiktok_bundle(study, sub_rec)
        blog_yaml = compose_blog_manifest_yaml(study, sub_rec)
        blog_blake3 = compute_bundle_blake3(blog_yaml)

        # Verify every tweet in the 5-post bundle
        if len(x_bundle["posts"]) != 5:
            raise AssertionError(f"Expected 5 X posts for {sid}")
        for post in x_bundle["posts"]:
            wlen = weighted_len(post["text"])
            if wlen > X_MAX_WEIGHTED_CHARS or wlen != post["weighted_chars"]:
                raise AssertionError(f"Invalid weighted_chars on {sid} post {post['position']}: {wlen}")
            total_tweets += 1
            global_max_weighted = max(global_max_weighted, wlen)
        if x_bundle["posts"][0]["urls"]:
            raise AssertionError(f"Post 1 for {sid} must have zero URLs")

        validate_tiktok_init_payload(tt_bundle["api_v2_init_payload"])

        # Validate Deliverable 1 schema projection against the canonical substrate record!
        tk_real = tiktok_real_by_id.get(sid)
        short_9x16_proj = {
            "video_uri": tk_real["video_url"] if tk_real else tt_bundle["short_vertical_9x16"]["video_uri"],
            "poster_uri": tk_real["poster_url"] if tk_real else tt_bundle["short_vertical_9x16"]["poster_uri"],
            "vtt_uri": tk_real["vtt_url"] if tk_real else tt_bundle["short_vertical_9x16"]["vtt_uri"],
            "resolution": "1080x1920",
            "fps": 60,
            "duration_s": float(tk_real["duration_s"]) if tk_real else tt_bundle["short_vertical_9x16"]["duration_s"],
            "safe_zone_verified": True,
            "sha256": tk_real["sha256"] if tk_real else tt_bundle["short_vertical_9x16"]["source_15s_sha256"],
        }
        med_proj = {
            "markdown_uri": med_bundle["markdown_uri"],
            "canonical_import_uri": med_bundle["canonical_import_uri"],
            "canonical_source_url": med_bundle["canonical_source_url"],
            "word_count": med_bundle["word_count"],
            "reading_time_min": med_bundle["reading_time_min"],
            "license": "CC0-1.0",
            "x_thread_backlink_slot": med_bundle["x_thread_backlink_slot"],
        }
        x_proj = {
            "bundle_uri": f"/syndication/x/{sid}.json",
            "post_count": x_bundle["post_count"],
            "max_weighted_chars": x_bundle["max_weighted_chars"],
            "card_video_uri": x_bundle["card_video_uri"],
            "medium_crosslink_uri": x_bundle["medium_crosslink_uri"],
        }
        chan_proj = _default_syndication_channels_projection()

        if sub_rec is not None:
            projected_artifact = copy.deepcopy(sub_rec)
            projected_artifact["modality_variants"]["short_vertical_9x16"] = short_9x16_proj
            projected_artifact["modality_variants"]["medium_article"] = med_proj
            projected_artifact["modality_variants"]["x_thread"] = x_proj
            projected_artifact["modality_variants"]["syndication_channels"] = chan_proj
            validate_openie_artifact(projected_artifact)

        # Write deterministic staged files
        (med_dir / f"{sid}.md").write_text(med_bundle["markdown"], encoding="utf-8")
        (x_dir / f"{sid}.json").write_text(
            json.dumps(x_bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        (tt_dir / f"{sid}.json").write_text(
            json.dumps(tt_bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        (blog_dir / f"{sid}.yaml").write_text(blog_yaml, encoding="utf-8")

        cid = str(sub_rec["canonical_id"]) if sub_rec else f"blake3:tv:{sid}"
        energy_obj = (sub_rec or {}).get(
            "energy_cost_j",
            {
                "evidence_class": "unmetered",
                "joules": None,
                "meter_or_formula": study.get("energy_disclosure", ""),
                "board_metered": False,
                "landauer_300k_bits_equiv": None,
            },
        )

        # Record all staged projections in the idempotent BLAKE3 ledger
        ledger.record(
            channel="medium_article",
            item_id=sid,
            direction="outbound",
            content_blake3=med_bundle["content_blake3"],
            status="staged",
            canonical_id=cid,
            remote_url=f"https://research.openie.dev{med_bundle['canonical_import_uri']}",
        )
        ledger.record(
            channel="x_thread",
            item_id=sid,
            direction="outbound",
            content_blake3=x_bundle["content_blake3"],
            status="staged",
            canonical_id=cid,
            remote_url=med_bundle["resolved_x_thread_url"],
        )
        ledger.record(
            channel="tiktok",
            item_id=sid,
            direction="outbound",
            content_blake3=tt_bundle["content_blake3"],
            status="staged",
            canonical_id=cid,
        )
        ledger.record(
            channel="blog_manifest",
            item_id=sid,
            direction="outbound",
            content_blake3=blog_blake3,
            status="staged",
            canonical_id=cid,
        )

        catalog_studies.append(
            {
                "id": sid,
                "title": study["title"],
                "short_title": study["short_title"],
                "category": study["category"],
                "headline_metric": study["headline_metric"],
                "epistemic_tags": study["epistemic_tags"],
                "canonical_id": cid,
                "paper_url": study["paper_url"],
                "pdf_url": study["pdf_url"],
                "poster_url": study["poster_url"],
                "tv_url": f"/tv/?study={sid}",
                "energy_tier": study["energy_tier"],
                "energy_disclosure": study["energy_disclosure"],
                "energy_cost_j": energy_obj,
                "short_vertical_9x16": short_9x16_proj,
                "medium": {
                    **med_proj,
                    "subtitle": med_bundle["subtitle"],
                    "tags": med_bundle["tags"],
                    "resolved_x_thread_url": med_bundle["resolved_x_thread_url"],
                    "blog_manifest_uri": f"/syndication/blog-manifests/{sid}.yaml",
                    "blog_manifest_blake3": blog_blake3,
                    "content_blake3": med_bundle["content_blake3"],
                },
                "x_thread": {
                    **x_proj,
                    "zero_urls_in_post_1": x_bundle["zero_urls_in_post_1"],
                    "content_blake3": x_bundle["content_blake3"],
                    "posts": x_bundle["posts"],
                },
                "tiktok": {
                    "bundle_uri": f"/syndication/tiktok/{sid}.json",
                    "video_uri": tt_bundle["short_vertical_9x16"]["video_uri"],
                    "fallback_video_uri": tt_bundle["short_vertical_9x16"]["fallback_video_uri"],
                    "pull_url": tt_bundle["api_v2_init_payload"]["source_info"]["video_url"],
                    "caption_utf16_chars": tt_bundle["caption_utf16_chars"],
                    "privacy_level": tt_bundle["api_v2_init_payload"]["post_info"]["privacy_level"],
                    "is_aigc": tt_bundle["api_v2_init_payload"]["post_info"]["is_aigc"],
                    "content_blake3": tt_bundle["content_blake3"],
                },
                "syndication_channels": chan_proj,
            }
        )

    ledger_dict = ledger.to_dict()
    ledger_digest = ledger.ledger_blake3()

    # Write public/syndication/ecosystem-matrix.json
    eco_doc = {
        **ecosystem_matrix,
        "study_count": len(catalog_studies),
        "x_post_count_total": total_tweets,
        "x_max_weighted_chars_observed": global_max_weighted,
        "ledger_blake3": ledger_digest,
    }
    eco_doc["matrix_blake3"] = compute_bundle_blake3(eco_doc)
    (pub_synd / "ecosystem-matrix.json").write_text(
        json.dumps(eco_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    # Write src/data/syndication-catalog.json
    syndication_catalog = {
        "schema": "openie.syndication_catalog.v1",
        "version": "1.0.0",
        "updated": "2026-11-24",
        "human_in_gate": False,
        "license": {
            "summaries_articles_threads": "CC0-1.0",
            "code_schema_envelopes": "Apache-2.0",
        },
        "summary_metrics": {
            "study_count": len(catalog_studies),
            "medium_articles_count": len(catalog_studies),
            "blog_manifests_count": len(catalog_studies),
            "x_threads_count": len(catalog_studies),
            "x_posts_total": total_tweets,
            "x_max_weighted_chars_limit": X_MAX_WEIGHTED_CHARS,
            "x_max_weighted_chars_observed": global_max_weighted,
            "tiktok_bundles_count": len(catalog_studies),
            "ecosystem_tiers_count": ecosystem_matrix["tier_count"],
            "ecosystem_entries_count": ecosystem_matrix["ecosystem_entry_count"],
            "publishos_literary_archives_count": ecosystem_matrix[
                "publishos_literary_archive_count"
            ],
            "parliaments_count": ecosystem_matrix["parliaments_count"],
        },
        "bidirectional_flows": {
            "forward_canonical_to_medium_and_x": {
                "direction": "outbound",
                "steps": [
                    "1. Project verified WAI1 / TV study into CC0-1.0 Medium essay (`public/syndication/medium/<id>.md`) + `blog.openie.dev` YAML manifest.",
                    "2. Publish Medium essay (REST v1 or Canonical `<link rel=\"canonical\">` Story Import) and capture live `medium.com` URL.",
                    "3. Update Post 5 of the 5-tweet X bundle (`<= 280` weighted chars, 0 URLs in Post 1 + native 9:16 snackable video card).",
                    "4. Upload 9:16 MP4 via OAuth 1.0a chunked upload and chain all 5 tweets via `POST /2/tweets`; resolve `{{X_THREAD_URL}}` backlink in ledger.",
                ],
            },
            "reverse_1_medium_rss_to_x": {
                "entrypoint": "openie_syndicate.sync_medium_rss_to_x",
                "direction": "bidirectional",
                "deduplication": "BLAKE3 over normalized `(guid, link, title)` in `SyndicationLedger`",
                "behavior": "Maps `<link rel=\"canonical\">` OpenIE essays to verified 5-post study threads or synthesizes a 4-post thread for standalone essays.",
            },
            "reverse_2_x_timeline_to_medium": {
                "entrypoint": "openie_syndicate.sync_x_threads_to_medium",
                "direction": "bidirectional",
                "deduplication": "BLAKE3 over `(root_tweet_id, self_reply_texts)` in `SyndicationLedger`",
                "behavior": "Groups X self-reply threads, compiles an illustrated CC0-1.0 Medium digest with `canonicalUrl`, and replies on the X thread root with the live Medium URL.",
            },
        },
        "ledger": {
            "ledger_blake3": ledger_digest,
            "entry_count": ledger_dict["entry_count"],
            "entries": ledger_dict["entries"],
        },
        "ecosystems": ecosystem_matrix,
        "studies": catalog_studies,
    }
    syndication_catalog["catalog_blake3"] = compute_bundle_blake3(syndication_catalog)
    (data_dir / "syndication-catalog.json").write_text(
        json.dumps(syndication_catalog, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return syndication_catalog


def verify_staged(web_root: Path) -> None:
    cat_path = web_root / "src" / "data" / "syndication-catalog.json"
    cat = json.loads(cat_path.read_text(encoding="utf-8"))
    assert cat["summary_metrics"]["study_count"] == 28
    assert cat["summary_metrics"]["x_posts_total"] == 140
    for st in cat["studies"]:
        sid = st["id"]
        assert (web_root / "public" / "syndication" / "medium" / f"{sid}.md").is_file()
        assert (web_root / "public" / "syndication" / "x" / f"{sid}.json").is_file()
        assert (web_root / "public" / "syndication" / "tiktok" / f"{sid}.json").is_file()
        assert (web_root / "public" / "syndication" / "blog-manifests" / f"{sid}.yaml").is_file()
        for post in st["x_thread"]["posts"]:
            assert weighted_len(post["text"]) <= X_MAX_WEIGHTED_CHARS
            if post["position"] == 1:
                assert len(post["urls"]) == 0
    assert (web_root / "public" / "syndication" / "ecosystem-matrix.json").is_file()


def publish_live_study(
    *,
    web_root: Path,
    study_id: str,
    ledger_path: Path,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Coordinate live outbound Medium -> X -> TikTok publication for one study."""
    ledger = SyndicationLedger.load(ledger_path)
    cat = json.loads((web_root / "src" / "data" / "syndication-catalog.json").read_text("utf-8"))
    study_entry = next(s for s in cat["studies"] if s["id"] == study_id)

    md_path = web_root / "public" / "syndication" / "medium" / f"{study_id}.md"
    x_path = web_root / "public" / "syndication" / "x" / f"{study_id}.json"
    tt_path = web_root / "public" / "syndication" / "tiktok" / f"{study_id}.json"

    md_text = md_path.read_text(encoding="utf-8")
    x_bundle = json.loads(x_path.read_text(encoding="utf-8"))
    tt_bundle = json.loads(tt_path.read_text(encoding="utf-8"))

    med_client = MediumClient()
    x_client = XClient()
    tt_client = TikTokClient()

    live_medium_url = x_bundle["medium_crosslink_uri"]
    if not dry_run and med_client.is_configured():
        med_data = med_client.publish_markdown_post(
            title=study_entry["title"],
            content_markdown=md_text,
            canonical_url=study_entry["medium"]["canonical_source_url"],
            tags=study_entry["medium"]["tags"],
        )
        live_medium_url = str(med_data["url"])
        x_bundle = update_x_bundle_medium_url(x_bundle, live_medium_url)

    live_x_url = study_entry["medium"]["resolved_x_thread_url"]
    if not dry_run and x_client.credentials.is_configured():
        media_id: str | None = None
        mp4_candidate = web_root / "public" / x_bundle["card_video_uri"].lstrip("/")
        if mp4_candidate.is_file():
            media_id = x_client.upload_video_chunked(mp4_candidate.read_bytes())
        tids = x_client.post_thread(x_bundle, first_post_media_id=media_id)
        live_x_url = f"https://x.com/i/status/{tids[0]}"
        md_text = resolve_medium_x_backlink(
            md_text, study_id, study_entry["short_title"], live_x_url
        )

    tt_res = tt_client.publish_pull_from_url(tt_bundle, ledger=ledger, dry_run=dry_run)
    ledger.save(ledger_path)
    return {
        "study_id": study_id,
        "dry_run": dry_run,
        "medium_url": live_medium_url,
        "x_thread_url": live_x_url,
        "tiktok": tt_res,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="OpenIE Deterministic X <-> Medium & Multi-Ecosystem Syndication Engine"
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=["stage", "verify", "publish", "sync-rss-to-x", "sync-x-to-medium"],
    )
    parser.add_argument("--tv-catalog", type=Path, help="Path to tv-catalog.json")
    parser.add_argument(
        "--substrate-catalog",
        type=Path,
        default=REPO_ROOT / "catalog" / "unsiloed-artifacts.jsonl",
        help="Path to unsiloed-artifacts.jsonl",
    )
    parser.add_argument("--web-root", type=Path, help="Path to research-openie-web root")
    parser.add_argument("--study-id", type=str, help="Study ID for --mode publish")
    parser.add_argument(
        "--ledger",
        type=Path,
        default=Path("syndication-ledger.json"),
        help="Path to idempotent BLAKE3 syndication ledger JSON",
    )
    parser.add_argument(
        "--rss-url",
        type=str,
        default=os.environ.get("MEDIUM_RSS_URL", ",".join(DEFAULT_MEDIUM_RSS_FEEDS)),
        help="Comma-separated Medium RSS URLs (defaults to open-interface-engineering & @openie)",
    )
    parser.add_argument("--timeline-json", type=Path, help="Local X timeline/pulse JSON file")
    parser.add_argument("--outbox", type=Path, help="Optional JSON outbox for staged RSS->X threads")
    parser.add_argument("--live", action="store_true", help="Disable dry-run and execute live HTTP calls")
    parser.add_argument(
        "--auto-live",
        action="store_true",
        help="Automatically switch to live posting when X OAuth 1.0a credentials are present in env",
    )

    args = parser.parse_args(argv)
    x_probe = XClient()
    dry_run = not (args.live or (args.auto_live and x_probe.credentials.is_configured()))

    if args.mode == "stage":
        if not args.tv_catalog or not args.web_root:
            parser.error("--mode stage requires --tv-catalog and --web-root")
        cat = stage_all(
            tv_catalog_path=args.tv_catalog,
            substrate_jsonl_path=args.substrate_catalog,
            web_root=args.web_root,
        )
        verify_staged(args.web_root)
        m = cat["summary_metrics"]
        print(
            f"OK: Staged {m['study_count']} Medium essays, {m['x_posts_total']} X posts "
            f"(max weighted={m['x_max_weighted_chars_observed']}/280), "
            f"{m['tiktok_bundles_count']} TikTok v2 bundles, {m['blog_manifests_count']} blog manifests, "
            f"and {m['ecosystem_entries_count']} ecosystem channels across {m['ecosystem_tiers_count']} tiers."
        )
        return 0

    if args.mode == "verify":
        if not args.web_root:
            parser.error("--mode verify requires --web-root")
        verify_staged(args.web_root)
        print("OK: Verified all staged OpenIE syndication artifacts.")
        return 0

    if args.mode == "publish":
        if not args.web_root or not args.study_id:
            parser.error("--mode publish requires --web-root and --study-id")
        res = publish_live_study(
            web_root=args.web_root,
            study_id=args.study_id,
            ledger_path=args.ledger,
            dry_run=dry_run,
        )
        print(json.dumps(res, indent=2))
        return 0

    if args.mode == "sync-rss-to-x":
        if not args.rss_url:
            parser.error("--mode sync-rss-to-x requires --rss-url or MEDIUM_RSS_URL")
        ledger = SyndicationLedger.load(args.ledger)
        by_paper: dict[str, dict[str, Any]] = {}
        by_title: dict[str, dict[str, Any]] = {}
        if args.web_root:
            cat_file = args.web_root / "src" / "data" / "syndication-catalog.json"
            x_dir = args.web_root / "public" / "syndication" / "x"
            if cat_file.is_file():
                cat_doc = json.loads(cat_file.read_text(encoding="utf-8"))
                for st in cat_doc.get("studies", []):
                    xb_path = x_dir / f"{st['id']}.json"
                    if xb_path.is_file():
                        xb = json.loads(xb_path.read_text(encoding="utf-8"))
                        canon = st.get("medium", {}).get("canonical_source_url", "")
                        if canon:
                            by_paper[canon] = xb
                        prim = st.get("medium", {}).get("primary_paper_url", "") or (
                            f"https://research.openie.dev{st['paper_url']}" if st.get("paper_url") else ""
                        )
                        if prim:
                            by_paper[prim if prim.endswith("/") else f"{prim}/"] = xb
                        by_paper[f"https://blog.openie.dev/posts/{st['id']}/"] = xb
                        by_paper[f"https://research.openie.dev/syndication/medium/{st['id']}/"] = xb
                        by_title[str(st.get("title", "")).strip().lower()] = xb
                        by_title[str(st.get("short_title", "")).strip().lower()] = xb

        def _load_video_bytes(card_uri: str) -> bytes | None:
            if not args.web_root:
                return None
            cand = args.web_root / "public" / card_uri.lstrip("/")
            return cand.read_bytes() if cand.is_file() else None

        feed_urls = [u.strip() for u in args.rss_url.split(",") if u.strip()]
        all_res: list[dict[str, Any]] = []
        for feed_u in feed_urls:
            res = sync_medium_rss_to_x(
                feed_u,
                ledger=ledger,
                x_bundles_by_paper_url=by_paper,
                x_bundles_by_title=by_title,
                video_bytes_loader=_load_video_bytes,
                x_client=x_probe,
                dry_run=dry_run,
            )
            all_res.extend(res)
        ledger.save(args.ledger)
        if args.outbox:
            args.outbox.parent.mkdir(parents=True, exist_ok=True)
            args.outbox.write_text(json.dumps(all_res, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(
            json.dumps(
                {
                    "feeds_polled": feed_urls,
                    "items_processed": len(all_res),
                    "new_threads": sum(1 for r in all_res if r.get("status") != "skipped_duplicate"),
                    "dry_run": dry_run,
                },
                indent=2,
            )
        )
        return 0

    if args.mode == "sync-x-to-medium":
        ledger = SyndicationLedger.load(args.ledger)
        if args.timeline_json:
            tweets = json.loads(args.timeline_json.read_text(encoding="utf-8"))
            if isinstance(tweets, dict):
                tweets = tweets.get("data", tweets.get("tweets", []))
        else:
            parser.error("--mode sync-x-to-medium requires --timeline-json")
        res = sync_x_threads_to_medium(
            tweets,
            ledger=ledger,
            medium_client=MediumClient(),
            x_client=XClient(),
            dry_run=dry_run,
        )
        ledger.save(args.ledger)
        print(json.dumps({"synced": len(res), "dry_run": dry_run}, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
