# SPDX-License-Identifier: Apache-2.0
"""Unit & conformance tests for `openie_syndicate` (`X <-> Medium`, `TikTok v2`, `OAuth 1.0a`, `Mirrors`)."""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path
from typing import Any

from openie_syndicate import (
    BlueskyATProtoMirror,
    InternetArchiveMirror,
    MastodonMirror,
    MediumClient,
    OAuth1Credentials,
    SyndicationLedger,
    TikTokClient,
    X_MAX_WEIGHTED_CHARS,
    XClient,
    build_bluesky_facets,
    build_canonical_import_html,
    build_ecosystem_matrix,
    build_oauth1_authorization_header,
    build_signature_base_string,
    compose_blog_manifest_yaml,
    compose_medium_article,
    compose_tiktok_bundle,
    compose_x_thread,
    compute_bundle_blake3,
    parse_medium_rss_xml,
    resolve_medium_x_backlink,
    sign_hmac_sha1,
    sync_medium_rss_to_x,
    sync_x_threads_to_medium,
    update_x_bundle_medium_url,
    validate_tiktok_init_payload,
    weighted_len,
)
from openie_syndicate.oauth1 import parse_form_urlencoded

SAMPLE_STUDY: dict[str, Any] = {
    "id": "gates",
    "title": "Metered Commit Gates: Energy-to-Correct-Completion for Agentic Systems",
    "short_title": "Metered Commit Gates",
    "category": "Foundations & Thermodynamics",
    "paper_url": "/papers/gates/",
    "pdf_url": "/pdfs/gates.pdf",
    "poster_url": "/media/tv/posters/gates-poster.jpg",
    "headline_metric": "11,428 Picojoules per Hardware Gate Check",
    "epistemic_tags": ["T", "E"],
    "energy_tier": "Board Power Sensor",
    "energy_disclosure": "Direct circuit-board power sensor on vision module; software runs stay estimates.",
    "plain_bullets": [
        "A computer should not take an irreversible action until an independent check confirms it is safe.",
        "It should try the cheapest method first and wake a large AI model only when simpler tools miss.",
        "Every decision is written to a receipt with the energy it used, so anyone can audit it later.",
    ],
    "tiers": {
        "15s": {
            "video_url": "/media/tv/films/gates-15s.mp4",
            "vtt_url": "/media/tv/captions/gates-15s.vtt",
            "duration_s": 21.87,
            "sha256": "f29dda7b557d9212cb245561454aafc08a84d747ab58506834ef0ea273679c30",
            "hook": "Why computers must check before taking undoable actions, start with the cheapest tool, and log every joule.",
            "transcript": "First, a computer should not take an irreversible action until an independent check confirms it is safe. Second, it should try the cheapest method first and wake a large AI model only when simpler tools miss. Third, every decision is written to a receipt with the energy it used, so anyone can audit it later.",
        },
        "45s": {
            "transcript": "First, a computer should not take an irreversible action until an independent check confirms it is safe. Second, it should try the cheapest method first and wake a large AI model only when simpler tools miss. Third, every decision is written to a receipt with the energy it used, so anyone can audit it later. A commit gate acts like a physical cockpit lock that blocks unsafe switches before anything moves."
        },
        "90s": {
            "transcript": "First, a computer should not take an irreversible action until an independent check confirms it is safe. Second, it should try the cheapest method first and wake a large AI model only when simpler tools miss. Third, every decision is written to a receipt with the energy it used, so anyone can audit it later. Across more than two hundred nine thousand simulated control checks, the discrete safety gate allowed zero unsafe actions."
        },
        "180s": {
            "transcript": "First, a computer should not take an irreversible action until an independent check confirms it is safe. Second, it should try the cheapest method first and wake a large AI model only when simpler tools miss. Third, every decision is written to a receipt with the energy it used, so anyone can audit it later. Every irreversible action passes through four strict runtime records in our Rust reference implementation while physical shunt sensors measure real module supply power."
        },
    },
}

SAMPLE_SUBSTRATE_REC: dict[str, Any] = {
    "canonical_id": "blake3:tv:" + ("a" * 64),
    "energy_cost_j": {
        "evidence_class": "measured_j",
        "joules": 11.428e-9,
        "meter_or_formula": "AMD Kria KV260 whole-module physical board power shunt",
        "board_metered": True,
        "landauer_300k_bits_equiv": 3.980589e12,
    },
    "verification_status": {
        "human_in_gate": False,
        "scientific_gate": {
            "passed": True,
            "lean_kernel_checked": True,
            "sat_miter_digest": "b" * 64,
        },
    },
    "interchange_envelope": {
        "envelope_blake3": "c" * 64,
        "envelope_bytes": 15000,
        "envelope_uri": "catalog/envelopes/tv-gates.wai",
    },
}


class TestOAuth1AndWeightedCounter(unittest.TestCase):
    def test_rfc5849_section_3_4_1_signature_base_string_and_hmac_sha1_vectors(self) -> None:
        # Official RFC 5849 §3.4.1.1 / §3.4.1.3.2 Normalization & Signature Base String Test Vector
        url = "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b"
        body_params = parse_form_urlencoded("c2&a3=2+q")
        oauth_params = [
            ("oauth_consumer_key", "9djdj82h48djs9d2"),
            ("oauth_token", "kkk9d7dh3k39sjv7"),
            ("oauth_signature_method", "HMAC-SHA1"),
            ("oauth_timestamp", "137131201"),
            ("oauth_nonce", "7d8f3e4a"),
        ]
        base_str = build_signature_base_string(
            method="POST",
            url=url,
            oauth_params=oauth_params,
            body_form_params=body_params,
        )
        expected_rfc5849_base = (
            "POST&http%3A%2F%2Fexample.com%2Frequest&"
            "a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26"
            "c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26"
            "oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26"
            "oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7"
        )
        self.assertEqual(base_str, expected_rfc5849_base)
        # RFC 5849 §3.4.2 HMAC-SHA1 signature with secrets j49sk3j29djd & dh893hdasih9 -> r6/TJjbCOr97/+UU0NsvSne7s5g=
        sig_rfc5849 = sign_hmac_sha1(base_str, "j49sk3j29djd", "dh893hdasih9")
        self.assertEqual(sig_rfc5849, "r6/TJjbCOr97/+UU0NsvSne7s5g=")

        # OAuth 1.0a Appendix A.5.1 / A.5.2 canonical HMAC-SHA1 test vector -> tR3+Ty81lMeYAr/Fid0kMTYa/WM=
        base_a5 = build_signature_base_string(
            method="GET",
            url="http://photos.example.net/photos?file=vacation.jpg&size=original",
            oauth_params=[
                ("oauth_consumer_key", "dpf43f3p2l4k3l03"),
                ("oauth_token", "nnch734d00sl2jdk"),
                ("oauth_signature_method", "HMAC-SHA1"),
                ("oauth_timestamp", "1191242096"),
                ("oauth_nonce", "kllo9940pd9333jh"),
                ("oauth_version", "1.0"),
            ],
        )
        self.assertEqual(
            sign_hmac_sha1(base_a5, "kd94hf93k423kf44", "pfkkdhi9sl3r4s00"),
            "tR3+Ty81lMeYAr/Fid0kMTYa/WM=",
        )

        # Verify full Authorization header construction
        creds = OAuth1Credentials(
            api_key="dpf43f3p2l4k3l03",
            api_secret="kd94hf93k423kf44",
            access_token="nnch734d00sl2jdk",
            access_token_secret="pfkkdhi9sl3r4s00",
        )
        hdr = build_oauth1_authorization_header(
            method="GET",
            url="http://photos.example.net/photos?file=vacation.jpg&size=original",
            credentials=creds,
            timestamp="1191242096",
            nonce="kllo9940pd9333jh",
            version="1.0",
        )
        self.assertIn('oauth_signature="tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D"', hdr)

    def test_x_weighted_280_char_counter(self) -> None:
        # Every https:// URL counts as exactly 23 weighted chars regardless of length
        long_url = "https://research.openie.dev/papers/communication-avalanche/?ref=very-long-parameter-value-1234567890"
        self.assertGreater(len(long_url), 90)
        self.assertEqual(weighted_len(long_url), 23)
        self.assertEqual(weighted_len(f"Read {long_url}."), 5 + 23 + 1)
        # CJK / emoji characters count as weight 2
        self.assertEqual(weighted_len("🚀"), 2)
        self.assertEqual(weighted_len("A🚀B"), 4)


class TestBidirectionalXMediumAndTikTok(unittest.TestCase):
    def test_forward_medium_blog_and_x_thread_generation(self) -> None:
        ledger = SyndicationLedger()
        med = compose_medium_article(SAMPLE_STUDY, SAMPLE_SUBSTRATE_REC, ledger=ledger)
        self.assertIn("**Canonical Primary Source**: [https://research.openie.dev/papers/gates/]", med["markdown"])
        self.assertIn("## Three Plain-Language Takeaways (Zero Acronym Soup)", med["markdown"])
        self.assertIn("## Everyday Analogy & Why It Matters", med["markdown"])
        self.assertIn("## Inside the Mechanism & Candid Limits", med["markdown"])
        self.assertIn("## How Energy Was Metered", med["markdown"])
        self.assertIn("`measured_j`", med["markdown"])
        self.assertEqual(med["license"], "CC0-1.0")

        # Canonical import HTML companion has <link rel="canonical">
        imp_html = build_canonical_import_html(med)
        self.assertIn('<link rel="canonical" href="https://research.openie.dev/papers/gates/" />', imp_html)

        # Blog manifest YAML conforms to build-post.js fields & valid categories
        yaml_text = compose_blog_manifest_yaml(SAMPLE_STUDY, SAMPLE_SUBSTRATE_REC)
        self.assertIn('slug: "gates"', yaml_text)
        self.assertIn('category: "energy"', yaml_text)
        self.assertIn("sections:", yaml_text)

        # X 5-post thread
        x_bundle = compose_x_thread(SAMPLE_STUDY, SAMPLE_SUBSTRATE_REC)
        self.assertEqual(x_bundle["post_count"], 5)
        self.assertTrue(x_bundle["zero_urls_in_post_1"])
        self.assertNotIn("http", x_bundle["posts"][0]["text"].lower())
        for post in x_bundle["posts"]:
            self.assertLessEqual(post["weighted_chars"], X_MAX_WEIGHTED_CHARS)
            self.assertEqual(post["weighted_chars"], weighted_len(post["text"]))

        # Dynamic Medium live URL update keeps weighted_chars identical (23 -> 23) and <= 280
        live_med = "https://medium.com/@openie/metered-commit-gates-9f8e7d6c5b4a"
        x_updated = update_x_bundle_medium_url(x_bundle, live_med)
        self.assertIn(live_med, x_updated["posts"][4]["text"])
        self.assertEqual(
            x_updated["posts"][4]["weighted_chars"],
            x_bundle["posts"][4]["weighted_chars"],
        )

        # Dynamic X thread backlink resolution in Medium Markdown
        resolved_md = resolve_medium_x_backlink(
            med["markdown"], "gates", "Metered Commit Gates", "https://x.com/i/status/1999888777"
        )
        self.assertIn("https://x.com/i/status/1999888777", resolved_md)

    def test_live_x_chunked_upload_and_chained_thread_mock_transport(self) -> None:
        calls: list[tuple[str, str, dict[str, str], bytes | None]] = []

        def fake_transport(
            method: str, url: str, headers: dict[str, str], body: bytes | None
        ) -> tuple[int, dict[str, str], bytes]:
            calls.append((method, url, headers, body))
            if "upload.twitter.com" in url:
                if method == "GET" and "command=STATUS" in url:
                    return 200, {}, json.dumps({"processing_info": {"state": "succeeded"}}).encode()
                if body and b"command=INIT" in body:
                    return 200, {}, json.dumps({"media_id_string": "media_999"}).encode()
                if body and b"command=FINALIZE" in body:
                    return (
                        200,
                        {},
                        json.dumps(
                            {"media_id_string": "media_999", "processing_info": {"state": "pending", "check_after_secs": 0}}
                        ).encode(),
                    )
                return 204, {}, b""
            if url == "https://api.x.com/2/tweets":
                idx = sum(1 for c in calls if c[1] == "https://api.x.com/2/tweets")
                return 201, {}, json.dumps({"data": {"id": f"tweet_{idx}"}}).encode()
            raise AssertionError(f"Unexpected URL {url}")

        creds = OAuth1Credentials("k", "s", "t", "ts")
        client = XClient(credentials=creds, transport=fake_transport, sleep_fn=lambda _: None)
        mid = client.upload_video_chunked(b"0123456789" * 50, chunk_size=200)
        self.assertEqual(mid, "media_999")

        x_bundle = compose_x_thread(SAMPLE_STUDY, SAMPLE_SUBSTRATE_REC)
        tids = client.post_thread(x_bundle, first_post_media_id=mid)
        self.assertEqual(tids, ["tweet_1", "tweet_2", "tweet_3", "tweet_4", "tweet_5"])

        tweet_bodies = [
            json.loads((c[3] or b"{}").decode("utf-8"))
            for c in calls
            if c[1] == "https://api.x.com/2/tweets"
        ]
        self.assertEqual(tweet_bodies[0]["media"]["media_ids"], ["media_999"])
        self.assertNotIn("reply", tweet_bodies[0])
        self.assertEqual(tweet_bodies[1]["reply"]["in_reply_to_tweet_id"], "tweet_1")
        self.assertEqual(tweet_bodies[4]["reply"]["in_reply_to_tweet_id"], "tweet_4")

    def test_reverse_flow_1_medium_rss_to_x_and_blake3_deduplication(self) -> None:
        rss_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/" xmlns:dc="http://purl.org/dc/elements/1.1/">
          <channel>
            <title>OpenIE Medium Feed</title>
            <item>
              <title>Metered Commit Gates</title>
              <link>https://medium.com/@openie/metered-commit-gates-abc123?source=rss-xyz</link>
              <guid isPermaLink="false">https://medium.com/p/abc123</guid>
              <category>open-science</category>
              <content:encoded><![CDATA[<p>Canonical Primary Source: https://research.openie.dev/papers/gates/</p><p>Safety gates check before irreversible actions.</p>]]></content:encoded>
            </item>
            <item>
              <title>Standalone Field Note on Joule Budgets</title>
              <link>https://medium.com/@openie/standalone-joule-note-def456</link>
              <guid isPermaLink="false">https://medium.com/p/def456</guid>
              <category>energy</category>
              <category>verification</category>
              <content:encoded><![CDATA[<p>Every autonomous loop should declare an explicit joule ceiling up front. Independent deterministic checks catch unsafe actions before external state mutates. Refusal receipts make budget exhaustion auditable rather than silent. Dedicated to the public domain under CC0-1.0.</p>]]></content:encoded>
            </item>
          </channel>
        </rss>"""

        parsed = parse_medium_rss_xml(rss_xml)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["canonical_openie_url"], "https://research.openie.dev/papers/gates/")

        gates_bundle = compose_x_thread(SAMPLE_STUDY, SAMPLE_SUBSTRATE_REC)
        ledger = SyndicationLedger()
        first_run = sync_medium_rss_to_x(
            rss_xml,
            ledger=ledger,
            x_bundles_by_paper_url={"https://research.openie.dev/papers/gates/": gates_bundle},
            dry_run=True,
        )
        self.assertEqual(len(first_run), 2)
        self.assertEqual(first_run[0]["matched_study_id"], "gates")
        self.assertEqual(first_run[0]["thread_bundle"]["post_count"], 5)
        self.assertIn(
            "https://medium.com/@openie/metered-commit-gates-abc123",
            first_run[0]["thread_bundle"]["posts"][4]["text"],
        )
        # Standalone Medium essay synthesizes a clean 4-tweet thread
        self.assertIsNone(first_run[1]["matched_study_id"])
        self.assertEqual(first_run[1]["thread_bundle"]["post_count"], 4)
        for p in first_run[1]["thread_bundle"]["posts"]:
            self.assertLessEqual(p["weighted_chars"], X_MAX_WEIGHTED_CHARS)

        # Second run on identical RSS XML must skip 100% as BLAKE3 duplicates!
        second_run = sync_medium_rss_to_x(
            rss_xml,
            ledger=ledger,
            x_bundles_by_paper_url={"https://research.openie.dev/papers/gates/": gates_bundle},
            dry_run=True,
        )
        self.assertTrue(all(r["status"] == "skipped_duplicate" for r in second_run))
        # Medium-first live URL tracking works even when dry_run=True (zero X credentials)
        self.assertEqual(
            ledger.medium_live_urls["gates"],
            "https://medium.com/@openie/metered-commit-gates-abc123",
        )
        self.assertEqual(
            ledger.medium_live_urls["https://medium.com/p/def456"],
            "https://medium.com/@openie/standalone-joule-note-def456",
        )

    def test_medium_first_57_chronicle_slug_matching_and_medium_url_normalization(self) -> None:
        rss_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
          <channel>
            <title>Open Interface Engineering on Medium</title>
            <item>
              <title>The Hidden Energy Crisis at Every Interface</title>
              <link>https://medium.com/open-interface-engineering/the-hidden-energy-crisis-111aaa?source=rss-pub</link>
              <guid isPermaLink="false">https://medium.com/p/111aaa</guid>
              <category>energy-efficiency</category>
              <content:encoded><![CDATA[<p>Imported via https://blog.openie.dev/medium/the-hidden-energy-crisis-at-every-interface</p>]]></content:encoded>
            </item>
            <item>
              <title>Bounded Entropy in Formal Languages: A Mathematical Foundation for Deterministic Code Generation</title>
              <link>https://medium.com/open-interface-engineering/bounded-entropy-222bbb?source=rss-pub</link>
              <guid isPermaLink="false">https://medium.com/p/222bbb</guid>
              <category>whitepaper</category>
              <content:encoded><![CDATA[<p>Canonical OpenIE Chronicle Entry: https://blog.openie.dev/posts/wp-bounded-entropy-code-generation/</p>]]></content:encoded>
            </item>
            <item>
              <title>Every Query Has a Cost in Joules</title>
              <link>https://medium.com/@openie/every-query-has-a-cost-in-joules-333ccc</link>
              <guid isPermaLink="false">https://medium.com/p/333ccc</guid>
              <category>databases</category>
              <content:encoded><![CDATA[<p>Every database operation is a physical event.</p>]]></content:encoded>
            </item>
          </channel>
        </rss>"""

        parsed = parse_medium_rss_xml(rss_xml)
        self.assertEqual(len(parsed), 3)
        # /medium/<slug> must normalize cleanly to /posts/<slug>/!
        self.assertEqual(
            parsed[0]["canonical_openie_url"],
            "https://blog.openie.dev/posts/the-hidden-energy-crisis-at-every-interface/",
        )
        self.assertEqual(
            parsed[1]["canonical_openie_url"],
            "https://blog.openie.dev/posts/wp-bounded-entropy-code-generation/",
        )
        self.assertIsNone(parsed[2]["canonical_openie_url"])

        ledger = SyndicationLedger()
        out = sync_medium_rss_to_x(
            rss_xml,
            ledger=ledger,
            chronicle_slugs_by_title={
                "every query has a cost in joules": "every-query-has-a-cost-in-joules"
            },
            dry_run=True,
        )
        self.assertEqual(len(out), 3)
        self.assertEqual(
            ledger.medium_live_urls["the-hidden-energy-crisis-at-every-interface"],
            "https://medium.com/open-interface-engineering/the-hidden-energy-crisis-111aaa",
        )
        self.assertEqual(
            ledger.medium_live_urls["wp-bounded-entropy-code-generation"],
            "https://medium.com/open-interface-engineering/bounded-entropy-222bbb",
        )
        self.assertEqual(
            ledger.medium_live_urls["every-query-has-a-cost-in-joules"],
            "https://medium.com/@openie/every-query-has-a-cost-in-joules-333ccc",
        )

    def test_reverse_flow_2_x_threads_to_medium_and_root_reply(self) -> None:
        timeline = [
            {
                "id": "1001",
                "conversation_id": "1001",
                "author_id": "u_openie",
                "created_at": "2026-11-24T12:00:00Z",
                "text": "Metered Commit Gates in 60 seconds\nWhy computers must check before undoable actions.",
            },
            {
                "id": "1002",
                "conversation_id": "1001",
                "author_id": "u_openie",
                "in_reply_to_user_id": "u_openie",
                "created_at": "2026-11-24T12:01:00Z",
                "text": "1/2 Try lookup tables and exact solvers before waking a neural model.",
            },
            {
                "id": "1003",
                "conversation_id": "1001",
                "author_id": "u_openie",
                "in_reply_to_user_id": "u_openie",
                "created_at": "2026-11-24T12:02:00Z",
                "text": "2/2 Full paper & hardware receipts: https://research.openie.dev/papers/gates/",
            },
            # External commenter reply (must be excluded from self-reply thread!)
            {
                "id": "1004",
                "conversation_id": "1001",
                "author_id": "u_someone_else",
                "in_reply_to_user_id": "u_openie",
                "created_at": "2026-11-24T12:05:00Z",
                "text": "Great thread!",
            },
        ]

        replies_sent: list[dict[str, Any]] = []

        def fake_med_transport(
            method: str, url: str, headers: dict[str, str], body: bytes | None
        ) -> tuple[int, dict[str, str], bytes]:
            if url.endswith("/me"):
                return 200, {}, json.dumps({"data": {"id": "author_42"}}).encode()
            return (
                201,
                {},
                json.dumps(
                    {"data": {"id": "mpost_1", "url": "https://medium.com/@openie/compiled-gates-1001"}}
                ).encode(),
            )

        def fake_x_transport(
            method: str, url: str, headers: dict[str, str], body: bytes | None
        ) -> tuple[int, dict[str, str], bytes]:
            replies_sent.append(json.loads((body or b"{}").decode("utf-8")))
            return 201, {}, json.dumps({"data": {"id": "reply_9001"}}).encode()

        ledger = SyndicationLedger()
        med_client = MediumClient(integration_token="tok_test", transport=fake_med_transport)
        x_client = XClient(
            credentials=OAuth1Credentials("k", "s", "t", "ts"),
            transport=fake_x_transport,
        )

        out = sync_x_threads_to_medium(
            timeline,
            ledger=ledger,
            medium_client=med_client,
            x_client=x_client,
            dry_run=False,
        )
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["status"], "published")
        self.assertEqual(out[0]["medium_url"], "https://medium.com/@openie/compiled-gates-1001")
        self.assertEqual(out[0]["compiled_essay"]["canonical_url"], "https://research.openie.dev/papers/gates/")
        self.assertNotIn("Great thread!", out[0]["compiled_essay"]["markdown"])
        self.assertEqual(replies_sent[0]["reply"]["in_reply_to_tweet_id"], "1001")
        self.assertLessEqual(out[0]["reply_weighted_chars"], X_MAX_WEIGHTED_CHARS)

        # Idempotent re-run skips duplicate
        out_dup = sync_x_threads_to_medium(
            timeline,
            ledger=ledger,
            medium_client=med_client,
            x_client=x_client,
            dry_run=False,
        )
        self.assertEqual(out_dup[0]["status"], "skipped_duplicate")

    def test_tiktok_v2_payload_validator_and_idempotency(self) -> None:
        tt_bundle = compose_tiktok_bundle(SAMPLE_STUDY, SAMPLE_SUBSTRATE_REC)
        validate_tiktok_init_payload(tt_bundle["api_v2_init_payload"])

        # Reject invalid source or broken chunk count
        bad = json.loads(json.dumps(tt_bundle["api_v2_init_payload"]))
        bad["source_info"] = {
            "source": "FILE_UPLOAD",
            "video_size": 25_000_000,
            "chunk_size": 10_000_000,
            "total_chunk_count": 2,  # should be 3!
        }
        with self.assertRaises(ValueError):
            validate_tiktok_init_payload(bad)

        ledger = SyndicationLedger()
        client = TikTokClient(access_token="tt_tok")
        r1 = client.publish_pull_from_url(tt_bundle, ledger=ledger, dry_run=True)
        self.assertEqual(r1["status"], "staged")
        r2 = client.publish_pull_from_url(tt_bundle, ledger=ledger, dry_run=True)
        self.assertEqual(r2["status"], "skipped_duplicate")

    def test_resilient_mirrors_and_ecosystem_matrix_6_tiers(self) -> None:
        matrix = build_ecosystem_matrix()
        self.assertEqual(matrix["tier_count"], 6)
        self.assertGreaterEqual(matrix["publishos_literary_archive_count"], 20)
        self.assertEqual(matrix["parliaments_count"], 5)

        # Bluesky UTF-8 byte-offset facet check with multi-byte character before URL
        sample_bsky = "ΔE check: https://research.openie.dev/papers/gates/ verified."
        facets = build_bluesky_facets(sample_bsky)
        self.assertEqual(len(facets), 1)
        b_start = facets[0]["index"]["byteStart"]
        b_end = facets[0]["index"]["byteEnd"]
        self.assertEqual(
            sample_bsky.encode("utf-8")[b_start:b_end].decode("utf-8"),
            "https://research.openie.dev/papers/gates/",
        )

        ledger = SyndicationLedger()
        ia = InternetArchiveMirror()
        self.assertEqual(
            ia.put_artifact(
                identifier="openie-gates",
                filename="tv-gates.wai",
                payload_bytes=b"WAI1...",
                title="Metered Commit Gates",
                canonical_id="blake3:tv:" + ("a" * 64),
                ledger=ledger,
                dry_run=True,
            )["status"],
            "staged",
        )
        masto = MastodonMirror()
        self.assertEqual(
            masto.post_thread(
                study_id="gates",
                posts=["Post 1 plain summary", "Post 2 https://research.openie.dev/papers/gates/"],
                ledger=ledger,
                dry_run=True,
            )["status"],
            "staged",
        )
        bsky = BlueskyATProtoMirror()
        self.assertEqual(
            bsky.post_thread(
                study_id="gates",
                posts=[sample_bsky],
                ledger=ledger,
                dry_run=True,
            )["status"],
            "staged",
        )

        # Ledger roundtrip persistence check
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "ledger.json"
            ledger.save(p)
            reloaded = SyndicationLedger.load(p)
            self.assertEqual(reloaded.ledger_blake3(), ledger.ledger_blake3())


if __name__ == "__main__":
    unittest.main()
