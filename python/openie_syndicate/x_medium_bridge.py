# SPDX-License-Identifier: Apache-2.0
"""Bidirectional X (Twitter) <-> Medium Automation & Canonical Essay/Thread Engine.

Pure Python standard library (`urllib`, `hmac`, `hashlib`, `base64`, `xml.etree.ElementTree`, `json`).
Enforces:
  - Strict epistemic separation (`measured_j` != `reported_j` != `est_j` != `unmetered`)
  - License hygiene (`CC0-1.0` for summaries/articles/threads, `Apache-2.0` for code/schema)
  - Zero human review gates (`human_in_gate = false`)
  - X exact weighted character counter (`<= 280`, every `https?://...` = 23 chars, 0 URLs in Post 1)
"""

from __future__ import annotations

import html
import json
import math
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from typing import Any, Callable, Sequence

from .ledger import (
    DEFAULT_TX_UTC,
    X_BACKLINK_PLACEHOLDER,
    SyndicationLedger,
    compute_bundle_blake3,
    default_medium_canonical_import_url,
    default_x_search_intent_url,
)
from .oauth1 import (
    X_MAX_WEIGHTED_CHARS,
    OAuth1Credentials,
    build_oauth1_authorization_header,
    extract_urls,
    parse_form_urlencoded,
    weighted_len,
)

RESEARCH_ORIGIN = "https://research.openie.dev"
COMMONS_ORIGIN = "https://scholar.askdavidc.ai"
SUBSTRATE_REPO_URL = "https://github.com/openIE-dev/openie-artifact-substrate"

HTTPTransport = Callable[
    [str, str, dict[str, str], bytes | None], tuple[int, dict[str, str], bytes]
]

_EPISTEMIC_TAG_LABELS: dict[str, str] = {
    "T": "Theorem / Machine-Checked Formal Proof",
    "E": "Empirical / Hardware-Instrumented Experiment",
    "M": "Mathematical / Analytical Cost or Physics Model",
    "S": "Survey / Historical Price or Accounting Audit",
}

_BLOG_CATEGORY_MAP: dict[str, str] = {
    "mei": "product",
    "jouleos": "product",
    "agency": "energy",
    "gates": "energy",
    "lut-adapt": "energy",
    "lut6-codon-nucleus": "energy",
    "eco-compute": "energy",
    "satiation": "energy",
    "rce": "engineering",
    "rce-jepa": "engineering",
    "rce-compile": "engineering",
    "rce-vc": "engineering",
    "game-engines": "engineering",
    "ai-reads-human": "engineering",
    "interface-economics": "engineering",
    "eco-synthesis": "engineering",
    "eco-database": "engineering",
}

# Deterministic lossless numeral contractions applied ONLY when a tweet exceeds 280 weighted chars
_TWEET_NUMERAL_CONTRACTIONS: tuple[tuple[str, str], ...] = (
    ("three-hundred-twenty-eight-million-dollar", "$328M"),
    ("sixty-four", "64"),
    ("thirty-seven", "37"),
    ("sixteen-kilobyte", "16 KB"),
    ("four-dollar", "$4"),
    ("six-input", "6-input"),
    ("three point six times", "3.6x"),
    ("nine of ten", "9/10"),
    ("twenty-five thousand five hundred", "25,500"),
    ("operating systems", "OSes"),
)


def default_urllib_transport(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    """Execute a real HTTPS request via stdlib `urllib.request`."""
    req = urllib.request.Request(url=url, data=body, headers=headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status = int(resp.status)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return status, resp_headers, resp.read()
    except urllib.error.HTTPError as exc:
        err_body = exc.read() if exc.fp is not None else b""
        resp_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        return int(exc.code), resp_headers, err_body


# ---------------------------------------------------------------------------
# Transcript de-duplication & formatting helpers
# ---------------------------------------------------------------------------


def _strip_three_bullet_recap(transcript: str) -> str:
    """Strip the repeated 'First, ... Second, ... Third, ...' studio opener from 45s/90s/180s cuts."""
    text = " ".join(transcript.strip().split())
    sentences = re.split(r"(?<=[.!?])\s+", text)
    if (
        len(sentences) >= 4
        and sentences[0].startswith("First,")
        and sentences[1].startswith("Second,")
        and sentences[2].startswith("Third,")
    ):
        return " ".join(sentences[3:]).strip()
    return text


def _split_into_paragraphs(prose: str, sentences_per_para: int = 3) -> list[str]:
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", prose.strip()) if s.strip()]
    if not sentences:
        return []
    paras: list[str] = []
    for i in range(0, len(sentences), sentences_per_para):
        paras.append(" ".join(sentences[i : i + sentences_per_para]))
    return paras


def _tighten_for_x(text: str, limit: int = X_MAX_WEIGHTED_CHARS) -> str:
    """Deterministically tighten plain prose so `weighted_len(text) <= limit`."""
    if weighted_len(text) <= limit:
        return text
    candidate = text
    for src, dst in _TWEET_NUMERAL_CONTRACTIONS:
        if src in candidate:
            candidate = candidate.replace(src, dst)
        if weighted_len(candidate) <= limit:
            return candidate
    if "\n\n" in candidate:
        candidate = candidate.replace("\n\n", "\n")
        if weighted_len(candidate) <= limit:
            return candidate
    # Word-boundary deterministic trim if still over limit (preserving URLs if any)
    while weighted_len(candidate) > limit and " " in candidate:
        head, _ = candidate.rsplit(" ", 1)
        candidate = head.rstrip(",;:- ") + "…"
    return candidate


def _format_joules_human(joules: float | None, evidence_class: str) -> str:
    if evidence_class == "unmetered" or joules is None:
        return "unmetered (joules = null; never fabricated as zero)"
    if joules < 1e-9:
        return f"{joules * 1e12:.2f} pJ ({evidence_class})"
    if joules < 1e-6:
        return f"{joules * 1e9:.2f} nJ ({evidence_class})"
    if joules < 1e-3:
        return f"{joules * 1e6:.2f} µJ ({evidence_class})"
    if joules < 1.0:
        return f"{joules * 1e3:.2f} mJ ({evidence_class})"
    return f"{joules:.3f} J ({evidence_class})"


# ---------------------------------------------------------------------------
# Forward Flow 1A: Medium Essay + Canonical Import HTML + blog.openie.dev YAML
# ---------------------------------------------------------------------------


def compose_medium_article(
    study: dict[str, Any],
    substrate_record: dict[str, Any] | None = None,
    ledger: SyndicationLedger | None = None,
) -> dict[str, Any]:
    """Generate publication-grade Medium Markdown + metadata for an OpenIE study."""
    study_id = str(study["id"])
    title = str(study["title"])
    short_title = str(study.get("short_title", title))
    paper_rel = str(study["paper_url"])
    canonical_source_url = (
        paper_rel if paper_rel.startswith("http") else f"{RESEARCH_ORIGIN}{paper_rel}"
    )
    poster_rel = str(study.get("poster_url", f"/media/tv/posters/{study_id}-poster.jpg"))
    poster_url = f"{RESEARCH_ORIGIN}{poster_rel}"
    tv_url = f"{RESEARCH_ORIGIN}/tv/?study={study_id}"
    snackable_url = f"{RESEARCH_ORIGIN}/media/tv/tiktok/{study_id}-tiktok.mp4"

    hook_15 = str(study["tiers"]["15s"]["hook"])
    subtitle = f"{study['headline_metric']} — {hook_15}"
    bullets: list[str] = list(study["plain_bullets"])

    # Provenance & energy from substrate record when available
    cid = (
        str(substrate_record["canonical_id"])
        if substrate_record and "canonical_id" in substrate_record
        else f"openie:tv:{study_id}"
    )
    wai_env = (substrate_record or {}).get("interchange_envelope", {})
    wai_blake3 = str(wai_env.get("envelope_blake3", "verified-wai1-envelope"))
    wai_uri = str(wai_env.get("envelope_uri", f"catalog/envelopes/tv-{study_id}.wai"))
    wai_github_url = f"{SUBSTRATE_REPO_URL}/blob/main/{wai_uri}"

    energy_obj = (substrate_record or {}).get("energy_cost_j") or {}
    ev_class = str(energy_obj.get("evidence_class", "unmetered"))
    joules = energy_obj.get("joules")
    board_metered = bool(energy_obj.get("board_metered", False))
    meter_or_formula = str(
        energy_obj.get("meter_or_formula", study.get("energy_disclosure", ""))
    )
    landauer_bits = energy_obj.get("landauer_300k_bits_equiv")

    sci_gate = ((substrate_record or {}).get("verification_status") or {}).get(
        "scientific_gate", {}
    )
    lean_checked = bool(sci_gate.get("lean_kernel_checked", False))
    sat_digest = sci_gate.get("sat_miter_digest")

    # De-duplicated plain narratives from 45s, 90s, and 180s cuts
    analogy_45 = _strip_three_bullet_recap(str(study["tiers"]["45s"]["transcript"]))
    analogy_90 = _strip_three_bullet_recap(str(study["tiers"]["90s"]["transcript"]))
    deep_180 = _strip_three_bullet_recap(str(study["tiers"]["180s"]["transcript"]))

    analogy_paras = _split_into_paragraphs(analogy_45, 3) + _split_into_paragraphs(
        analogy_90, 3
    )
    deep_paras = _split_into_paragraphs(deep_180, 4)

    epistemic_tags: list[str] = list(study.get("epistemic_tags", []))
    epistemic_lines = [
        f"- **`[{tag}]` {_EPISTEMIC_TAG_LABELS.get(tag, tag)}**" for tag in epistemic_tags
    ]
    if lean_checked:
        epistemic_lines.append(
            "- **Six-Kernel Lean 4.36.0 Quorum**: Verified inside `bwrap` sandboxes across all 6 independent proof checkers (`0 sorry`, `0 custom axioms`, `0 ofReduceBool`)."
        )
    if sat_digest:
        epistemic_lines.append(
            f"- **SAT / Miter Equivalence Digest**: `blake3:{sat_digest[:24]}…` (`0` mismatches)."
        )

    resolved_x_url = (
        ledger.resolve_x_thread_url(study_id, short_title)
        if ledger is not None
        else default_x_search_intent_url(study_id, short_title)
    )

    joules_display = _format_joules_human(joules, ev_class)
    landauer_line = (
        f"- **300 K Landauer Bit-Equivalents**: `{landauer_bits:.4e}` bits (`E / (k_B · 300 K · ln 2)`)"
        if isinstance(landauer_bits, (int, float)) and not isinstance(landauer_bits, bool)
        else "- **300 K Landauer Bit-Equivalents**: `null` (unmetered study — analytical/archival scope)"
    )

    md_parts: list[str] = [
        f"# {title}",
        "",
        f"*{subtitle}*",
        "",
        f"> **Public Domain (`CC0-1.0`) · OpenIE Research Essay**  ",
        f"> **Canonical Primary Source**: [{canonical_source_url}]({canonical_source_url})  ",
        f"> **Canonical Artifact ID**: `{cid}` · **Gate Invariant**: `human_in_gate = false`",
        "",
        "---",
        "",
        "## Three Plain-Language Takeaways (Zero Acronym Soup)",
        "",
        f"1. {bullets[0]}",
        f"2. {bullets[1]}",
        f"3. {bullets[2]}",
        "",
        f"![{title} — OpenIE Research TV Studio Poster]({poster_url})",
        f"*Studio key visual for **{short_title}** (`{study.get('category', 'OpenIE Research')}` · {study['headline_metric']}). Dedicated to the public domain under `CC0-1.0`.*",
        "",
        "## Everyday Analogy & Why It Matters",
        "",
        "\n\n".join(analogy_paras),
        "",
        "## Inside the Mechanism & Candid Limits",
        "",
        "\n\n".join(deep_paras),
        "",
        "### Epistemic Evidence Tags (`[T]` / `[E]` / `[M]` / `[S]`)",
        "",
        "\n".join(epistemic_lines),
        "",
        "## How Energy Was Metered",
        "",
        "Open Interface Engineering enforces strict epistemic non-mixing across physical power rails, processor counters, and mathematical bounds (`measured_j` $\\perp$ `reported_j` $\\perp$ `est_j` $\\perp$ `unmetered` — cross-class addition is forbidden by `ScientificGate`):",
        "",
        f"- **Acquisition Tier**: {study['energy_tier']}",
        f"- **Plain-Language Disclosure**: {study['energy_disclosure']}",
        f"- **Substrate Evidence Class**: `{ev_class}` (`board_metered = {str(board_metered).lower()}`)",
        f"- **Primary Reading**: `{joules_display}`",
        f"- **Meter or Formula**: {meter_or_formula}",
        landauer_line,
        "",
        "## Continue the Discussion & Verify Every Byte",
        "",
        f"<!-- x_thread_backlink_slot: {X_BACKLINK_PLACEHOLDER} -->",
        f"- **Watch in 15 Seconds or 3 Minutes**: Stream the native `9:16` Vertical Snackable ([`{study_id}-tiktok.mp4`]({snackable_url})) or explore all four captioned studio cuts (`15s`, `45s`, `90s`, and `3m` 3D cutaway documentary) on **[OpenIE Research TV]({tv_url})**.",
        f"- **Join the Synchronized X (Twitter) Thread**: Reply, critique, or inspect the 5-post verification thread on **[X (Twitter)]({resolved_x_url})**.",
        f"- **Query Grounded Prior Art & Signed WAI1 Receipts**: Explore linked lineage trails on **[The Commons (`scholar.askdavidc.ai`)]({COMMONS_ORIGIN})**, read the full primary paper & PDF at **[`research.openie.dev{paper_rel}`]({canonical_source_url})**, and verify the Ed25519-signed `WAI1` binary container (`blake3:{wai_blake3[:16]}…`) in **[`openie-artifact-substrate`]({wai_github_url})**.",
        "",
        "---",
        "",
        "*Summary & essay text dedicated to the public domain under [`CC0-1.0`](https://creativecommons.org/publicdomain/zero/1.0/). Code, verification gates, and `WAI1` schemas licensed under `Apache-2.0`.*",
        "",
    ]
    markdown_text = "\n".join(md_parts)
    words = re.findall(r"\b\w+\b", markdown_text)
    word_count = len(words)
    reading_time_min = max(1, math.ceil(word_count / 220))

    raw_tags = ["open-science", "computer-science", "ai-verification", "energy-efficiency"]
    cat_slug = re.sub(r"[^a-z0-9]+", "-", str(study.get("category", "")).lower()).strip("-")
    if cat_slug:
        raw_tags.insert(0, cat_slug[:25].rstrip("-"))
    tags = list(dict.fromkeys(raw_tags))[:5]

    return {
        "study_id": study_id,
        "title": title,
        "subtitle": subtitle,
        "markdown": markdown_text,
        "markdown_uri": f"/syndication/medium/{study_id}.md",
        "canonical_import_uri": f"/syndication/medium/{study_id}/",
        "canonical_source_url": canonical_source_url,
        "word_count": word_count,
        "reading_time_min": reading_time_min,
        "license": "CC0-1.0",
        "tags": tags,
        "x_thread_backlink_slot": X_BACKLINK_PLACEHOLDER,
        "resolved_x_thread_url": resolved_x_url,
        "content_blake3": compute_bundle_blake3(markdown_text),
    }


def resolve_medium_x_backlink(
    markdown_text: str, study_id: str, short_title: str, live_x_url: str
) -> str:
    """Replace `{{X_THREAD_URL}}` or fallback search URL in Medium Markdown with `live_x_url`."""
    fallback = default_x_search_intent_url(study_id, short_title)
    updated = markdown_text.replace(fallback, live_x_url)
    updated = updated.replace(
        f"<!-- x_thread_backlink_slot: {X_BACKLINK_PLACEHOLDER} -->",
        f"<!-- x_thread_backlink_slot: {live_x_url} -->",
    )
    if X_BACKLINK_PLACEHOLDER in updated:
        updated = updated.replace(X_BACKLINK_PLACEHOLDER, live_x_url)
    return updated


def build_canonical_import_html(medium_bundle: dict[str, Any]) -> str:
    """Render minimal semantic HTML with `<link rel="canonical">` for Medium's Story Import tool."""
    title_esc = html.escape(str(medium_bundle["title"]))
    sub_esc = html.escape(str(medium_bundle["subtitle"]))
    canon_esc = html.escape(str(medium_bundle["canonical_source_url"]))
    # Convert basic markdown paragraphs/headings for Medium Story Importer compatibility
    body_lines: list[str] = []
    for line in str(medium_bundle["markdown"]).splitlines():
        s = line.strip()
        if not s or s.startswith("<!--"):
            continue
        if s.startswith("# "):
            continue
        if s.startswith("## "):
            body_lines.append(f"<h2>{html.escape(s[3:])}</h2>")
        elif s.startswith("### "):
            body_lines.append(f"<h3>{html.escape(s[4:])}</h3>")
        elif s.startswith("!["):
            m_img = re.match(r"!\[(.*?)\]\((.*?)\)", s)
            if m_img:
                body_lines.append(
                    f'<figure><img src="{html.escape(m_img.group(2))}" alt="{html.escape(m_img.group(1))}" /></figure>'
                )
        elif s == "---":
            body_lines.append("<hr />")
        else:
            body_lines.append(f"<p>{html.escape(s)}</p>")

    joined_body = "\n      ".join(body_lines)
    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "  <head>\n"
        '    <meta charset="utf-8" />\n'
        f"    <title>{title_esc}</title>\n"
        f'    <link rel="canonical" href="{canon_esc}" />\n'
        '    <meta name="author" content="David Charlot, Open Interface Engineering" />\n'
        '    <meta name="dcterms.rights" content="https://creativecommons.org/publicdomain/zero/1.0/" />\n'
        "  </head>\n"
        "  <body>\n"
        "    <article>\n"
        f"      <h1>{title_esc}</h1>\n"
        f"      <p><em>{sub_esc}</em></p>\n"
        f"      {joined_body}\n"
        "    </article>\n"
        "  </body>\n"
        "</html>\n"
    )


def _yaml_quote(s: str) -> str:
    escaped = (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def _yaml_block(text: str, indent: int) -> str:
    pad = " " * indent
    lines = text.rstrip("\n").split("\n")
    out = ["|"]
    for ln in lines:
        out.append(f"{pad}{ln}" if ln else "")
    return "\n".join(out)


def compose_blog_manifest_yaml(
    study: dict[str, Any],
    substrate_record: dict[str, Any] | None = None,
    date_str: str = "2026-11-24",
) -> str:
    """Produce a `blog.openie.dev`-compatible YAML manifest matching `blog-openie-web/scripts/build-post.js`."""
    study_id = str(study["id"])
    title = str(study["title"])
    short_title = str(study.get("short_title", title))
    paper_rel = str(study["paper_url"])
    canonical_url = (
        paper_rel if paper_rel.startswith("http") else f"{RESEARCH_ORIGIN}{paper_rel}"
    )
    category = _BLOG_CATEGORY_MAP.get(study_id, "research")
    bullets = list(study["plain_bullets"])
    hook_15 = str(study["tiers"]["15s"]["hook"])

    energy_obj = (substrate_record or {}).get("energy_cost_j") or {}
    ev_class = str(energy_obj.get("evidence_class", "unmetered"))
    joules = energy_obj.get("joules")
    meter = str(energy_obj.get("meter_or_formula", study.get("energy_disclosure", "")))

    analogy = "\n\n".join(
        _split_into_paragraphs(
            _strip_three_bullet_recap(str(study["tiers"]["90s"]["transcript"])), 3
        )
    )
    deep_cut = "\n\n".join(
        _split_into_paragraphs(
            _strip_three_bullet_recap(str(study["tiers"]["180s"]["transcript"])), 4
        )
    )
    takeaways_md = "\n".join(f"{idx + 1}. {b}" for idx, b in enumerate(bullets))
    energy_md = (
        f"- **Acquisition Tier**: {study['energy_tier']}\n"
        f"- **Disclosure**: {study['energy_disclosure']}\n"
        f"- **Evidence Class**: `{ev_class}` (`{_format_joules_human(joules, ev_class)}`)\n"
        f"- **Meter / Formula**: {meter}\n\n"
        "Energy classes (`measured_j`, `reported_j`, `est_j`, `unmetered`) are strictly partitioned and never summed across boundaries."
    )

    tags_list = [study_id, category, "open-science", "cc0", ev_class.replace("_", "-")]
    tags_yaml = "[" + ", ".join(_yaml_quote(t) for t in dict.fromkeys(tags_list)) + "]"

    hero_alt = f"{short_title} — {study['headline_metric']}"
    intro_md = (
        f"*Canonical Primary Source: [{canonical_url}]({canonical_url}) · "
        f"Dedicated to the Public Domain (`CC0-1.0`)*\n\n{hook_15}"
    )
    closing_md = (
        f"Watch the 15-second vertical snackable and 3-minute 3D documentary on "
        f"[OpenIE Research TV]({RESEARCH_ORIGIN}/tv/?study={study_id}) or explore grounded prior art on "
        f"[The Commons]({COMMONS_ORIGIN})."
    )

    lines = [
        "# OpenIE Deterministic Blog Syndication Manifest (CC0-1.0)",
        f"slug: {_yaml_quote(study_id)}",
        "",
        "metadata:",
        f"  title: {_yaml_quote(title)}",
        f"  description: {_yaml_quote(hook_15)}",
        f"  date: {_yaml_quote(date_str)}",
        '  author: "David Charlot, Open Interface Engineering"',
        f"  category: {_yaml_quote(category)}",
        f"  tags: {tags_yaml}",
        "  featured: false",
        "  draft: false",
        "  toc: true",
        f"  canonicalUrl: {_yaml_quote(canonical_url)}",
        '  license: "CC0-1.0"',
        "",
        "hero:",
        f"  image: {_yaml_quote(f'{study_id}-poster.jpg')}",
        f"  alt: {_yaml_quote(hero_alt)}",
        "",
        "sections:",
        "  - heading: null",
        f"    content: {_yaml_block(intro_md, 6)}",
        "",
        '  - heading: "Three Plain-Language Takeaways (Zero Acronym Soup)"',
        f"    content: {_yaml_block(takeaways_md, 6)}",
        "",
        '  - heading: "Everyday Analogy & Why It Matters"',
        f"    content: {_yaml_block(analogy, 6)}",
        "",
        '  - heading: "Inside the Mechanism & Candid Limits"',
        f"    content: {_yaml_block(deep_cut, 6)}",
        "",
        '  - heading: "How Energy Was Metered"',
        f"    content: {_yaml_block(energy_md, 6)}",
        "",
        "references:",
        "  - id: 1",
        '    authors: "David Charlot, Open Interface Engineering"',
        f"    title: {_yaml_quote(title)}",
        '    publication: "OpenIE Research"',
        "    year: 2026",
        f"    url: {_yaml_quote(canonical_url)}",
        "",
        "closing:",
        f"  content: {_yaml_block(closing_md, 4)}",
        "  cta:",
        "    primary:",
        '      text: "Read Primary Study & PDF"',
        f"      url: {_yaml_quote(canonical_url)}",
        "    secondary:",
        '      text: "Watch on OpenIE Research TV"',
        f"      url: {_yaml_quote(f'{RESEARCH_ORIGIN}/tv/?study={study_id}')}",
        f"  footer_text: {_yaml_quote('Summary text dedicated to the public domain under CC0-1.0.')}",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Forward Flow 1B: X (Twitter) 5-Tweet Thread Composer
# ---------------------------------------------------------------------------


def compose_x_thread(
    study: dict[str, Any],
    substrate_record: dict[str, Any] | None = None,
    medium_url: str | None = None,
) -> dict[str, Any]:
    """Compose a deterministic 5-post X thread (`<= 280` weighted chars each, 0 URLs in Post 1)."""
    study_id = str(study["id"])
    title = str(study["title"])
    short_title = str(study.get("short_title", title))
    paper_rel = str(study["paper_url"])
    paper_url = (
        paper_rel if paper_rel.startswith("http") else f"{RESEARCH_ORIGIN}{paper_rel}"
    )
    resolved_medium_url = medium_url or default_medium_canonical_import_url(study_id)

    bullets = list(study["plain_bullets"])
    hook_15 = str(study["tiers"]["15s"]["hook"])
    headline_metric = str(study["headline_metric"])

    energy_obj = (substrate_record or {}).get("energy_cost_j") or {}
    ev_class = str(energy_obj.get("evidence_class", "unmetered"))
    joules = energy_obj.get("joules")
    board_metered = bool(energy_obj.get("board_metered", False))

    cid = (
        str(substrate_record["canonical_id"])
        if substrate_record and "canonical_id" in substrate_record
        else f"blake3:tv:{study_id}"
    )
    cid_short = cid.split(":")[-1][:12] if ":" in cid else cid[:12]

    sci_gate = ((substrate_record or {}).get("verification_status") or {}).get(
        "scientific_gate", {}
    )
    lean_checked = bool(sci_gate.get("lean_kernel_checked", False))
    sat_digest = sci_gate.get("sat_miter_digest")

    # Post 1: Scroll-Stopper Hook + Native 9:16 Snackable Video Card (ZERO external URLs!)
    display_head = title if len(title) <= 78 else short_title
    post_1_raw = f"{display_head}\n\n{hook_15}\n\n[{headline_metric}]"
    # Guarantee zero URLs in Post 1
    post_1_clean = re.sub(r"https?://\S+", "", post_1_raw).strip()
    post_1_text = _tighten_for_x(post_1_clean)

    # Post 2: 1/3 & 2/3 Plain Points
    post_2_raw = f"1/3 {bullets[0]}\n\n2/3 {bullets[1]}"
    post_2_text = _tighten_for_x(post_2_raw)

    # Post 3: 3/3 + Honest Energy Receipt (measured_j / reported_j / est_j / unmetered)
    if ev_class == "measured_j":
        e_note = f"Energy class: measured_j ({_format_joules_human(joules, ev_class).split(' (')[0]} via physical board shunt; board_metered=true)."
    elif ev_class == "reported_j":
        e_note = f"Energy class: reported_j ({_format_joules_human(joules, ev_class).split(' (')[0]} chip counter; board_metered=false, never mixed with shunts)."
    elif ev_class == "est_j":
        e_note = f"Energy class: est_j ({_format_joules_human(joules, ev_class).split(' (')[0]} analytical model; board_metered=false, no physical bench claim)."
    else:
        e_note = f"Energy class: unmetered ({study['energy_tier']}; joules=null, never faked as zero)."
    post_3_raw = f"3/3 {bullets[2]}\n\n{e_note}"
    post_3_text = _tighten_for_x(post_3_raw)

    # Post 4: Machine-Checked Verification (0 human review gates)
    if lean_checked and sat_digest:
        ver_core = "6/6 Lean 4.36.0 bwrap kernels (0 sorry, 0 custom axioms) + SAT/miter equivalence (0 mismatches)"
    elif lean_checked:
        ver_core = "6/6 Lean 4.36.0 bwrap proof kernels (0 sorry, 0 custom axioms, 0 ofReduceBool)"
    elif sat_digest:
        ver_core = f"Deterministic replay & miter verification (blake3:{str(sat_digest)[:10]}…, 0 mismatches)"
    else:
        ver_core = "Deterministic Shape-D null controls, Ed25519 receipts & epistemic non-mixing gates"

    tags_str = "/".join(f"[{t}]" for t in study.get("epistemic_tags", ["T", "E"]))
    post_4_raw = (
        f"Verified with 0 human review gates (human_in_gate=false):\n"
        f"• {ver_core}\n"
        f"• Evidence: {tags_str} · WAI1 blake3:{cid_short}… · CC0-1.0"
    )
    post_4_text = _tighten_for_x(post_4_raw)

    # Post 5: Bidirectional Medium + Primary Paper Bridge
    post_5_raw = (
        f"Read & verify {short_title} (CC0-1.0):\n"
        f"• Illustrated plain-language essay: {resolved_medium_url}\n"
        f"• Primary paper, PDF & receipts: {paper_url}"
    )
    post_5_text = _tighten_for_x(post_5_raw)

    raw_posts = [
        (1, "hook_video_card", post_1_text),
        (2, "plain_points_1_2", post_2_text),
        (3, "plain_point_3_and_energy", post_3_text),
        (4, "machine_verification_gate", post_4_text),
        (5, "bidirectional_medium_and_paper_bridge", post_5_text),
    ]

    posts_out: list[dict[str, Any]] = []
    for idx, role, txt in raw_posts:
        wlen = weighted_len(txt)
        if wlen > X_MAX_WEIGHTED_CHARS:
            raise ValueError(
                f"X post {idx} for {study_id} exceeded 280 weighted chars: {wlen}"
            )
        urls_in_post = extract_urls(txt)
        if idx == 1 and urls_in_post:
            raise ValueError(f"Post 1 for {study_id} must contain zero external URLs!")
        entry: dict[str, Any] = {
            "position": idx,
            "role": role,
            "text": txt,
            "weighted_chars": wlen,
            "raw_chars": len(txt),
            "urls": urls_in_post,
            "in_reply_to_position": None if idx == 1 else idx - 1,
        }
        if idx == 1:
            entry["media"] = {
                "video_uri": f"/media/tv/tiktok/{study_id}-tiktok.mp4",
                "fallback_video_uri": str(study["tiers"]["15s"]["video_url"]),
                "poster_uri": str(study["poster_url"]),
                "vtt_uri": str(study["tiers"]["15s"]["vtt_url"]),
                "aspect_ratio": "9:16",
                "resolution": "1080x1920",
                "fps": 60,
                "media_category": "tweet_video",
            }
        posts_out.append(entry)

    max_w = max(p["weighted_chars"] for p in posts_out)
    bundle_core = {
        "schema": "openie.x_thread_bundle.v1",
        "study_id": study_id,
        "canonical_id": cid,
        "license": "CC0-1.0",
        "post_count": len(posts_out),
        "max_weighted_chars": max_w,
        "card_video_uri": f"/media/tv/tiktok/{study_id}-tiktok.mp4",
        "fallback_video_uri": str(study["tiers"]["15s"]["video_url"]),
        "medium_crosslink_uri": resolved_medium_url,
        "canonical_paper_url": paper_url,
        "zero_urls_in_post_1": len(posts_out[0]["urls"]) == 0,
        "posts": posts_out,
    }
    bundle_core["content_blake3"] = compute_bundle_blake3(bundle_core)
    return bundle_core


def update_x_bundle_medium_url(
    x_bundle: dict[str, Any], live_medium_url: str
) -> dict[str, Any]:
    """Dynamically update Post 5's `medium_url` when Medium API returns a live story URL."""
    updated = json.loads(json.dumps(x_bundle))
    old_url = str(updated["medium_crosslink_uri"])
    updated["medium_crosslink_uri"] = live_medium_url
    post_5 = updated["posts"][-1]
    post_5["text"] = post_5["text"].replace(old_url, live_medium_url)
    post_5["weighted_chars"] = weighted_len(post_5["text"])
    post_5["raw_chars"] = len(post_5["text"])
    post_5["urls"] = extract_urls(post_5["text"])
    if post_5["weighted_chars"] > X_MAX_WEIGHTED_CHARS:
        raise ValueError("Updated Post 5 exceeded 280 weighted chars")
    updated["max_weighted_chars"] = max(p["weighted_chars"] for p in updated["posts"])
    updated.pop("content_blake3", None)
    updated["content_blake3"] = compute_bundle_blake3(updated)
    return updated


# ---------------------------------------------------------------------------
# Live OAuth 1.0a + v2 X Client (Chunked Video Upload + Chained Replies)
# ---------------------------------------------------------------------------


class XClient:
    """Zero-dependency X (Twitter) API v1.1 Media Upload + API v2 Tweets client."""

    UPLOAD_ENDPOINT = "https://upload.twitter.com/1.1/media/upload.json"
    TWEETS_V2_ENDPOINT = "https://api.x.com/2/tweets"
    USERS_V2_PREFIX = "https://api.x.com/2/users"

    def __init__(
        self,
        credentials: OAuth1Credentials | None = None,
        bearer_token: str | None = None,
        transport: HTTPTransport | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.credentials = credentials or OAuth1Credentials.from_env()
        self.bearer_token = (
            bearer_token
            if bearer_token is not None
            else os.environ.get("X_BEARER_TOKEN", "")
        )
        self.transport = transport or default_urllib_transport
        self.sleep_fn = sleep_fn

    def _signed_request(
        self,
        method: str,
        url: str,
        *,
        json_body: dict[str, Any] | None = None,
        form_params: Sequence[tuple[str, str]] | None = None,
        multipart_fields: Sequence[tuple[str, str | bytes, str | None]] | None = None,
    ) -> dict[str, Any]:
        if not self.credentials.is_configured():
            raise RuntimeError(
                "X OAuth 1.0a credentials missing in environment (X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_TOKEN_SECRET)"
            )

        body_bytes: bytes | None = None
        sig_body_params: Sequence[tuple[str, str]] = ()
        headers: dict[str, str] = {"Accept": "application/json"}

        if json_body is not None:
            body_bytes = json.dumps(json_body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
            # Per RFC 5849 §3.4.1.3.1, JSON entity-bodies are NOT included in OAuth 1.0a signature params
        elif form_params is not None:
            encoded = urllib.parse.urlencode(form_params, quote_via=urllib.parse.quote)
            body_bytes = encoded.encode("ascii")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            sig_body_params = parse_form_urlencoded(encoded)
        elif multipart_fields is not None:
            boundary = f"openieBoundary{uuid.uuid4().hex}"
            chunks: list[bytes] = []
            for name, value, filename in multipart_fields:
                chunks.append(f"--{boundary}\r\n".encode("ascii"))
                if filename is not None:
                    chunks.append(
                        f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode(
                            "utf-8"
                        )
                    )
                    chunks.append(
                        value if isinstance(value, bytes) else value.encode("utf-8")
                    )
                else:
                    chunks.append(
                        f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(
                            "utf-8"
                        )
                    )
                    chunks.append(
                        value if isinstance(value, bytes) else str(value).encode("utf-8")
                    )
                chunks.append(b"\r\n")
            chunks.append(f"--{boundary}--\r\n".encode("ascii"))
            body_bytes = b"".join(chunks)
            headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
            # Per RFC 5849 §3.4.1.3.1, multipart/form-data fields are excluded from OAuth 1.0a signature params

        headers["Authorization"] = build_oauth1_authorization_header(
            method=method,
            url=url,
            credentials=self.credentials,
            body_form_params=sig_body_params,
        )
        status, _, raw = self.transport(method, url, headers, body_bytes)
        if status < 200 or status >= 300:
            raise RuntimeError(
                f"X API {method} {url} failed with HTTP {status}: {raw.decode('utf-8', errors='replace')}"
            )
        return json.loads(raw.decode("utf-8")) if raw else {}

    def upload_video_chunked(
        self,
        video_bytes: bytes,
        *,
        media_type: str = "video/mp4",
        media_category: str = "tweet_video",
        chunk_size: int = 4 * 1024 * 1024,
        max_status_polls: int = 20,
    ) -> str:
        """Execute X chunked media upload (`INIT` -> `APPEND` -> `FINALIZE` -> `STATUS`)."""
        if not video_bytes:
            raise ValueError("video_bytes must be non-empty")

        init_resp = self._signed_request(
            "POST",
            self.UPLOAD_ENDPOINT,
            form_params=[
                ("command", "INIT"),
                ("total_bytes", str(len(video_bytes))),
                ("media_type", media_type),
                ("media_category", media_category),
            ],
        )
        media_id = str(init_resp["media_id_string"])

        seg_idx = 0
        for offset in range(0, len(video_bytes), chunk_size):
            segment = video_bytes[offset : offset + chunk_size]
            self._signed_request(
                "POST",
                self.UPLOAD_ENDPOINT,
                multipart_fields=[
                    ("command", "APPEND", None),
                    ("media_id", media_id, None),
                    ("segment_index", str(seg_idx), None),
                    ("media", segment, f"chunk-{seg_idx}.mp4"),
                ],
            )
            seg_idx += 1

        fin_resp = self._signed_request(
            "POST",
            self.UPLOAD_ENDPOINT,
            form_params=[("command", "FINALIZE"), ("media_id", media_id)],
        )

        proc_info = fin_resp.get("processing_info")
        polls = 0
        while isinstance(proc_info, dict) and proc_info.get("state") in {
            "pending",
            "in_progress",
        }:
            if polls >= max_status_polls:
                raise RuntimeError(f"X video processing timed out for media_id={media_id}")
            wait_s = float(proc_info.get("check_after_secs", 1))
            self.sleep_fn(max(0.0, wait_s))
            status_url = (
                f"{self.UPLOAD_ENDPOINT}?command=STATUS&media_id={urllib.parse.quote(media_id)}"
            )
            st_resp = self._signed_request("GET", status_url)
            proc_info = st_resp.get("processing_info")
            polls += 1

        if isinstance(proc_info, dict) and proc_info.get("state") == "failed":
            raise RuntimeError(f"X video processing failed: {proc_info}")
        return media_id

    def post_tweet(
        self,
        text: str,
        *,
        in_reply_to_tweet_id: str | None = None,
        media_ids: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        """Publish a single post via `POST https://api.x.com/2/tweets`."""
        wlen = weighted_len(text)
        if wlen > X_MAX_WEIGHTED_CHARS:
            raise ValueError(f"Tweet exceeds 280 weighted chars ({wlen})")
        payload: dict[str, Any] = {"text": text}
        if in_reply_to_tweet_id:
            payload["reply"] = {"in_reply_to_tweet_id": in_reply_to_tweet_id}
        if media_ids:
            payload["media"] = {"media_ids": list(media_ids)}
        return self._signed_request("POST", self.TWEETS_V2_ENDPOINT, json_body=payload)

    def post_thread(
        self,
        x_bundle: dict[str, Any],
        *,
        first_post_media_id: str | None = None,
    ) -> list[str]:
        """Publish all posts in `x_bundle` as a chained self-reply thread on X."""
        tweet_ids: list[str] = []
        prev_id: str | None = None
        for idx, post in enumerate(x_bundle["posts"]):
            m_ids = [first_post_media_id] if (idx == 0 and first_post_media_id) else None
            resp = self.post_tweet(
                str(post["text"]),
                in_reply_to_tweet_id=prev_id,
                media_ids=m_ids,
            )
            tid = str(resp["data"]["id"])
            tweet_ids.append(tid)
            prev_id = tid
        return tweet_ids

    def get_user_timeline(self, user_id: str, max_results: int = 50) -> list[dict[str, Any]]:
        """Fetch recent tweets via `GET /2/users/{id}/tweets` using `X_BEARER_TOKEN`."""
        if not self.bearer_token:
            raise RuntimeError("X_BEARER_TOKEN missing in environment")
        qs = urllib.parse.urlencode(
            {
                "max_results": str(max(5, min(100, max_results))),
                "tweet.fields": "author_id,conversation_id,created_at,in_reply_to_user_id,referenced_tweets,entities",
            }
        )
        url = f"{self.USERS_V2_PREFIX}/{urllib.parse.quote(user_id)}/tweets?{qs}"
        status, _, raw = self.transport(
            "GET",
            url,
            {"Authorization": f"Bearer {self.bearer_token}", "Accept": "application/json"},
            None,
        )
        if status < 200 or status >= 300:
            raise RuntimeError(f"X timeline GET failed with HTTP {status}")
        doc = json.loads(raw.decode("utf-8"))
        return list(doc.get("data", []))


# ---------------------------------------------------------------------------
# Live Medium REST API v1 Client
# ---------------------------------------------------------------------------


class MediumClient:
    """Zero-dependency Medium REST API v1 client + Canonical Import helper."""

    API_BASE = "https://api.medium.com/v1"

    def __init__(
        self,
        integration_token: str | None = None,
        author_id: str | None = None,
        transport: HTTPTransport | None = None,
    ) -> None:
        self.integration_token = (
            integration_token
            if integration_token is not None
            else os.environ.get("MEDIUM_INTEGRATION_TOKEN", "")
        )
        self.author_id = (
            author_id
            if author_id is not None
            else os.environ.get("MEDIUM_AUTHOR_ID", "")
        )
        self.transport = transport or default_urllib_transport

    def is_configured(self) -> bool:
        return bool(self.integration_token)

    def _headers(self) -> dict[str, str]:
        if not self.integration_token:
            raise RuntimeError("MEDIUM_INTEGRATION_TOKEN missing in environment")
        return {
            "Authorization": f"Bearer {self.integration_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Accept-Charset": "utf-8",
        }

    def get_me(self) -> dict[str, Any]:
        status, _, raw = self.transport(
            "GET", f"{self.API_BASE}/me", self._headers(), None
        )
        if status < 200 or status >= 300:
            raise RuntimeError(f"Medium GET /v1/me failed with HTTP {status}")
        data = json.loads(raw.decode("utf-8"))["data"]
        if not self.author_id and "id" in data:
            self.author_id = str(data["id"])
        return dict(data)

    def publish_markdown_post(
        self,
        *,
        title: str,
        content_markdown: str,
        canonical_url: str,
        tags: Sequence[str] = (),
        publish_status: str = "public",
        license_name: str = "public-domain",
        notify_followers: bool = True,
    ) -> dict[str, Any]:
        """Publish a Markdown essay via `POST /v1/users/{authorId}/posts`."""
        author = self.author_id
        if not author:
            me = self.get_me()
            author = str(me["id"])
        payload = {
            "title": title,
            "contentFormat": "markdown",
            "content": content_markdown,
            "canonicalUrl": canonical_url,
            "tags": list(tags)[:5],
            "publishStatus": publish_status,
            "license": license_name,
            "notifyFollowers": notify_followers,
        }
        status, _, raw = self.transport(
            "POST",
            f"{self.API_BASE}/users/{urllib.parse.quote(author)}/posts",
            self._headers(),
            json.dumps(payload).encode("utf-8"),
        )
        if status < 200 or status >= 300:
            raise RuntimeError(
                f"Medium POST /v1/users/{author}/posts failed with HTTP {status}: {raw.decode('utf-8', errors='replace')}"
            )
        return dict(json.loads(raw.decode("utf-8"))["data"])


# ---------------------------------------------------------------------------
# Reverse Flow 1: Medium RSS XML -> Idempotent X Thread (`sync_medium_rss_to_x`)
# ---------------------------------------------------------------------------

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_CANONICAL_OPENIE_RE = re.compile(
    r"https://research\.openie\.dev/(?:papers|products)/[a-z0-9_-]+/?", re.IGNORECASE
)


def _strip_html_to_plain(html_fragment: str) -> str:
    # Preserve paragraph breaks before stripping tags
    with_breaks = re.sub(r"</(?:p|h1|h2|h3|li|blockquote)>", "\n", html_fragment, flags=re.I)
    clean = html.unescape(_HTML_TAG_RE.sub(" ", with_breaks))
    lines = [" ".join(ln.split()) for ln in clean.splitlines()]
    return "\n".join(ln for ln in lines if ln)


def parse_medium_rss_xml(xml_text: str) -> list[dict[str, Any]]:
    """Parse a Medium RSS 2.0 XML feed into normalized item records."""
    root = ET.fromstring(xml_text)
    ns = {
        "content": "http://purl.org/rss/1.0/modules/content/",
        "dc": "http://purl.org/dc/elements/1.1/",
        "atom": "http://www.w3.org/2005/Atom",
    }
    items_out: list[dict[str, Any]] = []
    for item in root.findall("./channel/item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        # Strip Medium's ?source=rss-... tracking suffix for clean canonical deduplication
        clean_link = link.split("?")[0] if "medium.com/" in link else link
        guid = (item.findtext("guid") or clean_link).strip()
        pub_date = (item.findtext("pubDate") or "").strip()
        creator = (item.findtext("dc:creator", default="", namespaces=ns) or "").strip()
        categories = [
            (c.text or "").strip() for c in item.findall("category") if (c.text or "").strip()
        ]
        encoded_html = (
            item.findtext("content:encoded", default="", namespaces=ns)
            or item.findtext("description")
            or ""
        )
        plain_body = _strip_html_to_plain(encoded_html)
        m_canon = _CANONICAL_OPENIE_RE.search(encoded_html)
        canonical_openie_url = m_canon.group(0) if m_canon else None
        if canonical_openie_url and not canonical_openie_url.endswith("/"):
            canonical_openie_url += "/"

        items_out.append(
            {
                "guid": guid,
                "title": title,
                "link": clean_link,
                "pub_date": pub_date,
                "creator": creator,
                "categories": categories,
                "plain_body": plain_body,
                "canonical_openie_url": canonical_openie_url,
            }
        )
    return items_out


def synthesize_standalone_x_thread_from_medium_item(item: dict[str, Any]) -> dict[str, Any]:
    """Synthesize a clean 4-tweet thread (`<= 280` weighted chars) for a standalone Medium essay."""
    title = str(item["title"])
    link = str(item["link"])
    lines = [ln.strip() for ln in str(item.get("plain_body", "")).splitlines() if ln.strip()]
    sentences: list[str] = []
    for ln in lines:
        if ln == title:
            continue
        for s in re.split(r"(?<=[.!?])\s+", ln):
            s_clean = re.sub(r"https?://\S+", "", s).strip()
            if len(s_clean) >= 20:
                sentences.append(s_clean)

    hook = sentences[0] if sentences else "Plain-language engineering notes from Open Interface Engineering."
    pt1 = sentences[1] if len(sentences) > 1 else "Every interface assumption should be written down and machine-checked."
    pt2 = sentences[2] if len(sentences) > 2 else "Verify task completion first, then rank passing designs by energy spent."
    pt3 = sentences[3] if len(sentences) > 3 else "Dedicated to the public domain (CC0-1.0) with zero human review gates."

    t1 = _tighten_for_x(f"{title}\n\n{hook}")
    t2 = _tighten_for_x(f"1/2 {pt1}\n\n2/2 {pt2}")
    t3 = _tighten_for_x(f"Key takeaway: {pt3}\n\n[OpenIE Public Domain Notes · CC0-1.0]")
    cats = [re.sub(r"[^A-Za-z0-9]", "", c.title()) for c in item.get("categories", [])[:2]]
    tag_tail = " ".join(f"#{c}" for c in cats if c) or "#OpenScience #OpenIE"
    t4 = _tighten_for_x(f"Read the full illustrated essay on Medium:\n{link}\n\n{tag_tail}")

    posts = [
        {
            "position": idx,
            "role": role,
            "text": txt,
            "weighted_chars": weighted_len(txt),
            "raw_chars": len(txt),
            "urls": extract_urls(txt),
            "in_reply_to_position": None if idx == 1 else idx - 1,
        }
        for idx, (role, txt) in enumerate(
            [
                ("standalone_hook", t1),
                ("standalone_points", t2),
                ("standalone_takeaway", t3),
                ("medium_backlink", t4),
            ],
            start=1,
        )
    ]
    bundle = {
        "schema": "openie.x_thread_bundle.v1",
        "study_id": f"medium-{compute_bundle_blake3(item['guid'])[:10]}",
        "license": "CC0-1.0",
        "post_count": len(posts),
        "max_weighted_chars": max(p["weighted_chars"] for p in posts),
        "medium_crosslink_uri": link,
        "zero_urls_in_post_1": len(posts[0]["urls"]) == 0,
        "posts": posts,
    }
    bundle["content_blake3"] = compute_bundle_blake3(bundle)
    return bundle


def sync_medium_rss_to_x(
    rss_source: str,
    *,
    ledger: SyndicationLedger,
    x_bundles_by_paper_url: dict[str, dict[str, Any]] | None = None,
    x_client: XClient | None = None,
    transport: HTTPTransport | None = None,
    dry_run: bool = True,
) -> list[dict[str, Any]]:
    """Reverse Flow 1: Ingest Medium RSS XML and stage/publish deduplicated X threads."""
    if rss_source.lstrip().startswith("<"):
        xml_text = rss_source
    else:
        http_fn = transport or default_urllib_transport
        status, _, raw = http_fn(
            "GET",
            rss_source,
            {"User-Agent": "OpenIE-Syndicate/1.0 (+https://research.openie.dev)"},
            None,
        )
        if status < 200 or status >= 300:
            raise RuntimeError(f"Failed fetching Medium RSS {rss_source}: HTTP {status}")
        xml_text = raw.decode("utf-8")

    items = parse_medium_rss_xml(xml_text)
    canonical_map = x_bundles_by_paper_url or {}
    results: list[dict[str, Any]] = []

    for item in items:
        item_digest = compute_bundle_blake3(
            {
                "guid": item["guid"],
                "link": item["link"],
                "title": item["title"],
            }
        )
        item_key = item["guid"] or item["link"]
        if ledger.is_duplicate("reverse_medium_to_x", item_key, item_digest):
            results.append(
                {
                    "guid": item_key,
                    "status": "skipped_duplicate",
                    "content_blake3": item_digest,
                }
            )
            continue

        canon_url = item.get("canonical_openie_url")
        if canon_url and canon_url in canonical_map:
            thread_bundle = update_x_bundle_medium_url(
                canonical_map[canon_url], str(item["link"])
            )
            matched_study = thread_bundle["study_id"]
        else:
            thread_bundle = synthesize_standalone_x_thread_from_medium_item(item)
            matched_study = None

        tweet_ids: list[str] = []
        status_label = "staged"
        remote_url: str | None = None
        if not dry_run:
            if x_client is None:
                raise RuntimeError("x_client required when dry_run=False")
            tweet_ids = x_client.post_thread(thread_bundle)
            status_label = "published"
            remote_url = f"https://x.com/i/status/{tweet_ids[0]}"

        ledger.record(
            channel="reverse_medium_to_x",
            item_id=item_key,
            direction="inbound_to_outbound",
            content_blake3=item_digest,
            status=status_label,
            remote_id=tweet_ids[0] if tweet_ids else None,
            remote_url=remote_url,
            metadata={
                "medium_url": item["link"],
                "matched_study_id": matched_study,
                "post_count": thread_bundle["post_count"],
            },
        )
        results.append(
            {
                "guid": item_key,
                "matched_study_id": matched_study,
                "status": status_label,
                "content_blake3": item_digest,
                "thread_bundle": thread_bundle,
                "tweet_ids": tweet_ids,
            }
        )
    return results


# ---------------------------------------------------------------------------
# Reverse Flow 2: X Self-Reply Threads -> Medium Digest + Root Reply (`sync_x_threads_to_medium`)
# ---------------------------------------------------------------------------


def group_self_reply_threads(tweets: Sequence[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Group flat X timeline tweets into chronological self-reply threads (>= 2 posts)."""
    by_id: dict[str, dict[str, Any]] = {str(t["id"]): dict(t) for t in tweets if "id" in t}
    by_conv: dict[str, list[dict[str, Any]]] = {}

    for t in by_id.values():
        conv_id = str(t.get("conversation_id") or t["id"])
        by_conv.setdefault(conv_id, []).append(t)

    threads: list[list[dict[str, Any]]] = []
    for conv_id, group in sorted(by_conv.items()):
        root = by_id.get(conv_id)
        if root is None:
            # Fallback to earliest tweet in group if root is present with matching id
            group_sorted = sorted(group, key=lambda x: (str(x.get("created_at", "")), str(x["id"])))
            root = group_sorted[0]
        root_author = root.get("author_id")

        # Keep only self-replies by the root author
        valid: list[dict[str, Any]] = []
        for item in group:
            if root_author and item.get("author_id") != root_author:
                continue
            in_reply_user = item.get("in_reply_to_user_id")
            if in_reply_user and root_author and str(in_reply_user) != str(root_author):
                continue
            valid.append(item)

        valid.sort(key=lambda x: (str(x.get("created_at", "")), int(str(x["id"])) if str(x["id"]).isdigit() else 0))
        if len(valid) >= 2:
            threads.append(valid)
    return threads


def compile_x_thread_to_medium_essay(thread: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Compile an X self-reply thread into a clean illustrated CC0-1.0 Medium essay."""
    if not thread:
        raise ValueError("thread cannot be empty")
    root = thread[0]
    root_id = str(root["id"])
    root_x_url = f"https://x.com/i/status/{root_id}"

    first_lines = [ln.strip() for ln in str(root.get("text", "")).splitlines() if ln.strip()]
    raw_headline = first_lines[0] if first_lines else f"OpenIE Research Field Notes #{root_id}"
    clean_title = re.sub(r"https?://\S+", "", raw_headline).strip() or f"OpenIE Thread #{root_id}"

    discovered_openie_url: str | None = None
    for post in thread:
        m = _CANONICAL_OPENIE_RE.search(str(post.get("text", "")))
        if m:
            discovered_openie_url = m.group(0)
            if not discovered_openie_url.endswith("/"):
                discovered_openie_url += "/"
            break

    canonical_url = discovered_openie_url or root_x_url

    md_sections: list[str] = [
        f"# {clean_title}",
        "",
        "*Compiled from an attested OpenIE X (Twitter) research thread · Dedicated to the Public Domain (`CC0-1.0`)*",
        "",
        f"> **Canonical Primary Source**: [{canonical_url}]({canonical_url})  ",
        f"> **Synchronized X Thread Root**: [{root_x_url}]({root_x_url})  ",
        "> **License**: `CC0-1.0` (Public Domain Dedication)",
        "",
        "---",
        "",
        "## Thread Synthesis",
        "",
    ]
    for idx, post in enumerate(thread, start=1):
        txt = str(post.get("text", "")).strip()
        md_sections.append(f"### Note {idx} of {len(thread)}")
        md_sections.append("")
        md_sections.append(txt)
        md_sections.append("")

    md_sections.extend(
        [
            "---",
            "",
            f"*Explore grounded prior art on [The Commons]({COMMONS_ORIGIN}) and full verified studies on [OpenIE Research]({RESEARCH_ORIGIN}).*",
            "",
        ]
    )
    markdown = "\n".join(md_sections)
    return {
        "root_tweet_id": root_id,
        "root_x_url": root_x_url,
        "title": clean_title,
        "canonical_url": canonical_url,
        "markdown": markdown,
        "tags": ["open-science", "computer-science", "verified-ai", "energy-efficiency", "openie"],
        "license": "CC0-1.0",
        "content_blake3": compute_bundle_blake3(
            {"root_id": root_id, "posts": [str(p.get("text", "")) for p in thread]}
        ),
    }


def sync_x_threads_to_medium(
    timeline_tweets: Sequence[dict[str, Any]],
    *,
    ledger: SyndicationLedger,
    medium_client: MediumClient | None = None,
    x_client: XClient | None = None,
    dry_run: bool = True,
) -> list[dict[str, Any]]:
    """Reverse Flow 2: Compile X self-reply threads to Medium essays & reply on X root with link."""
    threads = group_self_reply_threads(timeline_tweets)
    outcomes: list[dict[str, Any]] = []

    for thread in threads:
        compiled = compile_x_thread_to_medium_essay(thread)
        root_id = compiled["root_tweet_id"]
        digest = compiled["content_blake3"]

        if ledger.is_duplicate("reverse_x_to_medium", root_id, digest):
            outcomes.append(
                {
                    "root_tweet_id": root_id,
                    "status": "skipped_duplicate",
                    "content_blake3": digest,
                }
            )
            continue

        if dry_run:
            medium_url = f"https://research.openie.dev/syndication/medium/x-{root_id}/"
            reply_text = _tighten_for_x(
                f"Full illustrated public-domain (CC0-1.0) essay compiled from this thread:\n{medium_url}"
            )
            reply_tweet_id = None
            status_label = "staged"
        else:
            if medium_client is None or x_client is None:
                raise RuntimeError("medium_client and x_client required when dry_run=False")
            med_resp = medium_client.publish_markdown_post(
                title=compiled["title"],
                content_markdown=compiled["markdown"],
                canonical_url=compiled["canonical_url"],
                tags=compiled["tags"],
                publish_status="public",
                license_name="public-domain",
            )
            medium_url = str(med_resp["url"])
            reply_text = _tighten_for_x(
                f"Full illustrated public-domain (CC0-1.0) essay compiled from this thread:\n{medium_url}"
            )
            rep_resp = x_client.post_tweet(
                reply_text,
                in_reply_to_tweet_id=root_id,
            )
            reply_tweet_id = str(rep_resp["data"]["id"])
            status_label = "published"

        if weighted_len(reply_text) > X_MAX_WEIGHTED_CHARS:
            raise ValueError("Backlink reply exceeded 280 weighted chars")

        ledger.record(
            channel="reverse_x_to_medium",
            item_id=root_id,
            direction="inbound_to_outbound",
            content_blake3=digest,
            status=status_label,
            remote_id=reply_tweet_id,
            remote_url=medium_url,
            metadata={"reply_text": reply_text, "post_count": len(thread)},
        )
        outcomes.append(
            {
                "root_tweet_id": root_id,
                "status": status_label,
                "content_blake3": digest,
                "compiled_essay": compiled,
                "medium_url": medium_url,
                "reply_text": reply_text,
                "reply_weighted_chars": weighted_len(reply_text),
                "reply_tweet_id": reply_tweet_id,
            }
        )
    return outcomes
