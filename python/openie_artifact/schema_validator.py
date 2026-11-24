# SPDX-License-Identifier: Apache-2.0
"""Deterministic validator for `schema/openie-artifact-v1.schema.json` (Draft 2020-12)."""

from __future__ import annotations

import math
import re
from typing import Any

CANONICAL_ID_RE = re.compile(
    r"^blake3:(paper|tv|radio|tutorial|humanoid_prior_art|humanoid_morphology|blueprint|concept):([0-9a-f]{64})$"
)
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX128_RE = re.compile(r"^[0-9a-f]{128}$")
GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
LOCALE_RE = re.compile(r"^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$")
AAC_ID_RE = re.compile(r"^aac:[a-z0-9_-]+$")
AAC_URI_RE = re.compile(r"^https://commons\.openie\.dev/aac/[a-z0-9_-]+$")

ALLOWED_KINDS = frozenset(
    {
        "paper",
        "tv",
        "radio",
        "tutorial",
        "humanoid_prior_art",
        "humanoid_morphology",
        "blueprint",
        "concept",
    }
)
ALLOWED_LICENSES = frozenset({"CC0-1.0", "Apache-2.0", "CERN-OHL-S-2.0"})
ALLOWED_EVIDENCE_CLASSES = frozenset({"measured_j", "reported_j", "est_j", "unmetered"})
ALLOWED_STATUSES = frozenset({"verified", "flagged_do_not_ship", "draft"})
ALLOWED_TOP_KEYS = frozenset(
    {
        "canonical_id",
        "artifact_kind",
        "slug",
        "title",
        "summary",
        "upstream_url",
        "tags",
        "provenance_chain",
        "energy_cost_j",
        "difficulty_rung",
        "verification_status",
        "modality_variants",
        "license",
        "interchange_envelope",
    }
)
REQUIRED_TOP_KEYS = frozenset(
    {
        "canonical_id",
        "provenance_chain",
        "energy_cost_j",
        "difficulty_rung",
        "verification_status",
        "modality_variants",
        "license",
        "interchange_envelope",
    }
)


class SchemaValidationError(ValueError):
    """Raised when an artifact violates `openie-artifact-v1.schema.json`."""


def _is_strict_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_finite_number(v: Any) -> bool:
    return (
        isinstance(v, (int, float))
        and not isinstance(v, bool)
        and math.isfinite(float(v))
    )


def _check_keys(
    obj: Any,
    path: str,
    required: set[str] | frozenset[str],
    allowed: set[str] | frozenset[str],
) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise SchemaValidationError(f"{path}: expected object")
    missing = sorted(required - set(obj.keys()))
    if missing:
        raise SchemaValidationError(f"{path}: missing required keys {missing}")
    extra = sorted(set(obj.keys()) - allowed)
    if extra:
        raise SchemaValidationError(f"{path}: unexpected keys {extra}")
    return obj


def validate_openie_artifact(artifact: dict[str, Any]) -> None:
    """Validate `artifact` against all Draft 2020-12 constraints of v1."""
    _check_keys(artifact, "$", REQUIRED_TOP_KEYS, ALLOWED_TOP_KEYS)

    cid = artifact["canonical_id"]
    if not isinstance(cid, str):
        raise SchemaValidationError("$.canonical_id: must be string")
    m_cid = CANONICAL_ID_RE.match(cid)
    if not m_cid:
        raise SchemaValidationError(f"$.canonical_id: invalid pattern {cid!r}")
    cid_kind, cid_hash = m_cid.group(1), m_cid.group(2)

    if "artifact_kind" in artifact:
        ak = artifact["artifact_kind"]
        if ak not in ALLOWED_KINDS or ak != cid_kind:
            raise SchemaValidationError(
                f"$.artifact_kind: {ak!r} does not match canonical_id kind {cid_kind!r}"
            )
    if "slug" in artifact:
        slug = artifact["slug"]
        if not isinstance(slug, str) or not SLUG_RE.match(slug) or len(slug) > 256:
            raise SchemaValidationError(f"$.slug: invalid slug {slug!r}")
    for s_key in ("title", "summary", "upstream_url"):
        if s_key in artifact:
            val = artifact[s_key]
            if not isinstance(val, str) or len(val) == 0:
                raise SchemaValidationError(f"$.{s_key}: must be non-empty string")
    if "tags" in artifact:
        tags = artifact["tags"]
        if (
            not isinstance(tags, list)
            or any(not isinstance(t, str) or not t for t in tags)
            or len(tags) != len(set(tags))
        ):
            raise SchemaValidationError("$.tags: must be unique non-empty strings")

    # 1. provenance_chain
    prov_keys = {
        "content_blake3",
        "sha256",
        "ed25519_pubkey",
        "ed25519_sig",
        "tx_time_utc",
        "lineage_parents",
        "anchors",
    }
    prov = _check_keys(artifact["provenance_chain"], "$.provenance_chain", prov_keys, prov_keys)
    for h_key in ("content_blake3", "sha256", "ed25519_pubkey"):
        if not isinstance(prov[h_key], str) or not HEX64_RE.match(prov[h_key]):
            raise SchemaValidationError(f"$.provenance_chain.{h_key}: invalid 64-hex")
    if prov["content_blake3"] != cid_hash:
        raise SchemaValidationError(
            "$.provenance_chain.content_blake3: must match canonical_id digest"
        )
    if not isinstance(prov["ed25519_sig"], str) or not HEX128_RE.match(prov["ed25519_sig"]):
        raise SchemaValidationError("$.provenance_chain.ed25519_sig: invalid 128-hex")
    if not isinstance(prov["tx_time_utc"], str) or not UTC_RE.match(prov["tx_time_utc"]):
        raise SchemaValidationError("$.provenance_chain.tx_time_utc: invalid UTC timestamp")
    lp = prov["lineage_parents"]
    if not isinstance(lp, list) or len(lp) != len(set(lp)):
        raise SchemaValidationError("$.provenance_chain.lineage_parents: must be unique array")
    for p_id in lp:
        if not isinstance(p_id, str) or not CANONICAL_ID_RE.match(p_id):
            raise SchemaValidationError(
                f"$.provenance_chain.lineage_parents: invalid canonical_id {p_id!r}"
            )
    anchors = _check_keys(
        prov["anchors"],
        "$.provenance_chain.anchors",
        set(),
        {
            "git_commit",
            "rfc3161_tsr",
            "opentimestamps_ots",
            "drand_round",
            "jcr1_receipt_blake3",
        },
    )
    if "git_commit" in anchors and (
        not isinstance(anchors["git_commit"], str)
        or not GIT_COMMIT_RE.match(anchors["git_commit"])
    ):
        raise SchemaValidationError("$.provenance_chain.anchors.git_commit: invalid hex")
    for a_str in ("rfc3161_tsr", "opentimestamps_ots"):
        if a_str in anchors and (
            not isinstance(anchors[a_str], str) or len(anchors[a_str]) == 0
        ):
            raise SchemaValidationError(f"$.provenance_chain.anchors.{a_str}: invalid")
    if "drand_round" in anchors and (
        not _is_strict_int(anchors["drand_round"]) or anchors["drand_round"] < 1
    ):
        raise SchemaValidationError("$.provenance_chain.anchors.drand_round: invalid")
    if "jcr1_receipt_blake3" in anchors and (
        not isinstance(anchors["jcr1_receipt_blake3"], str)
        or not HEX64_RE.match(anchors["jcr1_receipt_blake3"])
    ):
        raise SchemaValidationError(
            "$.provenance_chain.anchors.jcr1_receipt_blake3: invalid 64-hex"
        )

    # 2. energy_cost_j (non-mixing invariants!)
    ekeys = {
        "evidence_class",
        "joules",
        "meter_or_formula",
        "board_metered",
        "landauer_300k_bits_equiv",
    }
    ec = _check_keys(artifact["energy_cost_j"], "$.energy_cost_j", ekeys, ekeys)
    ev = ec["evidence_class"]
    if ev not in ALLOWED_EVIDENCE_CLASSES:
        raise SchemaValidationError(f"$.energy_cost_j.evidence_class: invalid {ev!r}")
    if not isinstance(ec["meter_or_formula"], str) or not ec["meter_or_formula"]:
        raise SchemaValidationError("$.energy_cost_j.meter_or_formula: must be non-empty")
    if not isinstance(ec["board_metered"], bool):
        raise SchemaValidationError("$.energy_cost_j.board_metered: must be boolean")

    if ev == "unmetered":
        if ec["board_metered"] is not False:
            raise SchemaValidationError("$.energy_cost_j: unmetered must have board_metered=false")
        if ec["joules"] is not None or ec["landauer_300k_bits_equiv"] is not None:
            raise SchemaValidationError(
                "$.energy_cost_j: unmetered must have joules=null and landauer_300k_bits_equiv=null"
            )
    else:
        expected_board = ev == "measured_j"
        if ec["board_metered"] is not expected_board:
            raise SchemaValidationError(
                f"$.energy_cost_j: {ev} requires board_metered={expected_board}"
            )
        if not _is_finite_number(ec["joules"]) or float(ec["joules"]) <= 0.0:
            raise SchemaValidationError(f"$.energy_cost_j.joules: {ev} requires positive number")
        if (
            not _is_finite_number(ec["landauer_300k_bits_equiv"])
            or float(ec["landauer_300k_bits_equiv"]) <= 0.0
        ):
            raise SchemaValidationError(
                f"$.energy_cost_j.landauer_300k_bits_equiv: {ev} requires positive number"
            )

    # 3. difficulty_rung
    dr = _check_keys(
        artifact["difficulty_rung"],
        "$.difficulty_rung",
        {"rung", "rung_name", "phase", "compilation_threshold_crossed"},
        {"rung", "rung_name", "phase", "compilation_threshold_crossed", "notes"},
    )
    if not _is_strict_int(dr["rung"]) or not (1 <= dr["rung"] <= 9):
        raise SchemaValidationError("$.difficulty_rung.rung: must be integer 1..9")
    if not isinstance(dr["rung_name"], str) or not dr["rung_name"]:
        raise SchemaValidationError("$.difficulty_rung.rung_name: must be non-empty string")
    if not _is_strict_int(dr["phase"]) or dr["phase"] not in (1, 2):
        raise SchemaValidationError("$.difficulty_rung.phase: must be integer 1 or 2")
    if not isinstance(dr["compilation_threshold_crossed"], bool):
        raise SchemaValidationError(
            "$.difficulty_rung.compilation_threshold_crossed: must be boolean"
        )
    if "notes" in dr and not isinstance(dr["notes"], str):
        raise SchemaValidationError("$.difficulty_rung.notes: must be string")

    # 4. verification_status
    vs_keys = {
        "status",
        "human_in_gate",
        "scientific_gate",
        "translation_gate",
        "accessibility_gate",
    }
    vs = _check_keys(artifact["verification_status"], "$.verification_status", vs_keys, vs_keys)
    if vs["status"] not in ALLOWED_STATUSES:
        raise SchemaValidationError(f"$.verification_status.status: invalid {vs['status']!r}")
    if vs["human_in_gate"] is not False:
        raise SchemaValidationError("$.verification_status.human_in_gate: MUST be false")

    sg = _check_keys(
        vs["scientific_gate"],
        "$.verification_status.scientific_gate",
        {
            "passed",
            "lean_kernel_checked",
            "sorry_count",
            "custom_axiom_count",
            "of_reduce_bool_count",
            "energy_non_mixing_ok",
            "failure_reasons",
        },
        {
            "passed",
            "lean_kernel_checked",
            "lean_version",
            "kernel_count",
            "sorry_count",
            "custom_axiom_count",
            "of_reduce_bool_count",
            "bwrap_sandboxed",
            "sat_miter_digest",
            "energy_non_mixing_ok",
            "failure_reasons",
        },
    )
    for b_k in ("passed", "lean_kernel_checked", "energy_non_mixing_ok"):
        if not isinstance(sg[b_k], bool):
            raise SchemaValidationError(f"scientific_gate.{b_k}: must be boolean")
    for i_k in ("sorry_count", "custom_axiom_count", "of_reduce_bool_count"):
        if not _is_strict_int(sg[i_k]) or sg[i_k] < 0:
            raise SchemaValidationError(f"scientific_gate.{i_k}: must be integer >= 0")
    if "kernel_count" in sg and (
        not _is_strict_int(sg["kernel_count"]) or sg["kernel_count"] < 0
    ):
        raise SchemaValidationError("scientific_gate.kernel_count: must be integer >= 0")
    if "lean_version" in sg and not isinstance(sg["lean_version"], str):
        raise SchemaValidationError("scientific_gate.lean_version: must be string")
    if "bwrap_sandboxed" in sg and not isinstance(sg["bwrap_sandboxed"], bool):
        raise SchemaValidationError("scientific_gate.bwrap_sandboxed: must be boolean")
    if "sat_miter_digest" in sg and sg["sat_miter_digest"] is not None:
        if not isinstance(sg["sat_miter_digest"], str) or not HEX64_RE.match(
            sg["sat_miter_digest"]
        ):
            raise SchemaValidationError("scientific_gate.sat_miter_digest: invalid 64-hex")
    if not isinstance(sg["failure_reasons"], list) or any(
        not isinstance(r, str) for r in sg["failure_reasons"]
    ):
        raise SchemaValidationError("scientific_gate.failure_reasons: must be string[]")

    tg_keys = {
        "passed",
        "evaluated_locales",
        "min_bleu4",
        "min_chrf_pp",
        "min_comet_proxy",
        "numeric_id_conservation_ok",
        "consecutive_failures",
        "retry_triggered",
        "quarantined_do_not_ship",
        "failure_reasons",
    }
    tg = _check_keys(
        vs["translation_gate"], "$.verification_status.translation_gate", tg_keys, tg_keys
    )
    for b_k in (
        "passed",
        "numeric_id_conservation_ok",
        "retry_triggered",
        "quarantined_do_not_ship",
    ):
        if not isinstance(tg[b_k], bool):
            raise SchemaValidationError(f"translation_gate.{b_k}: must be boolean")
    if not isinstance(tg["evaluated_locales"], list) or any(
        not isinstance(loc, str) or not LOCALE_RE.match(loc)
        for loc in tg["evaluated_locales"]
    ):
        raise SchemaValidationError("translation_gate.evaluated_locales: invalid locales")
    for m_k, hi in (("min_bleu4", 100.0), ("min_chrf_pp", 100.0), ("min_comet_proxy", 1.0)):
        if not _is_finite_number(tg[m_k]) or not (0.0 <= float(tg[m_k]) <= hi):
            raise SchemaValidationError(f"translation_gate.{m_k}: out of range")
    if not _is_strict_int(tg["consecutive_failures"]) or tg["consecutive_failures"] < 0:
        raise SchemaValidationError("translation_gate.consecutive_failures: invalid")
    if not isinstance(tg["failure_reasons"], list) or any(
        not isinstance(r, str) for r in tg["failure_reasons"]
    ):
        raise SchemaValidationError("translation_gate.failure_reasons: must be string[]")

    ag_keys = {
        "passed",
        "wcag_22_aa_captions_ok",
        "easy_read_ok",
        "easy_read_avg_words_per_sentence",
        "unexplained_acronyms",
        "audio_description_ok",
        "aac_concepts_resolved",
        "failure_reasons",
    }
    ag = _check_keys(
        vs["accessibility_gate"],
        "$.verification_status.accessibility_gate",
        ag_keys,
        ag_keys,
    )
    for b_k in (
        "passed",
        "wcag_22_aa_captions_ok",
        "easy_read_ok",
        "audio_description_ok",
        "aac_concepts_resolved",
    ):
        if not isinstance(ag[b_k], bool):
            raise SchemaValidationError(f"accessibility_gate.{b_k}: must be boolean")
    if (
        not _is_finite_number(ag["easy_read_avg_words_per_sentence"])
        or float(ag["easy_read_avg_words_per_sentence"]) < 0.0
    ):
        raise SchemaValidationError("accessibility_gate.easy_read_avg_words_per_sentence")
    for arr_k in ("unexplained_acronyms", "failure_reasons"):
        if not isinstance(ag[arr_k], list) or any(
            not isinstance(x, str) for x in ag[arr_k]
        ):
            raise SchemaValidationError(f"accessibility_gate.{arr_k}: must be string[]")

    # 5. modality_variants
    mv = _check_keys(
        artifact["modality_variants"],
        "$.modality_variants",
        set(),
        {
            "text",
            "audio",
            "video",
            "structure_3d",
            "plain_easy_read",
            "audio_description",
            "aac_concepts",
            "multilingual",
        },
    )
    if "text" in mv:
        tx = _check_keys(
            mv["text"],
            "$.modality_variants.text",
            {"uri", "media_type", "summary"},
            {"uri", "media_type", "summary", "sha256"},
        )
        for k in ("uri", "media_type", "summary"):
            if not isinstance(tx[k], str) or not tx[k]:
                raise SchemaValidationError(f"modality_variants.text.{k}: non-empty string")
        if "sha256" in tx and (
            not isinstance(tx["sha256"], str) or not HEX64_RE.match(tx["sha256"])
        ):
            raise SchemaValidationError("modality_variants.text.sha256: invalid 64-hex")
    if "audio" in mv:
        au = _check_keys(
            mv["audio"],
            "$.modality_variants.audio",
            {"uri", "media_type", "duration_sec", "captions_vtt_uri", "transcript_uri"},
            {
                "uri",
                "media_type",
                "duration_sec",
                "captions_vtt_uri",
                "transcript_uri",
                "sha256",
            },
        )
        for k in ("uri", "media_type", "captions_vtt_uri", "transcript_uri"):
            if not isinstance(au[k], str) or not au[k]:
                raise SchemaValidationError(f"modality_variants.audio.{k}: non-empty")
        if not _is_finite_number(au["duration_sec"]) or float(au["duration_sec"]) <= 0.0:
            raise SchemaValidationError("modality_variants.audio.duration_sec: > 0")
    if "video" in mv:
        vd = _check_keys(
            mv["video"], "$.modality_variants.video", set(), {"15s", "45s", "90s", "180s"}
        )
        for slot, cut in vd.items():
            ck = {
                "video_uri",
                "vtt_uri",
                "duration_s",
                "bytes",
                "sha256",
                "hook",
                "transcript",
            }
            c_obj = _check_keys(cut, f"$.modality_variants.video.{slot}", ck, ck)
            for k in ("video_uri", "vtt_uri", "hook", "transcript"):
                if not isinstance(c_obj[k], str) or not c_obj[k]:
                    raise SchemaValidationError(f"video.{slot}.{k}: non-empty string")
            if (
                not _is_finite_number(c_obj["duration_s"])
                or float(c_obj["duration_s"]) <= 0.0
            ):
                raise SchemaValidationError(f"video.{slot}.duration_s: > 0")
            if not _is_strict_int(c_obj["bytes"]) or c_obj["bytes"] < 1:
                raise SchemaValidationError(f"video.{slot}.bytes: positive integer")
            if not isinstance(c_obj["sha256"], str) or not HEX64_RE.match(c_obj["sha256"]):
                raise SchemaValidationError(f"video.{slot}.sha256: invalid 64-hex")
    if "structure_3d" in mv:
        s3 = _check_keys(
            mv["structure_3d"],
            "$.modality_variants.structure_3d",
            {"uri", "format", "id"},
            {"uri", "format", "id", "sha256"},
        )
        if s3["format"] not in {"glb", "urdf", "mjcf", "step", "cutaway_3d"}:
            raise SchemaValidationError("structure_3d.format: invalid")
        for k in ("uri", "id"):
            if not isinstance(s3[k], str) or not s3[k]:
                raise SchemaValidationError(f"structure_3d.{k}: non-empty string")
    if "plain_easy_read" in mv:
        er = _check_keys(
            mv["plain_easy_read"],
            "$.modality_variants.plain_easy_read",
            {"text", "bullets", "avg_words_per_sentence"},
            {"text", "bullets", "avg_words_per_sentence"},
        )
        if not isinstance(er["text"], str) or not er["text"]:
            raise SchemaValidationError("plain_easy_read.text: non-empty string")
        if (
            not isinstance(er["bullets"], list)
            or len(er["bullets"]) == 0
            or any(not isinstance(b, str) or not b for b in er["bullets"])
        ):
            raise SchemaValidationError("plain_easy_read.bullets: non-empty string[]")
        if not _is_finite_number(er["avg_words_per_sentence"]) or not (
            0.0 < float(er["avg_words_per_sentence"]) <= 18.0
        ):
            raise SchemaValidationError(
                "plain_easy_read.avg_words_per_sentence: must be in (0, 18]"
            )
    if "audio_description" in mv:
        ad = _check_keys(
            mv["audio_description"],
            "$.modality_variants.audio_description",
            {"track_uri", "script", "voicing"},
            {"track_uri", "script", "voicing", "ducking_db"},
        )
        for k in ("track_uri", "script"):
            if not isinstance(ad[k], str) or not ad[k]:
                raise SchemaValidationError(f"audio_description.{k}: non-empty string")
        if ad["voicing"] not in {"machine", "human"}:
            raise SchemaValidationError("audio_description.voicing: invalid")
    if "aac_concepts" in mv:
        aac = mv["aac_concepts"]
        if not isinstance(aac, list) or len(aac) == 0:
            raise SchemaValidationError("aac_concepts: non-empty array")
        for idx, item in enumerate(aac):
            ak = {"concept_id", "label", "symbol_anchor_uri"}
            it = _check_keys(item, f"$.modality_variants.aac_concepts[{idx}]", ak, ak)
            if not isinstance(it["concept_id"], str) or not AAC_ID_RE.match(
                it["concept_id"]
            ):
                raise SchemaValidationError("aac_concepts.concept_id: invalid")
            if not isinstance(it["label"], str) or not it["label"]:
                raise SchemaValidationError("aac_concepts.label: non-empty")
            if not isinstance(it["symbol_anchor_uri"], str) or not AAC_URI_RE.match(
                it["symbol_anchor_uri"]
            ):
                raise SchemaValidationError("aac_concepts.symbol_anchor_uri: invalid")
    if "multilingual" in mv:
        ml = mv["multilingual"]
        if not isinstance(ml, dict):
            raise SchemaValidationError("multilingual: must be object")
        for loc, entry in ml.items():
            if not isinstance(loc, str) or not LOCALE_RE.match(loc):
                raise SchemaValidationError(f"multilingual locale {loc!r}: invalid")
            mk = {
                "title",
                "plain_easy_read",
                "bleu4",
                "chrf_pp",
                "comet_proxy",
                "numeric_id_conserved",
            }
            m_obj = _check_keys(entry, f"$.modality_variants.multilingual.{loc}", mk, mk)
            for sk in ("title", "plain_easy_read"):
                if not isinstance(m_obj[sk], str) or not m_obj[sk]:
                    raise SchemaValidationError(f"multilingual.{loc}.{sk}: non-empty")
            for nk, hi in (("bleu4", 100.0), ("chrf_pp", 100.0), ("comet_proxy", 1.0)):
                if not _is_finite_number(m_obj[nk]) or not (0.0 <= float(m_obj[nk]) <= hi):
                    raise SchemaValidationError(f"multilingual.{loc}.{nk}: range error")
            if not isinstance(m_obj["numeric_id_conserved"], bool):
                raise SchemaValidationError(f"multilingual.{loc}.numeric_id_conserved")

    # 6. license
    if artifact["license"] not in ALLOWED_LICENSES:
        raise SchemaValidationError(f"$.license: invalid {artifact['license']!r}")

    # 7. interchange_envelope
    ie = _check_keys(
        artifact["interchange_envelope"],
        "$.interchange_envelope",
        {
            "format",
            "wai_version",
            "media_type",
            "capability",
            "fallback",
            "envelope_blake3",
            "envelope_bytes",
        },
        {
            "format",
            "wai_version",
            "media_type",
            "capability",
            "fallback",
            "envelope_blake3",
            "envelope_bytes",
            "envelope_uri",
        },
    )
    if ie["format"] != "WAI1":
        raise SchemaValidationError("interchange_envelope.format: must be 'WAI1'")
    if ie["wai_version"] != "1.0":
        raise SchemaValidationError("interchange_envelope.wai_version: must be '1.0'")
    if ie["media_type"] != "application/vnd.wai":
        raise SchemaValidationError(
            "interchange_envelope.media_type: must be 'application/vnd.wai'"
        )
    if not isinstance(ie["capability"], str) or not ie["capability"]:
        raise SchemaValidationError("interchange_envelope.capability: non-empty string")
    if ie["fallback"] is not None and (
        not isinstance(ie["fallback"], str) or not ie["fallback"]
    ):
        raise SchemaValidationError("interchange_envelope.fallback: string or null")
    if not isinstance(ie["envelope_blake3"], str) or not HEX64_RE.match(
        ie["envelope_blake3"]
    ):
        raise SchemaValidationError("interchange_envelope.envelope_blake3: invalid 64-hex")
    if not _is_strict_int(ie["envelope_bytes"]) or ie["envelope_bytes"] < 14:
        raise SchemaValidationError("interchange_envelope.envelope_bytes: integer >= 14")
    if "envelope_uri" in ie and (
        not isinstance(ie["envelope_uri"], str) or not ie["envelope_uri"]
    ):
        raise SchemaValidationError("interchange_envelope.envelope_uri: non-empty string")
