# SPDX-License-Identifier: Apache-2.0
"""Deterministic Verification Gate Library (Step 3 — Zero Humans in the Gates).

Implements:
  - `ScientificGate`: Lean 4.36.0 6-kernel `bwrap` proof receipts (`0 sorry`,
    `0 custom axioms`, `0 ofReduceBool`), deterministic SAT/miter digests, and
    `measured_j` / `reported_j` / `est_j` / `unmetered` non-mixing invariants.
  - `TranslationGate`: Deterministic `BLEU-4` + `chrF++` + semantic embedding
    `COMET`-proxy score + numeric/identifier conservation check; triggers automatic
    retry callback on failure #1 and stamps `flagged_do_not_ship` on 2 consecutive
    failures.
  - `AccessibilityGate`: WCAG 2.2 AA caption/transcript presence, Easy-Read sentence
    length (`<= 18.0` words/sentence avg) & acronym-free plain text, audio-description
    track pointer, and AAC Concepts anchor resolution.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable

from .crypto import blake3_hex, canonical_jcs_bytes

LANDAUER_300K_J_PER_BIT = 1.380649e-23 * 300.0 * math.log(2.0)  # 2.8709319022672855e-21 J

EXPECTED_SIX_LEAN_KERNELS = frozenset(
    {
        "lean4-v4.36.0",
        "lean4lean",
        "nanoda",
        "leanchecker",
        "con-leche",
        "con-ron",
    }
)

STANDARD_LEAN_AXIOMS = frozenset(
    {
        "propext",
        "Quot.sound",
        "Classical.choice",
    }
)

BOARD_INSTRUMENT_TOKENS = (
    "ina238",
    "ina3221",
    "kv260",
    "shunt",
    "board power sensor",
    "circuit-board",
)
SOFTWARE_COUNTER_TOKENS = (
    "rapl",
    "nvml",
    "ioreport",
    "proc_pid_rusage",
    "ri_energy_nj",
)

# Canonical OpenIE Commons AAC Concept Registry (`https://commons.openie.dev/aac/<slug>`)
AAC_CONCEPT_REGISTRY: dict[str, dict[str, str]] = {
    f"aac:{slug}": {
        "label": label,
        "symbol_anchor_uri": f"https://commons.openie.dev/aac/{slug}",
    }
    for slug, label in [
        ("goal-agent", "Agent aiming at a goal"),
        ("energy-budget", "Energy budget in joules"),
        ("safety-gate", "Independent safety check gate"),
        ("receipt-log", "Signed verification receipt"),
        ("formal-proof", "Mathematical proof check"),
        ("truth-table", "Fast lookup table"),
        ("state-machine", "Step-by-step state machine"),
        ("zero-clock-sleep", "Sleep until needed without polling"),
        ("quorum-signal", "Group threshold signal"),
        ("consent-firewall", "Opt-in neural consent switch"),
        ("time-horizon", "Future horizon and fresh salt"),
        ("open-science", "Open public research commons"),
        ("audio-broadcast", "Multi-voice audio broadcast"),
        ("video-explainer", "Captioned visual study film"),
        ("interactive-lab", "Hands-on interactive experiment"),
        ("humanoid-robot", "Humanoid robot body and joints"),
        ("prior-art", "Historical public invention record"),
        ("open-hardware", "Open hardware mechanical design"),
        ("bipedal-balance", "Two-legged walking balance"),
        ("dexterous-hand", "Articulated grasping hand"),
        ("sensor-vision", "Camera and distance sensing"),
        ("thermal-limit", "Safe temperature boundary"),
        ("language-translation", "Verified multilingual translation"),
        ("easy-read", "Plain words for every reader"),
        ("compiler-check", "Verified program compilation"),
        ("version-control", "Conflict-free change history"),
        ("lockstep-replay", "Identical replay across computers"),
        ("economic-satiation", "Task finish line and cost"),
        ("unsiloed-envelope", "Unified portable media envelope"),
        ("sim-to-real", "Simulation to physical robot transfer"),
        ("mobile-phone", "Open handset and radio communication"),
        ("wearable-device", "Body-worn sensor and assistive device"),
        ("electric-aircraft", "Vertical electric flight and propulsion"),
        # 36 SKOS AAC Concepts from research.openie.dev/glossary/concepts.json
        ("commit-gate", "Safety check before permanent computer action"),
        ("receipt", "Saved record of prediction, outcome, and energy"),
        ("completeness-predicate", "Pass-or-fail test for finished work"),
        ("energy-to-correct-completion", "Smallest electrical energy to finish right"),
        ("value-of-information", "Gain from a new clue minus cost of looking"),
        ("impedance-tax", "Extra work wasted parsing human text between machines"),
        ("token", "Small word piece read one step at a time"),
        ("landauer-bound", "Physical floor of heat when one bit is erased"),
        ("cheapest-first-cascade", "Trying quick low-power tools before large models"),
        ("mixture-of-limits", "Lowest-energy tool that passes the test"),
        ("sigma-law-selector", "Rule picking best chance per unit of energy"),
        ("plateau", "Finish line where extra power cannot improve the answer"),
        ("replay-class", "Label showing exact rule versus guessing model"),
        ("software-reference-implementation", "Working program for testing rules before hardware"),
        ("est-j", "Math estimate of energy from step counts"),
        ("reported-j", "Energy reading from built-in chip power counter"),
        ("measured-j", "Real electrical energy from physical wire sensor"),
        ("trajectory-j", "Tiny physical work along molecular motion paths"),
        ("evidence-classes", "Honest labels separating math, counters, and hardware"),
        ("board-metered", "Badge true only with circuit-board power sensors"),
        ("form-and-fit", "Program written as clear states and step logs"),
        ("reality-code-engine", "Checked blueprint generating matching code across languages"),
        ("requires-change", "Clear message naming exact line and rule to fix"),
        ("kept-step", "Keeping old state safe when an invalid event arrives"),
        ("metabolic-intelligence", "Checked intelligence inside a strict energy budget"),
        ("wise-computer-automation", "Open software checking safety gates before acting"),
        ("universal-law-of-agency", "Agent holding a goal, respecting energy, able to refuse"),
        ("law-of-version-control", "Admitting edits whenever a named checker approves"),
        ("deterministic-null", "Frozen lookup table baseline with zero models"),
        ("good-turing-unseen-mass", "Counting one-time requests to estimate brand-new ones"),
        ("canonical-artifact", "Verified master record behind every accessible format"),
        ("wai1-envelope", "Signed digital wrapper proving origin and integrity"),
        ("easy-read-projection", "Short one-idea plain sentences with picture symbols"),
        ("audio-description-track", "Spoken voice track describing visuals for blind viewers"),
        ("codon-lookup-nucleus", "Sixteen-kilobyte sixty-four-state lookup core"),
        ("communication-tool-avalanche", "Scaling teams by sharing checked signals only when needed"),
    ]
}


def compute_landauer_300k_bits(joules: float) -> float:
    """Convert `joules` into 300 K Landauer bit-erasure equivalents (10 sig figs)."""
    return float(f"{joules / LANDAUER_300K_J_PER_BIT:.10g}")


# ---------------------------------------------------------------------------
# 1. ScientificGate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LeanProofReceipt:
    lean_version: str
    bwrap_sandboxed: bool
    kernels_verified: tuple[str, ...]
    theorem_count: int
    sorry_count: int
    axioms_used: tuple[str, ...]
    of_reduce_bool_count: int
    opaque_bypass_count: int = 0


@dataclass(frozen=True)
class SatMiterReceipt:
    suite_id: str
    lhs_ir_hash: str
    rhs_ir_hash: str
    vector_count: int
    mismatch_count: int
    status: str  # must be "unsat" for miter equivalence
    claimed_digest: str | None = None

    def compute_digest(self) -> str:
        doc = {
            "lhs_ir_hash": self.lhs_ir_hash,
            "mismatch_count": self.mismatch_count,
            "rhs_ir_hash": self.rhs_ir_hash,
            "status": self.status,
            "suite_id": self.suite_id,
            "vector_count": self.vector_count,
        }
        return blake3_hex(b"openie-sat-miter-v1\x00" + canonical_jcs_bytes(doc))


class ScientificGate:
    """Validates Lean 4.36.0 6-kernel bwrap receipts, SAT/miter digests, and energy invariants."""

    def evaluate(
        self,
        *,
        energy_cost_j: dict[str, Any],
        lean_receipt: LeanProofReceipt | None = None,
        sat_miter_receipt: SatMiterReceipt | None = None,
        telemetry_channels: list[dict[str, Any]] | None = None,
        human_in_gate: bool = False,
    ) -> dict[str, Any]:
        reasons: list[str] = []
        if human_in_gate is not False:
            reasons.append("human_in_gate_forbidden")

        # Energy non-mixing & Landauer consistency checks
        energy_ok = True
        ev = energy_cost_j.get("evidence_class")
        joules = energy_cost_j.get("joules")
        board = energy_cost_j.get("board_metered")
        meter_desc = str(energy_cost_j.get("meter_or_formula", ""))
        meter_lower = meter_desc.lower()
        landauer = energy_cost_j.get("landauer_300k_bits_equiv")

        if ev not in {"measured_j", "reported_j", "est_j", "unmetered"}:
            energy_ok = False
            reasons.append(f"invalid_evidence_class:{ev}")
        elif ev == "unmetered":
            if board is not False:
                energy_ok = False
                reasons.append("unmetered_claims_board_metered")
            if joules is not None:
                energy_ok = False
                reasons.append("unmetered_must_not_carry_numeric_joules")
            if landauer is not None:
                energy_ok = False
                reasons.append("unmetered_must_not_carry_landauer_bits")
        else:
            if (
                not isinstance(joules, (int, float))
                or isinstance(joules, bool)
                or not math.isfinite(float(joules))
                or float(joules) <= 0.0
            ):
                energy_ok = False
                reasons.append("non_positive_or_invalid_joules")
            else:
                expected_bits = compute_landauer_300k_bits(float(joules))
                if (
                    not isinstance(landauer, (int, float))
                    or isinstance(landauer, bool)
                    or not math.isfinite(float(landauer))
                    or abs(float(landauer) - expected_bits) / expected_bits > 1e-6
                ):
                    energy_ok = False
                    reasons.append("landauer_300k_bits_mismatch")

            if ev == "measured_j":
                if board is not True:
                    energy_ok = False
                    reasons.append("measured_j_requires_board_metered_true")
                if not any(tok in meter_lower for tok in BOARD_INSTRUMENT_TOKENS):
                    energy_ok = False
                    reasons.append("measured_j_missing_physical_board_instrument")
                if "+" in meter_lower and any(
                    sw in meter_lower for sw in SOFTWARE_COUNTER_TOKENS
                ):
                    energy_ok = False
                    reasons.append("energy_classes_mixed_measured_and_reported")
            elif ev == "reported_j":
                if board is not False:
                    energy_ok = False
                    reasons.append("reported_j_cannot_claim_board_metered")
                if "measured_j +" in meter_lower or "+ est_j" in meter_lower:
                    energy_ok = False
                    reasons.append("energy_classes_mixed_in_formula")
            elif ev == "est_j":
                if board is not False:
                    energy_ok = False
                    reasons.append("est_j_cannot_claim_board_metered")
                if any(sw in meter_lower and "+" in meter_lower for sw in SOFTWARE_COUNTER_TOKENS):
                    energy_ok = False
                    reasons.append("energy_classes_mixed_est_and_reported")

        # Optional multi-channel telemetry non-mixing check
        if telemetry_channels:
            classes = {c.get("evidence_class") for c in telemetry_channels}
            if len(classes) > 1 and any(c.get("summed_into_primary") for c in telemetry_channels):
                energy_ok = False
                reasons.append("telemetry_cross_class_summation_forbidden")

        # Lean 4.36.0 6-kernel bwrap check
        lean_checked = False
        sorry_count = 0
        custom_axiom_count = 0
        of_reduce_bool_count = 0
        kernel_count = 0
        lean_ver = None
        bwrap = None

        if lean_receipt is not None:
            lean_checked = True
            lean_ver = lean_receipt.lean_version
            bwrap = lean_receipt.bwrap_sandboxed
            kernel_count = len(set(lean_receipt.kernels_verified))
            sorry_count = lean_receipt.sorry_count
            of_reduce_bool_count = lean_receipt.of_reduce_bool_count
            custom_axioms = [
                ax for ax in lean_receipt.axioms_used if ax not in STANDARD_LEAN_AXIOMS
            ]
            custom_axiom_count = len(custom_axioms) + lean_receipt.opaque_bypass_count

            if lean_receipt.lean_version != "4.36.0":
                reasons.append(f"lean_version_mismatch:{lean_receipt.lean_version}")
            if not lean_receipt.bwrap_sandboxed:
                reasons.append("lean_bwrap_sandbox_required")
            if set(lean_receipt.kernels_verified) != EXPECTED_SIX_LEAN_KERNELS:
                reasons.append(f"lean_six_kernel_quorum_incomplete:{kernel_count}/6")
            if lean_receipt.theorem_count < 1:
                reasons.append("lean_zero_theorems")
            if sorry_count != 0:
                reasons.append(f"lean_sorry_nonzero:{sorry_count}")
            if custom_axiom_count != 0:
                reasons.append(f"lean_custom_axioms_or_opaque_nonzero:{custom_axiom_count}")
            if of_reduce_bool_count != 0:
                reasons.append(f"lean_of_reduce_bool_nonzero:{of_reduce_bool_count}")

        # SAT / Miter equivalence digest check
        sat_digest: str | None = None
        if sat_miter_receipt is not None:
            computed = sat_miter_receipt.compute_digest()
            sat_digest = computed
            if sat_miter_receipt.status != "unsat":
                reasons.append(f"sat_miter_not_unsat:{sat_miter_receipt.status}")
            if sat_miter_receipt.mismatch_count != 0:
                reasons.append(f"sat_miter_mismatches:{sat_miter_receipt.mismatch_count}")
            if sat_miter_receipt.vector_count < 1:
                reasons.append("sat_miter_zero_vectors")
            if (
                sat_miter_receipt.claimed_digest is not None
                and sat_miter_receipt.claimed_digest != computed
            ):
                reasons.append("sat_miter_digest_mismatch")

        result: dict[str, Any] = {
            "passed": len(reasons) == 0,
            "lean_kernel_checked": lean_checked,
            "sorry_count": sorry_count,
            "custom_axiom_count": custom_axiom_count,
            "of_reduce_bool_count": of_reduce_bool_count,
            "energy_non_mixing_ok": energy_ok,
            "sat_miter_digest": sat_digest,
            "failure_reasons": reasons,
        }
        if lean_ver is not None:
            result["lean_version"] = lean_ver
            result["kernel_count"] = kernel_count
            result["bwrap_sandboxed"] = bool(bwrap)
        return result


# ---------------------------------------------------------------------------
# 2. TranslationGate (BLEU-4 + chrF++ + COMET-proxy + Numeric/ID + 2-strike quarantine)
# ---------------------------------------------------------------------------

_WORD_RE = re.compile(r"\w+|[^\w\s]", re.UNICODE)
# Extracts numeric magnitudes and formal OpenIE identifiers (e.g. CTA-T29, LA-28, WAI1)
_NUMERIC_TOKEN_RE = re.compile(r"\b\d+(?:[.,]\d+)*\b")
_IDENTIFIER_RE = re.compile(
    r"\b(?:CTA-[A-Z]\d+|GE-H\d+|LA-\d+|CA-M\d+|DNULLMM1|WAI1|WAI2|BLAKE3|Ed25519|LUT6|JCR-1|DES-10)\b"
)


def _tokenize_words(text: str) -> list[str]:
    return [tok.lower() for tok in _WORD_RE.findall(text)]


def compute_bleu4(candidate: str, reference: str) -> float:
    """Deterministic smoothed sentence BLEU-4 (`0.0 .. 100.0`, Chen-Cherry method 1)."""
    cand = _tokenize_words(candidate)
    ref = _tokenize_words(reference)
    if not cand or not ref:
        return 0.0
    c_len = len(cand)
    r_len = len(ref)
    bp = 1.0 if c_len > r_len else math.exp(1.0 - (r_len / c_len))

    log_sum = 0.0
    max_n = min(4, c_len, r_len)
    for n in range(1, 5):
        if n > max_n:
            # Extrapolate with smoothed 0.1 / 1.0 if shorter than 4 tokens
            p_n = 0.1 / 1.0
        else:
            c_ngrams = Counter(tuple(cand[i : i + n]) for i in range(c_len - n + 1))
            r_ngrams = Counter(tuple(ref[i : i + n]) for i in range(r_len - n + 1))
            overlap = sum(min(cnt, r_ngrams[ng]) for ng, cnt in c_ngrams.items())
            total = max(1, c_len - n + 1)
            if overlap == 0:
                p_n = 0.1 / (total + 0.1)
            else:
                p_n = overlap / total
        log_sum += 0.25 * math.log(p_n)
    return round(min(100.0, 100.0 * bp * math.exp(log_sum)), 4)


def _f_beta(overlap: int, cand_total: int, ref_total: int, beta: float = 2.0) -> float:
    if cand_total == 0 and ref_total == 0:
        return 1.0
    if overlap == 0 or cand_total == 0 or ref_total == 0:
        return 0.0
    prec = overlap / cand_total
    rec = overlap / ref_total
    b2 = beta * beta
    return ((1.0 + b2) * prec * rec) / (b2 * prec + rec)


def compute_chrf_pp(candidate: str, reference: str) -> float:
    """Deterministic Popović (2017) chrF++ (`char n=1..6` + `word n=1..2`, beta=2, `0..100`)."""
    c_chars = "".join(candidate.lower().split())
    r_chars = "".join(reference.lower().split())
    c_words = _tokenize_words(candidate)
    r_words = _tokenize_words(reference)
    if not c_chars or not r_chars:
        return 0.0

    scores: list[float] = []
    for n in range(1, 7):
        if len(c_chars) < n or len(r_chars) < n:
            continue
        cg = Counter(c_chars[i : i + n] for i in range(len(c_chars) - n + 1))
        rg = Counter(r_chars[i : i + n] for i in range(len(r_chars) - n + 1))
        ov = sum(min(cnt, rg[g]) for g, cnt in cg.items())
        scores.append(_f_beta(ov, sum(cg.values()), sum(rg.values()), 2.0))

    for n in range(1, 3):
        if len(c_words) < n or len(r_words) < n:
            continue
        cw = Counter(tuple(c_words[i : i + n]) for i in range(len(c_words) - n + 1))
        rw = Counter(tuple(r_words[i : i + n]) for i in range(len(r_words) - n + 1))
        ov = sum(min(cnt, rw[g]) for g, cnt in cw.items())
        scores.append(_f_beta(ov, sum(cw.values()), sum(rw.values()), 2.0))

    if not scores:
        return 0.0
    return round(100.0 * (sum(scores) / len(scores)), 4)


def _embed_deterministic_128d(text: str) -> list[float]:
    """Deterministic 128-D signed feature-hash embedding over char 3-grams & word stems."""
    vec = [0.0] * 128
    norm_text = " ".join(text.lower().split())
    padded = f"<{norm_text}>"
    for i in range(max(0, len(padded) - 2)):
        tri = padded[i : i + 3].encode("utf-8")
        h = blake3_hex(b"comet-tri:" + tri)
        idx = int(h[:2], 16) % 128
        sign = 1.0 if (int(h[2:4], 16) & 1) == 0 else -1.0
        vec[idx] += sign
    for tok in _tokenize_words(norm_text):
        h = blake3_hex(b"comet-tok:" + tok.encode("utf-8"))
        idx = int(h[:2], 16) % 128
        sign = 1.0 if (int(h[2:4], 16) & 1) == 0 else -1.0
        vec[idx] += 1.5 * sign
    norm = math.sqrt(sum(v * v for v in vec))
    if norm == 0.0:
        return vec
    return [v / norm for v in vec]


def compute_comet_proxy(
    source_en: str, candidate: str, reference: str
) -> float:
    """Deterministic semantic embedding COMET-proxy (`0.0 .. 1.0`)."""
    v_cand = _embed_deterministic_128d(candidate)
    v_ref = _embed_deterministic_128d(reference)
    v_src = _embed_deterministic_128d(source_en)
    cos_ref = max(0.0, sum(a * b for a, b in zip(v_cand, v_ref)))
    cos_src = max(0.0, sum(a * b for a, b in zip(v_cand, v_src)))
    len_ratio = min(len(candidate) + 1, len(reference) + 1) / max(
        len(candidate) + 1, len(reference) + 1
    )
    score = 0.70 * cos_ref + 0.15 * cos_src + 0.15 * len_ratio
    return round(min(1.0, max(0.0, score)), 4)


def _normalize_numeric_token(tok: str) -> str:
    # Normalize thousands separators like 11,428 -> 11428 while preserving decimals like 95.49
    if "," in tok and "." not in tok:
        parts = tok.split(",")
        if len(parts) > 1 and all(len(p) == 3 for p in parts[1:]):
            return "".join(parts)
        # European decimal comma e.g. 95,49 -> 95.49
        return tok.replace(",", ".")
    return tok.replace(",", "")


def check_numeric_and_id_conservation(source_en: str, candidate: str) -> bool:
    """Verify 100% conservation of numeric literals and formal OpenIE identifiers."""
    src_nums = sorted(_normalize_numeric_token(m) for m in _NUMERIC_TOKEN_RE.findall(source_en))
    cand_nums = sorted(_normalize_numeric_token(m) for m in _NUMERIC_TOKEN_RE.findall(candidate))
    if src_nums != cand_nums:
        return False
    src_ids = sorted(_IDENTIFIER_RE.findall(source_en))
    cand_ids = sorted(_IDENTIFIER_RE.findall(candidate))
    return src_ids == cand_ids


@dataclass(frozen=True)
class TranslationCandidate:
    locale: str
    title: str
    plain_easy_read: str
    reference_text: str


class TranslationGate:
    """Deterministic multilingual quality & conservation gate with retry + 2-strike quarantine."""

    def __init__(
        self,
        *,
        min_bleu4_threshold: float = 35.0,
        min_chrf_pp_threshold: float = 60.0,
        min_comet_proxy_threshold: float = 0.72,
    ) -> None:
        self.min_bleu4_threshold = min_bleu4_threshold
        self.min_chrf_pp_threshold = min_chrf_pp_threshold
        self.min_comet_proxy_threshold = min_comet_proxy_threshold

    def _score_single(
        self, source_en: str, cand: TranslationCandidate
    ) -> tuple[bool, dict[str, Any], list[str]]:
        bleu = compute_bleu4(cand.plain_easy_read, cand.reference_text)
        chrf = compute_chrf_pp(cand.plain_easy_read, cand.reference_text)
        comet = compute_comet_proxy(source_en, cand.plain_easy_read, cand.reference_text)
        conserved = check_numeric_and_id_conservation(source_en, cand.plain_easy_read)
        reasons: list[str] = []
        if bleu < self.min_bleu4_threshold:
            reasons.append(f"{cand.locale}:bleu4_below_threshold:{bleu}<{self.min_bleu4_threshold}")
        if chrf < self.min_chrf_pp_threshold:
            reasons.append(
                f"{cand.locale}:chrf_pp_below_threshold:{chrf}<{self.min_chrf_pp_threshold}"
            )
        if comet < self.min_comet_proxy_threshold:
            reasons.append(
                f"{cand.locale}:comet_proxy_below_threshold:{comet}<{self.min_comet_proxy_threshold}"
            )
        if not conserved:
            reasons.append(f"{cand.locale}:numeric_or_identifier_mismatch")
        entry = {
            "title": cand.title,
            "plain_easy_read": cand.plain_easy_read,
            "bleu4": bleu,
            "chrf_pp": chrf,
            "comet_proxy": comet,
            "numeric_id_conserved": conserved,
        }
        return len(reasons) == 0, entry, reasons

    def evaluate(
        self,
        *,
        source_en: str,
        candidates: list[TranslationCandidate],
        retry_callback: Callable[[TranslationCandidate, list[str], int], TranslationCandidate]
        | None = None,
        prior_consecutive_failures: int = 0,
        human_in_gate: bool = False,
    ) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
        """Evaluate all locale candidates; auto-retry on failure #1; quarantine on failure #2."""
        if human_in_gate is not False:
            return (
                {
                    "passed": False,
                    "evaluated_locales": [c.locale for c in candidates],
                    "min_bleu4": 0.0,
                    "min_chrf_pp": 0.0,
                    "min_comet_proxy": 0.0,
                    "numeric_id_conservation_ok": False,
                    "consecutive_failures": prior_consecutive_failures + 1,
                    "retry_triggered": False,
                    "quarantined_do_not_ship": (prior_consecutive_failures + 1) >= 2,
                    "failure_reasons": ["human_in_gate_forbidden"],
                },
                {},
            )

        if not candidates:
            return (
                {
                    "passed": True,
                    "evaluated_locales": [],
                    "min_bleu4": 100.0,
                    "min_chrf_pp": 100.0,
                    "min_comet_proxy": 1.0,
                    "numeric_id_conservation_ok": True,
                    "consecutive_failures": 0,
                    "retry_triggered": False,
                    "quarantined_do_not_ship": False,
                    "failure_reasons": [],
                },
                {},
            )

        multilingual_out: dict[str, dict[str, Any]] = {}
        all_reasons: list[str] = []
        consecutive_failures = prior_consecutive_failures
        retry_triggered = False

        for cand in candidates:
            ok, entry, reasons = self._score_single(source_en, cand)
            if not ok:
                consecutive_failures += 1
                if consecutive_failures == 1 and retry_callback is not None:
                    retry_triggered = True
                    repaired = retry_callback(cand, reasons, 1)
                    ok2, entry2, reasons2 = self._score_single(source_en, repaired)
                    entry = entry2
                    if ok2:
                        consecutive_failures = 0
                    else:
                        consecutive_failures += 1
                        all_reasons.extend(reasons2)
                else:
                    all_reasons.extend(reasons)
            multilingual_out[cand.locale] = entry

        min_bleu = min(v["bleu4"] for v in multilingual_out.values())
        min_chrf = min(v["chrf_pp"] for v in multilingual_out.values())
        min_comet = min(v["comet_proxy"] for v in multilingual_out.values())
        num_ok = all(v["numeric_id_conserved"] for v in multilingual_out.values())
        quarantined = consecutive_failures >= 2
        passed = len(all_reasons) == 0 and not quarantined

        gate_report = {
            "passed": passed,
            "evaluated_locales": [c.locale for c in candidates],
            "min_bleu4": round(min_bleu, 4),
            "min_chrf_pp": round(min_chrf, 4),
            "min_comet_proxy": round(min_comet, 4),
            "numeric_id_conservation_ok": num_ok,
            "consecutive_failures": consecutive_failures,
            "retry_triggered": retry_triggered,
            "quarantined_do_not_ship": quarantined,
            "failure_reasons": all_reasons,
        }
        return gate_report, multilingual_out


# ---------------------------------------------------------------------------
# 3. AccessibilityGate (WCAG 2.2 AA, Easy-Read <=18 wps & zero acronyms, AD, AAC)
# ---------------------------------------------------------------------------

_SENTENCE_SPLIT_RE = re.compile(r"[.!?]+(?:\s+|$)")
_PLAIN_WORD_RE = re.compile(r"[A-Za-z0-9]+(?:[-'][A-Za-z0-9]+)*")
_ASCII_ALNUM_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")


def _has_two_or_more_upper(tok: str) -> bool:
    return sum(1 for ch in tok if "A" <= ch <= "Z") >= 2


def compute_easy_read_metrics(text: str, bullets: list[str]) -> tuple[float, list[str]]:
    """Compute `(avg_words_per_sentence, unexplained_acronyms)` over plain_easy_read."""
    combined_sentences: list[str] = []
    for block in [text, *bullets]:
        for seg in _SENTENCE_SPLIT_RE.split(block.strip()):
            seg_clean = seg.strip()
            if seg_clean:
                combined_sentences.append(seg_clean)
    if not combined_sentences:
        return 0.0, []

    word_counts = [len(_PLAIN_WORD_RE.findall(s)) for s in combined_sentences]
    word_counts = [wc for wc in word_counts if wc > 0]
    if not word_counts:
        return 0.0, []
    avg_wps = round(sum(word_counts) / len(word_counts), 4)

    full_text = " ".join([text, *bullets])
    acronyms_found: list[str] = []
    for match in _ASCII_ALNUM_TOKEN_RE.finditer(full_text):
        acr = match.group(0)
        if not _has_two_or_more_upper(acr):
            continue
        # Allow inline parenthetical expansion immediately preceding e.g. "artificial intelligence (AI)"
        start = match.start()
        end = match.end()
        explained_inline = (
            start >= 2
            and full_text[start - 1] == "("
            and end < len(full_text)
            and full_text[end] == ")"
            and len(_PLAIN_WORD_RE.findall(full_text[max(0, start - 60) : start - 1])) >= len(acr)
        )
        if not explained_inline and acr not in acronyms_found:
            acronyms_found.append(acr)
    return avg_wps, acronyms_found


class AccessibilityGate:
    """Enforces WCAG 2.2 AA captions/transcripts, Easy-Read <=18 wps & acronym-free, AD, AAC."""

    MAX_AVG_WORDS_PER_SENTENCE = 18.0

    def evaluate(
        self,
        *,
        modality_variants: dict[str, Any],
        human_in_gate: bool = False,
    ) -> dict[str, Any]:
        reasons: list[str] = []
        if human_in_gate is not False:
            reasons.append("human_in_gate_forbidden")

        # 1. WCAG 2.2 AA caption / transcript presence
        captions_ok = True
        has_any_primary = False

        if "text" in modality_variants:
            has_any_primary = True
            tx = modality_variants["text"]
            if not isinstance(tx, dict) or not tx.get("summary") or not tx.get("uri"):
                captions_ok = False
                reasons.append("wcag_text_summary_missing")

        if "audio" in modality_variants:
            has_any_primary = True
            au = modality_variants["audio"]
            if (
                not isinstance(au, dict)
                or not str(au.get("captions_vtt_uri", "")).endswith(".vtt")
                or not au.get("transcript_uri")
            ):
                captions_ok = False
                reasons.append("wcag_audio_captions_or_transcript_missing")

        if "video" in modality_variants:
            has_any_primary = True
            vd = modality_variants["video"]
            if not isinstance(vd, dict) or len(vd) == 0:
                captions_ok = False
                reasons.append("wcag_video_cuts_empty")
            else:
                for slot, cut in vd.items():
                    if (
                        not isinstance(cut, dict)
                        or not str(cut.get("vtt_uri", "")).endswith(".vtt")
                        or not cut.get("transcript")
                    ):
                        captions_ok = False
                        reasons.append(f"wcag_video_cut_missing_vtt_or_transcript:{slot}")

        if "short_vertical_9x16" in modality_variants:
            has_any_primary = True
            sv = modality_variants["short_vertical_9x16"]
            if (
                not isinstance(sv, dict)
                or not str(sv.get("vtt_uri", "")).endswith(".vtt")
                or sv.get("resolution") != "1080x1920"
                or sv.get("fps") != 60
                or not isinstance(sv.get("safe_zone_verified"), bool)
            ):
                captions_ok = False
                reasons.append("wcag_short_vertical_9x16_invalid_or_missing_vtt")

        if not has_any_primary:
            captions_ok = False
            reasons.append("wcag_no_primary_modality_present")

        # 2. Easy-Read <= 18.0 words/sentence & acronym-free plain text
        er = modality_variants.get("plain_easy_read")
        easy_read_ok = True
        avg_wps = 0.0
        acronyms: list[str] = []
        if not isinstance(er, dict) or not er.get("text") or not er.get("bullets"):
            easy_read_ok = False
            reasons.append("easy_read_missing")
        else:
            avg_wps, acronyms = compute_easy_read_metrics(er["text"], list(er["bullets"]))
            if avg_wps <= 0.0 or avg_wps > self.MAX_AVG_WORDS_PER_SENTENCE:
                easy_read_ok = False
                reasons.append(
                    f"easy_read_sentence_length_exceeded:{avg_wps}>{self.MAX_AVG_WORDS_PER_SENTENCE}"
                )
            if acronyms:
                easy_read_ok = False
                reasons.append(f"easy_read_unexplained_acronyms:{','.join(acronyms)}")

        # 3. Audio-description track pointer
        ad = modality_variants.get("audio_description")
        ad_ok = True
        if (
            not isinstance(ad, dict)
            or not ad.get("track_uri")
            or not ad.get("script")
            or ad.get("voicing") not in {"machine", "human"}
        ):
            ad_ok = False
            reasons.append("audio_description_track_missing_or_invalid")

        # 4. AAC Concepts anchor resolution
        aac = modality_variants.get("aac_concepts")
        aac_ok = True
        if not isinstance(aac, list) or len(aac) == 0:
            aac_ok = False
            reasons.append("aac_concepts_missing")
        else:
            for item in aac:
                if not isinstance(item, dict):
                    aac_ok = False
                    reasons.append("aac_concept_malformed")
                    continue
                cid = item.get("concept_id", "")
                uri = item.get("symbol_anchor_uri", "")
                reg = AAC_CONCEPT_REGISTRY.get(cid)
                if reg is None or reg["symbol_anchor_uri"] != uri:
                    aac_ok = False
                    reasons.append(f"aac_concept_unresolved:{cid}")

        return {
            "passed": len(reasons) == 0,
            "wcag_22_aa_captions_ok": captions_ok,
            "easy_read_ok": easy_read_ok,
            "easy_read_avg_words_per_sentence": avg_wps,
            "unexplained_acronyms": acronyms,
            "audio_description_ok": ad_ok,
            "aac_concepts_resolved": aac_ok,
            "failure_reasons": reasons,
        }


# ---------------------------------------------------------------------------
# Unified Deterministic Gate Orchestrator (Zero Humans in the Gates)
# ---------------------------------------------------------------------------


class VerificationOrchestrator:
    """Runs ScientificGate, TranslationGate, and AccessibilityGate deterministically."""

    def __init__(
        self,
        scientific_gate: ScientificGate | None = None,
        translation_gate: TranslationGate | None = None,
        accessibility_gate: AccessibilityGate | None = None,
    ) -> None:
        self.scientific_gate = scientific_gate or ScientificGate()
        self.translation_gate = translation_gate or TranslationGate()
        self.accessibility_gate = accessibility_gate or AccessibilityGate()

    def run_all(
        self,
        *,
        energy_cost_j: dict[str, Any],
        modality_variants: dict[str, Any],
        source_en_for_translation: str,
        translation_candidates: list[TranslationCandidate],
        lean_receipt: LeanProofReceipt | None = None,
        sat_miter_receipt: SatMiterReceipt | None = None,
        telemetry_channels: list[dict[str, Any]] | None = None,
        retry_callback: Callable[[TranslationCandidate, list[str], int], TranslationCandidate]
        | None = None,
        prior_translation_failures: int = 0,
        is_upstream_draft: bool = False,
        human_in_gate: bool = False,
    ) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
        if human_in_gate is not False:
            raise ValueError("Zero Humans in the Gates invariant violated: human_in_gate=True")

        sci = self.scientific_gate.evaluate(
            energy_cost_j=energy_cost_j,
            lean_receipt=lean_receipt,
            sat_miter_receipt=sat_miter_receipt,
            telemetry_channels=telemetry_channels,
            human_in_gate=False,
        )
        trans, multilingual_map = self.translation_gate.evaluate(
            source_en=source_en_for_translation,
            candidates=translation_candidates,
            retry_callback=retry_callback,
            prior_consecutive_failures=prior_translation_failures,
            human_in_gate=False,
        )
        acc = self.accessibility_gate.evaluate(
            modality_variants=modality_variants,
            human_in_gate=False,
        )

        if trans["quarantined_do_not_ship"] or not sci["passed"] or not acc["passed"] or not trans["passed"]:
            overall_status = "flagged_do_not_ship"
        elif is_upstream_draft:
            overall_status = "draft"
        else:
            overall_status = "verified"

        return (
            {
                "status": overall_status,
                "human_in_gate": False,
                "scientific_gate": sci,
                "translation_gate": trans,
                "accessibility_gate": acc,
            },
            multilingual_map,
        )
