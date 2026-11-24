// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

//! Deterministic Verification Gate Library (`openie-gates`, Step 3 — Zero Humans in the Gates).
//!
//! Machine-checkable gates:
//! - [`ScientificGate`]: Lean 4.36.0 6-kernel `bwrap` proof receipts (`0 sorry`,
//!   `0 custom axioms`, `0 ofReduceBool`), deterministic SAT/miter `BLAKE3` digests,
//!   and `measured_j` / `reported_j` / `est_j` / `unmetered` non-mixing invariants.
//! - [`TranslationGate`]: Deterministic `BLEU-4` + `chrF++` + semantic embedding
//!   `COMET`-proxy score + numeric/identifier conservation check; triggers automatic
//!   retry callback on failure #1 and stamps `flagged_do_not_ship` on 2 consecutive
//!   failures.
//! - [`AccessibilityGate`]: WCAG 2.2 AA caption/transcript presence, Easy-Read sentence
//!   length (`<= 18.0` words/sentence avg) & acronym-free plain text, audio-description
//!   track pointer, and OpenIE Commons AAC Concepts anchor resolution.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const LANDAUER_300K_J_PER_BIT: f64 = 1.380649e-23 * 300.0 * std::f64::consts::LN_2;

pub const EXPECTED_SIX_LEAN_KERNELS: [&str; 6] = [
    "lean4-v4.36.0",
    "lean4lean",
    "nanoda",
    "leanchecker",
    "con-leche",
    "con-ron",
];

pub const STANDARD_LEAN_AXIOMS: [&str; 3] = ["propext", "Quot.sound", "Classical.choice"];

pub const BOARD_INSTRUMENT_TOKENS: [&str; 6] = [
    "ina238",
    "ina3221",
    "kv260",
    "shunt",
    "board power sensor",
    "circuit-board",
];

pub const SOFTWARE_COUNTER_TOKENS: [&str; 5] = [
    "rapl",
    "nvml",
    "ioreport",
    "proc_pid_rusage",
    "ri_energy_nj",
];

pub const AAC_CONCEPT_SLUGS: [(&str, &str); 30] = [
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
];

pub fn resolve_aac_anchor(concept_id: &str) -> Option<String> {
    let slug = concept_id.strip_prefix("aac:")?;
    for (s, _) in AAC_CONCEPT_SLUGS {
        if s == slug {
            return Some(format!("https://commons.openie.dev/aac/{s}"));
        }
    }
    None
}

pub fn compute_landauer_300k_bits(joules: f64) -> f64 {
    let raw = joules / LANDAUER_300K_J_PER_BIT;
    format!("{raw:.10e}").parse::<f64>().unwrap_or(raw)
}

// ---------------------------------------------------------------------------
// 1. ScientificGate
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnergyCostSpec {
    pub evidence_class: String,
    pub joules: Option<f64>,
    pub meter_or_formula: String,
    pub board_metered: bool,
    pub landauer_300k_bits_equiv: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryChannelSample {
    pub channel_id: String,
    pub evidence_class: String,
    pub joules: f64,
    pub summed_into_primary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeanProofReceipt {
    pub lean_version: String,
    pub bwrap_sandboxed: bool,
    pub kernels_verified: Vec<String>,
    pub theorem_count: usize,
    pub sorry_count: usize,
    pub axioms_used: Vec<String>,
    pub of_reduce_bool_count: usize,
    pub opaque_bypass_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SatMiterReceipt {
    pub suite_id: String,
    pub lhs_ir_hash: String,
    pub rhs_ir_hash: String,
    pub vector_count: u64,
    pub mismatch_count: u64,
    pub status: String,
    pub claimed_digest: Option<String>,
}

impl SatMiterReceipt {
    pub fn compute_digest(&self) -> String {
        // Matches Python canonical JCS alphabetical key order
        let canonical = format!(
            "{{\"lhs_ir_hash\":{},\"mismatch_count\":{},\"rhs_ir_hash\":{},\"status\":{},\"suite_id\":{},\"vector_count\":{}}}",
            serde_json::to_string(&self.lhs_ir_hash).unwrap_or_default(),
            self.mismatch_count,
            serde_json::to_string(&self.rhs_ir_hash).unwrap_or_default(),
            serde_json::to_string(&self.status).unwrap_or_default(),
            serde_json::to_string(&self.suite_id).unwrap_or_default(),
            self.vector_count,
        );
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"openie-sat-miter-v1\x00");
        hasher.update(canonical.as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScientificGateReport {
    pub passed: bool,
    pub lean_kernel_checked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lean_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_count: Option<usize>,
    pub sorry_count: usize,
    pub custom_axiom_count: usize,
    pub of_reduce_bool_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bwrap_sandboxed: Option<bool>,
    pub sat_miter_digest: Option<String>,
    pub energy_non_mixing_ok: bool,
    pub failure_reasons: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct ScientificGate;

impl ScientificGate {
    pub fn evaluate(
        &self,
        energy: &EnergyCostSpec,
        lean_receipt: Option<&LeanProofReceipt>,
        sat_receipt: Option<&SatMiterReceipt>,
        telemetry_channels: Option<&[TelemetryChannelSample]>,
        human_in_gate: bool,
    ) -> ScientificGateReport {
        let mut reasons = Vec::new();
        if human_in_gate {
            reasons.push("human_in_gate_forbidden".to_string());
        }

        let mut energy_ok = true;
        let ev = energy.evidence_class.as_str();
        let meter_lower = energy.meter_or_formula.to_lowercase();

        match ev {
            "unmetered" => {
                if energy.board_metered {
                    energy_ok = false;
                    reasons.push("unmetered_claims_board_metered".to_string());
                }
                if energy.joules.is_some() {
                    energy_ok = false;
                    reasons.push("unmetered_must_not_carry_numeric_joules".to_string());
                }
                if energy.landauer_300k_bits_equiv.is_some() {
                    energy_ok = false;
                    reasons.push("unmetered_must_not_carry_landauer_bits".to_string());
                }
            }
            "measured_j" | "reported_j" | "est_j" => {
                match energy.joules {
                    Some(j) if j.is_finite() && j > 0.0 => {
                        let expected_bits = compute_landauer_300k_bits(j);
                        match energy.landauer_300k_bits_equiv {
                            Some(lb)
                                if lb.is_finite()
                                    && ((lb - expected_bits).abs() / expected_bits) <= 1e-6 => {}
                            _ => {
                                energy_ok = false;
                                reasons.push("landauer_300k_bits_mismatch".to_string());
                            }
                        }
                    }
                    _ => {
                        energy_ok = false;
                        reasons.push("non_positive_or_invalid_joules".to_string());
                    }
                }

                if ev == "measured_j" {
                    if !energy.board_metered {
                        energy_ok = false;
                        reasons.push("measured_j_requires_board_metered_true".to_string());
                    }
                    if !BOARD_INSTRUMENT_TOKENS
                        .iter()
                        .any(|tok| meter_lower.contains(tok))
                    {
                        energy_ok = false;
                        reasons.push("measured_j_missing_physical_board_instrument".to_string());
                    }
                    if meter_lower.contains('+')
                        && SOFTWARE_COUNTER_TOKENS
                            .iter()
                            .any(|sw| meter_lower.contains(sw))
                    {
                        energy_ok = false;
                        reasons.push("energy_classes_mixed_measured_and_reported".to_string());
                    }
                } else if ev == "reported_j" {
                    if energy.board_metered {
                        energy_ok = false;
                        reasons.push("reported_j_cannot_claim_board_metered".to_string());
                    }
                    if meter_lower.contains("measured_j +") || meter_lower.contains("+ est_j") {
                        energy_ok = false;
                        reasons.push("energy_classes_mixed_in_formula".to_string());
                    }
                } else if ev == "est_j" {
                    if energy.board_metered {
                        energy_ok = false;
                        reasons.push("est_j_cannot_claim_board_metered".to_string());
                    }
                    if meter_lower.contains('+')
                        && SOFTWARE_COUNTER_TOKENS
                            .iter()
                            .any(|sw| meter_lower.contains(sw))
                    {
                        energy_ok = false;
                        reasons.push("energy_classes_mixed_est_and_reported".to_string());
                    }
                }
            }
            other => {
                energy_ok = false;
                reasons.push(format!("invalid_evidence_class:{other}"));
            }
        }

        if let Some(chans) = telemetry_channels {
            let classes: BTreeSet<&str> =
                chans.iter().map(|c| c.evidence_class.as_str()).collect();
            if classes.len() > 1 && chans.iter().any(|c| c.summed_into_primary) {
                energy_ok = false;
                reasons.push("telemetry_cross_class_summation_forbidden".to_string());
            }
        }

        let mut lean_checked = false;
        let mut sorry_count = 0usize;
        let mut custom_axiom_count = 0usize;
        let mut of_reduce_bool_count = 0usize;
        let mut lean_ver = None;
        let mut kernel_count = None;
        let mut bwrap = None;

        if let Some(lr) = lean_receipt {
            lean_checked = true;
            lean_ver = Some(lr.lean_version.clone());
            bwrap = Some(lr.bwrap_sandboxed);
            let unique_kernels: BTreeSet<&str> =
                lr.kernels_verified.iter().map(|s| s.as_str()).collect();
            let kcount = unique_kernels.len();
            kernel_count = Some(kcount);
            sorry_count = lr.sorry_count;
            of_reduce_bool_count = lr.of_reduce_bool_count;

            let custom_ax = lr
                .axioms_used
                .iter()
                .filter(|ax| !STANDARD_LEAN_AXIOMS.contains(&ax.as_str()))
                .count();
            custom_axiom_count = custom_ax + lr.opaque_bypass_count;

            if lr.lean_version != "4.36.0" {
                reasons.push(format!("lean_version_mismatch:{}", lr.lean_version));
            }
            if !lr.bwrap_sandboxed {
                reasons.push("lean_bwrap_sandbox_required".to_string());
            }
            let expected_set: BTreeSet<&str> = EXPECTED_SIX_LEAN_KERNELS.into_iter().collect();
            if unique_kernels != expected_set {
                reasons.push(format!("lean_six_kernel_quorum_incomplete:{kcount}/6"));
            }
            if lr.theorem_count == 0 {
                reasons.push("lean_zero_theorems".to_string());
            }
            if sorry_count != 0 {
                reasons.push(format!("lean_sorry_nonzero:{sorry_count}"));
            }
            if custom_axiom_count != 0 {
                reasons.push(format!(
                    "lean_custom_axioms_or_opaque_nonzero:{custom_axiom_count}"
                ));
            }
            if of_reduce_bool_count != 0 {
                reasons.push(format!(
                    "lean_of_reduce_bool_nonzero:{of_reduce_bool_count}"
                ));
            }
        }

        let mut sat_digest = None;
        if let Some(sr) = sat_receipt {
            let computed = sr.compute_digest();
            if sr.status != "unsat" {
                reasons.push(format!("sat_miter_not_unsat:{}", sr.status));
            }
            if sr.mismatch_count != 0 {
                reasons.push(format!("sat_miter_mismatches:{}", sr.mismatch_count));
            }
            if sr.vector_count == 0 {
                reasons.push("sat_miter_zero_vectors".to_string());
            }
            if let Some(claimed) = &sr.claimed_digest {
                if claimed != &computed {
                    reasons.push("sat_miter_digest_mismatch".to_string());
                }
            }
            sat_digest = Some(computed);
        }

        ScientificGateReport {
            passed: reasons.is_empty(),
            lean_kernel_checked: lean_checked,
            lean_version: lean_ver,
            kernel_count,
            sorry_count,
            custom_axiom_count,
            of_reduce_bool_count,
            bwrap_sandboxed: bwrap,
            sat_miter_digest: sat_digest,
            energy_non_mixing_ok: energy_ok,
            failure_reasons: reasons,
        }
    }
}

// ---------------------------------------------------------------------------
// 2. TranslationGate
// ---------------------------------------------------------------------------

fn round4(v: f64) -> f64 {
    (v * 10_000.0).round() / 10_000.0
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

pub fn tokenize_words(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if is_word_char(ch) {
            for lc in ch.to_lowercase() {
                cur.push(lc);
            }
        } else {
            if !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
            if !ch.is_whitespace() {
                tokens.push(ch.to_lowercase().to_string());
            }
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

pub fn compute_bleu4(candidate: &str, reference: &str) -> f64 {
    let cand = tokenize_words(candidate);
    let r_tok = tokenize_words(reference);
    if cand.is_empty() || r_tok.is_empty() {
        return 0.0;
    }
    let c_len = cand.len();
    let r_len = r_tok.len();
    let bp = if c_len > r_len {
        1.0
    } else {
        (1.0 - (r_len as f64 / c_len as f64)).exp()
    };

    let mut log_sum = 0.0;
    let max_n = 4usize.min(c_len).min(r_len);
    for n in 1..=4 {
        let p_n = if n > max_n {
            0.1
        } else {
            let mut c_counts: BTreeMap<&[String], usize> = BTreeMap::new();
            for i in 0..=(c_len - n) {
                *c_counts.entry(&cand[i..i + n]).or_insert(0) += 1;
            }
            let mut r_counts: BTreeMap<&[String], usize> = BTreeMap::new();
            for i in 0..=(r_len - n) {
                *r_counts.entry(&r_tok[i..i + n]).or_insert(0) += 1;
            }
            let mut overlap = 0usize;
            for (ng, cnt) in &c_counts {
                if let Some(rc) = r_counts.get(ng) {
                    overlap += (*cnt).min(*rc);
                }
            }
            let total = (c_len - n + 1).max(1) as f64;
            if overlap == 0 {
                0.1 / (total + 0.1)
            } else {
                overlap as f64 / total
            }
        };
        log_sum += 0.25 * p_n.ln();
    }
    round4((100.0 * bp * log_sum.exp()).min(100.0))
}

fn f_beta(overlap: usize, cand_total: usize, ref_total: usize, beta: f64) -> f64 {
    if cand_total == 0 && ref_total == 0 {
        return 1.0;
    }
    if overlap == 0 || cand_total == 0 || ref_total == 0 {
        return 0.0;
    }
    let prec = overlap as f64 / cand_total as f64;
    let rec = overlap as f64 / ref_total as f64;
    let b2 = beta * beta;
    ((1.0 + b2) * prec * rec) / (b2 * prec + rec)
}

pub fn compute_chrf_pp(candidate: &str, reference: &str) -> f64 {
    let c_chars: Vec<char> = candidate
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(|c| c.to_lowercase())
        .collect();
    let r_chars: Vec<char> = reference
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(|c| c.to_lowercase())
        .collect();
    if c_chars.is_empty() || r_chars.is_empty() {
        return 0.0;
    }
    let c_words = tokenize_words(candidate);
    let r_words = tokenize_words(reference);

    let mut scores = Vec::new();
    for n in 1..=6 {
        if c_chars.len() < n || r_chars.len() < n {
            continue;
        }
        let mut cg: BTreeMap<&[char], usize> = BTreeMap::new();
        for i in 0..=(c_chars.len() - n) {
            *cg.entry(&c_chars[i..i + n]).or_insert(0) += 1;
        }
        let mut rg: BTreeMap<&[char], usize> = BTreeMap::new();
        for i in 0..=(r_chars.len() - n) {
            *rg.entry(&r_chars[i..i + n]).or_insert(0) += 1;
        }
        let mut ov = 0usize;
        for (g, cnt) in &cg {
            if let Some(rc) = rg.get(g) {
                ov += (*cnt).min(*rc);
            }
        }
        scores.push(f_beta(ov, c_chars.len() - n + 1, r_chars.len() - n + 1, 2.0));
    }
    for n in 1..=2 {
        if c_words.len() < n || r_words.len() < n {
            continue;
        }
        let mut cw: BTreeMap<&[String], usize> = BTreeMap::new();
        for i in 0..=(c_words.len() - n) {
            *cw.entry(&c_words[i..i + n]).or_insert(0) += 1;
        }
        let mut rw: BTreeMap<&[String], usize> = BTreeMap::new();
        for i in 0..=(r_words.len() - n) {
            *rw.entry(&r_words[i..i + n]).or_insert(0) += 1;
        }
        let mut ov = 0usize;
        for (g, cnt) in &cw {
            if let Some(rc) = rw.get(g) {
                ov += (*cnt).min(*rc);
            }
        }
        scores.push(f_beta(ov, c_words.len() - n + 1, r_words.len() - n + 1, 2.0));
    }
    if scores.is_empty() {
        return 0.0;
    }
    let avg = scores.iter().sum::<f64>() / scores.len() as f64;
    round4(100.0 * avg)
}

fn embed_deterministic_128d(text: &str) -> [f64; 128] {
    let mut vec = [0.0f64; 128];
    let norm_text = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let padded_chars: Vec<char> = format!("<{norm_text}>").chars().collect();
    if padded_chars.len() >= 3 {
        for i in 0..=(padded_chars.len() - 3) {
            let tri: String = padded_chars[i..i + 3].iter().collect();
            let mut h = blake3::Hasher::new();
            h.update(b"comet-tri:");
            h.update(tri.as_bytes());
            let bytes = h.finalize();
            let b = bytes.as_bytes();
            let idx = (b[0] as usize) % 128;
            let sign = if (b[1] & 1) == 0 { 1.0 } else { -1.0 };
            vec[idx] += sign;
        }
    }
    for tok in tokenize_words(&norm_text) {
        let mut h = blake3::Hasher::new();
        h.update(b"comet-tok:");
        h.update(tok.as_bytes());
        let bytes = h.finalize();
        let b = bytes.as_bytes();
        let idx = (b[0] as usize) % 128;
        let sign = if (b[1] & 1) == 0 { 1.0 } else { -1.0 };
        vec[idx] += 1.5 * sign;
    }
    let norm = vec.iter().map(|v| v * v).sum::<f64>().sqrt();
    if norm > 0.0 {
        for v in &mut vec {
            *v /= norm;
        }
    }
    vec
}

pub fn compute_comet_proxy(source_en: &str, candidate: &str, reference: &str) -> f64 {
    let vc = embed_deterministic_128d(candidate);
    let vr = embed_deterministic_128d(reference);
    let vs = embed_deterministic_128d(source_en);
    let cos_ref = vc
        .iter()
        .zip(vr.iter())
        .map(|(a, b)| a * b)
        .sum::<f64>()
        .max(0.0);
    let cos_src = vc
        .iter()
        .zip(vs.iter())
        .map(|(a, b)| a * b)
        .sum::<f64>()
        .max(0.0);
    let cl = candidate.chars().count() + 1;
    let rl = reference.chars().count() + 1;
    let len_ratio = (cl.min(rl) as f64) / (cl.max(rl) as f64);
    let score = 0.70 * cos_ref + 0.15 * cos_src + 0.15 * len_ratio;
    round4(score.clamp(0.0, 1.0))
}

fn extract_normalized_numbers(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let prev_word = i > 0 && is_word_char(chars[i - 1]);
        if !prev_word && chars[i].is_ascii_digit() {
            let start = i;
            i += 1;
            while i < chars.len() {
                if chars[i].is_ascii_digit() {
                    i += 1;
                } else if (chars[i] == '.' || chars[i] == ',')
                    && i + 1 < chars.len()
                    && chars[i + 1].is_ascii_digit()
                {
                    i += 1;
                } else {
                    break;
                }
            }
            let next_word = i < chars.len() && is_word_char(chars[i]);
            if !next_word {
                let raw: String = chars[start..i].iter().collect();
                let norm = if raw.contains(',') && !raw.contains('.') {
                    let parts: Vec<&str> = raw.split(',').collect();
                    if parts.len() > 1 && parts[1..].iter().all(|p| p.len() == 3) {
                        parts.join("")
                    } else {
                        raw.replace(',', ".")
                    }
                } else {
                    raw.replace(',', "")
                };
                out.push(norm);
            }
        } else {
            i += 1;
        }
    }
    out.sort();
    out
}

fn extract_formal_identifiers(text: &str) -> Vec<String> {
    const EXACT_IDS: [&str; 7] = [
        "DNULLMM1", "WAI1", "WAI2", "BLAKE3", "Ed25519", "LUT6", "JCR-1",
    ];
    let mut found = Vec::new();
    for raw_tok in text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                ',' | '.' | ';' | ':' | '(' | ')' | '[' | ']' | '{' | '}' | '"' | '\'' | '/'
            )
    }) {
        if raw_tok.is_empty() {
            continue;
        }
        if EXACT_IDS.contains(&raw_tok) || raw_tok == "DES-10" {
            found.push(raw_tok.to_string());
            continue;
        }
        if let Some(rest) = raw_tok.strip_prefix("CTA-") {
            if rest.len() >= 2
                && rest.as_bytes()[0].is_ascii_uppercase()
                && rest[1..].chars().all(|c| c.is_ascii_digit())
            {
                found.push(raw_tok.to_string());
            }
        } else if let Some(rest) = raw_tok.strip_prefix("GE-H") {
            if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
                found.push(raw_tok.to_string());
            }
        } else if let Some(rest) = raw_tok.strip_prefix("LA-") {
            if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
                found.push(raw_tok.to_string());
            }
        } else if let Some(rest) = raw_tok.strip_prefix("CA-M") {
            if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
                found.push(raw_tok.to_string());
            }
        }
    }
    found.sort();
    found
}

pub fn check_numeric_and_id_conservation(source_en: &str, candidate: &str) -> bool {
    extract_normalized_numbers(source_en) == extract_normalized_numbers(candidate)
        && extract_formal_identifiers(source_en) == extract_formal_identifiers(candidate)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationCandidate {
    pub locale: String,
    pub title: String,
    pub plain_easy_read: String,
    pub reference_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvaluatedTranslation {
    pub title: String,
    pub plain_easy_read: String,
    pub bleu4: f64,
    pub chrf_pp: f64,
    pub comet_proxy: f64,
    pub numeric_id_conserved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TranslationGateReport {
    pub passed: bool,
    pub evaluated_locales: Vec<String>,
    pub min_bleu4: f64,
    pub min_chrf_pp: f64,
    pub min_comet_proxy: f64,
    pub numeric_id_conservation_ok: bool,
    pub consecutive_failures: usize,
    pub retry_triggered: bool,
    pub quarantined_do_not_ship: bool,
    pub failure_reasons: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TranslationGate {
    pub min_bleu4_threshold: f64,
    pub min_chrf_pp_threshold: f64,
    pub min_comet_proxy_threshold: f64,
}

impl Default for TranslationGate {
    fn default() -> Self {
        Self {
            min_bleu4_threshold: 35.0,
            min_chrf_pp_threshold: 60.0,
            min_comet_proxy_threshold: 0.72,
        }
    }
}

impl TranslationGate {
    fn score_single(
        &self,
        source_en: &str,
        cand: &TranslationCandidate,
    ) -> (bool, EvaluatedTranslation, Vec<String>) {
        let bleu = compute_bleu4(&cand.plain_easy_read, &cand.reference_text);
        let chrf = compute_chrf_pp(&cand.plain_easy_read, &cand.reference_text);
        let comet = compute_comet_proxy(source_en, &cand.plain_easy_read, &cand.reference_text);
        let conserved = check_numeric_and_id_conservation(source_en, &cand.plain_easy_read);

        let mut reasons = Vec::new();
        if bleu < self.min_bleu4_threshold {
            reasons.push(format!(
                "{}:bleu4_below_threshold:{bleu}<{}",
                cand.locale, self.min_bleu4_threshold
            ));
        }
        if chrf < self.min_chrf_pp_threshold {
            reasons.push(format!(
                "{}:chrf_pp_below_threshold:{chrf}<{}",
                cand.locale, self.min_chrf_pp_threshold
            ));
        }
        if comet < self.min_comet_proxy_threshold {
            reasons.push(format!(
                "{}:comet_proxy_below_threshold:{comet}<{}",
                cand.locale, self.min_comet_proxy_threshold
            ));
        }
        if !conserved {
            reasons.push(format!("{}:numeric_or_identifier_mismatch", cand.locale));
        }

        let entry = EvaluatedTranslation {
            title: cand.title.clone(),
            plain_easy_read: cand.plain_easy_read.clone(),
            bleu4: bleu,
            chrf_pp: chrf,
            comet_proxy: comet,
            numeric_id_conserved: conserved,
        };
        (reasons.is_empty(), entry, reasons)
    }

    pub fn evaluate<F>(
        &self,
        source_en: &str,
        candidates: &[TranslationCandidate],
        mut retry_callback: Option<F>,
        prior_consecutive_failures: usize,
        human_in_gate: bool,
    ) -> (TranslationGateReport, BTreeMap<String, EvaluatedTranslation>)
    where
        F: FnMut(&TranslationCandidate, &[String], usize) -> TranslationCandidate,
    {
        if human_in_gate {
            let cf = prior_consecutive_failures + 1;
            return (
                TranslationGateReport {
                    passed: false,
                    evaluated_locales: candidates.iter().map(|c| c.locale.clone()).collect(),
                    min_bleu4: 0.0,
                    min_chrf_pp: 0.0,
                    min_comet_proxy: 0.0,
                    numeric_id_conservation_ok: false,
                    consecutive_failures: cf,
                    retry_triggered: false,
                    quarantined_do_not_ship: cf >= 2,
                    failure_reasons: vec!["human_in_gate_forbidden".to_string()],
                },
                BTreeMap::new(),
            );
        }

        if candidates.is_empty() {
            return (
                TranslationGateReport {
                    passed: true,
                    evaluated_locales: Vec::new(),
                    min_bleu4: 100.0,
                    min_chrf_pp: 100.0,
                    min_comet_proxy: 1.0,
                    numeric_id_conservation_ok: true,
                    consecutive_failures: 0,
                    retry_triggered: false,
                    quarantined_do_not_ship: false,
                    failure_reasons: Vec::new(),
                },
                BTreeMap::new(),
            );
        }

        let mut out_map = BTreeMap::new();
        let mut all_reasons = Vec::new();
        let mut consecutive_failures = prior_consecutive_failures;
        let mut retry_triggered = false;

        for cand in candidates {
            let (ok, mut entry, reasons) = self.score_single(source_en, cand);
            if !ok {
                consecutive_failures += 1;
                if consecutive_failures == 1 {
                    if let Some(cb) = retry_callback.as_mut() {
                        retry_triggered = true;
                        let repaired = cb(cand, &reasons, 1);
                        let (ok2, entry2, reasons2) = self.score_single(source_en, &repaired);
                        entry = entry2;
                        if ok2 {
                            consecutive_failures = 0;
                        } else {
                            consecutive_failures += 1;
                            all_reasons.extend(reasons2);
                        }
                    } else {
                        all_reasons.extend(reasons);
                    }
                } else {
                    all_reasons.extend(reasons);
                }
            }
            out_map.insert(cand.locale.clone(), entry);
        }

        let min_bleu = out_map
            .values()
            .map(|v| v.bleu4)
            .fold(100.0f64, f64::min);
        let min_chrf = out_map
            .values()
            .map(|v| v.chrf_pp)
            .fold(100.0f64, f64::min);
        let min_comet = out_map
            .values()
            .map(|v| v.comet_proxy)
            .fold(1.0f64, f64::min);
        let num_ok = out_map.values().all(|v| v.numeric_id_conserved);
        let quarantined = consecutive_failures >= 2;
        let passed = all_reasons.is_empty() && !quarantined;

        (
            TranslationGateReport {
                passed,
                evaluated_locales: candidates.iter().map(|c| c.locale.clone()).collect(),
                min_bleu4: round4(min_bleu),
                min_chrf_pp: round4(min_chrf),
                min_comet_proxy: round4(min_comet),
                numeric_id_conservation_ok: num_ok,
                consecutive_failures,
                retry_triggered,
                quarantined_do_not_ship: quarantined,
                failure_reasons: all_reasons,
            },
            out_map,
        )
    }
}

// ---------------------------------------------------------------------------
// 3. AccessibilityGate
// ---------------------------------------------------------------------------

fn count_plain_words(s: &str) -> usize {
    let chars: Vec<char> = s.chars().collect();
    let mut count = 0usize;
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i].is_ascii_alphanumeric() {
            count += 1;
            i += 1;
            while i < chars.len()
                && (chars[i].is_ascii_alphanumeric()
                    || ((chars[i] == '-' || chars[i] == '\'')
                        && i + 1 < chars.len()
                        && chars[i + 1].is_ascii_alphanumeric()))
            {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    count
}

fn is_acronym_token(tok: &str) -> bool {
    tok.bytes().filter(|b| b.is_ascii_uppercase()).count() >= 2
}

pub fn compute_easy_read_metrics(text: &str, bullets: &[String]) -> (f64, Vec<String>) {
    let mut word_counts = Vec::new();
    for block in std::iter::once(text).chain(bullets.iter().map(|s| s.as_str())) {
        let trimmed = block.trim();
        for seg in trimmed.split(|c| matches!(c, '.' | '!' | '?')) {
            let s = seg.trim();
            if !s.is_empty() {
                let wc = count_plain_words(s);
                if wc > 0 {
                    word_counts.push(wc);
                }
            }
        }
    }
    if word_counts.is_empty() {
        return (0.0, Vec::new());
    }
    let avg_wps = round4(word_counts.iter().sum::<usize>() as f64 / word_counts.len() as f64);

    let mut full = String::from(text);
    for b in bullets {
        full.push(' ');
        full.push_str(b);
    }
    let full_bytes = full.as_bytes();
    let mut acronyms = Vec::new();
    let mut idx = 0usize;
    while idx < full_bytes.len() {
        if full_bytes[idx].is_ascii_alphanumeric() {
            let start = idx;
            idx += 1;
            while idx < full_bytes.len() && full_bytes[idx].is_ascii_alphanumeric() {
                idx += 1;
            }
            let tok = &full[start..idx];
            if is_acronym_token(tok) {
                let explained_inline = start >= 2
                    && full_bytes[start - 1] == b'('
                    && idx < full_bytes.len()
                    && full_bytes[idx] == b')'
                    && {
                        let prefix_start = start.saturating_sub(60);
                        // Find safe char boundary
                        let mut ps = prefix_start;
                        while !full.is_char_boundary(ps) && ps < start {
                            ps += 1;
                        }
                        count_plain_words(&full[ps..start - 1]) >= tok.len()
                    };
                if !explained_inline && !acronyms.iter().any(|a| a == tok) {
                    acronyms.push(tok.to_string());
                }
            }
        } else {
            idx += 1;
        }
    }

    (avg_wps, acronyms)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccessibilityGateReport {
    pub passed: bool,
    pub wcag_22_aa_captions_ok: bool,
    pub easy_read_ok: bool,
    pub easy_read_avg_words_per_sentence: f64,
    pub unexplained_acronyms: Vec<String>,
    pub audio_description_ok: bool,
    pub aac_concepts_resolved: bool,
    pub failure_reasons: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct AccessibilityGate;

impl AccessibilityGate {
    pub const MAX_AVG_WORDS_PER_SENTENCE: f64 = 18.0;

    pub fn evaluate(
        &self,
        modality_variants: &Value,
        human_in_gate: bool,
    ) -> AccessibilityGateReport {
        let mut reasons = Vec::new();
        if human_in_gate {
            reasons.push("human_in_gate_forbidden".to_string());
        }

        let mv = match modality_variants.as_object() {
            Some(m) => m,
            None => {
                reasons.push("modality_variants_not_object".to_string());
                return AccessibilityGateReport {
                    passed: false,
                    wcag_22_aa_captions_ok: false,
                    easy_read_ok: false,
                    easy_read_avg_words_per_sentence: 0.0,
                    unexplained_acronyms: Vec::new(),
                    audio_description_ok: false,
                    aac_concepts_resolved: false,
                    failure_reasons: reasons,
                };
            }
        };

        let mut captions_ok = true;
        let mut has_primary = false;

        if let Some(tx) = mv.get("text") {
            has_primary = true;
            let ok = tx
                .as_object()
                .map(|o| {
                    o.get("summary")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.is_empty())
                        && o.get("uri")
                            .and_then(|v| v.as_str())
                            .is_some_and(|s| !s.is_empty())
                })
                .unwrap_or(false);
            if !ok {
                captions_ok = false;
                reasons.push("wcag_text_summary_missing".to_string());
            }
        }

        if let Some(au) = mv.get("audio") {
            has_primary = true;
            let ok = au
                .as_object()
                .map(|o| {
                    o.get("captions_vtt_uri")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| s.ends_with(".vtt"))
                        && o.get("transcript_uri")
                            .and_then(|v| v.as_str())
                            .is_some_and(|s| !s.is_empty())
                })
                .unwrap_or(false);
            if !ok {
                captions_ok = false;
                reasons.push("wcag_audio_captions_or_transcript_missing".to_string());
            }
        }

        if let Some(vd) = mv.get("video") {
            has_primary = true;
            match vd.as_object() {
                Some(vmap) if !vmap.is_empty() => {
                    for (slot, cut) in vmap {
                        let ok = cut
                            .as_object()
                            .map(|o| {
                                o.get("vtt_uri")
                                    .and_then(|v| v.as_str())
                                    .is_some_and(|s| s.ends_with(".vtt"))
                                    && o.get("transcript")
                                        .and_then(|v| v.as_str())
                                        .is_some_and(|s| !s.is_empty())
                            })
                            .unwrap_or(false);
                        if !ok {
                            captions_ok = false;
                            reasons.push(format!(
                                "wcag_video_cut_missing_vtt_or_transcript:{slot}"
                            ));
                        }
                    }
                }
                _ => {
                    captions_ok = false;
                    reasons.push("wcag_video_cuts_empty".to_string());
                }
            }
        }

        if !has_primary {
            captions_ok = false;
            reasons.push("wcag_no_primary_modality_present".to_string());
        }

        let mut easy_read_ok = true;
        let mut avg_wps = 0.0;
        let mut acronyms = Vec::new();
        match mv.get("plain_easy_read").and_then(|v| v.as_object()) {
            Some(er) => {
                let text = er.get("text").and_then(|v| v.as_str()).unwrap_or("");
                let bullets: Vec<String> = er
                    .get("bullets")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                if text.is_empty() || bullets.is_empty() {
                    easy_read_ok = false;
                    reasons.push("easy_read_missing".to_string());
                } else {
                    let (w, acr) = compute_easy_read_metrics(text, &bullets);
                    avg_wps = w;
                    acronyms = acr;
                    if avg_wps <= 0.0 || avg_wps > Self::MAX_AVG_WORDS_PER_SENTENCE {
                        easy_read_ok = false;
                        reasons.push(format!(
                            "easy_read_sentence_length_exceeded:{avg_wps}>{}",
                            Self::MAX_AVG_WORDS_PER_SENTENCE
                        ));
                    }
                    if !acronyms.is_empty() {
                        easy_read_ok = false;
                        reasons.push(format!(
                            "easy_read_unexplained_acronyms:{}",
                            acronyms.join(",")
                        ));
                    }
                }
            }
            None => {
                easy_read_ok = false;
                reasons.push("easy_read_missing".to_string());
            }
        }

        let ad_ok = mv
            .get("audio_description")
            .and_then(|v| v.as_object())
            .map(|ad| {
                ad.get("track_uri")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty())
                    && ad
                        .get("script")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.is_empty())
                    && matches!(
                        ad.get("voicing").and_then(|v| v.as_str()),
                        Some("machine" | "human")
                    )
            })
            .unwrap_or(false);
        if !ad_ok {
            reasons.push("audio_description_track_missing_or_invalid".to_string());
        }

        let mut aac_ok = true;
        match mv.get("aac_concepts").and_then(|v| v.as_array()) {
            Some(arr) if !arr.is_empty() => {
                for item in arr {
                    match item.as_object() {
                        Some(obj) => {
                            let cid = obj.get("concept_id").and_then(|v| v.as_str()).unwrap_or("");
                            let uri = obj
                                .get("symbol_anchor_uri")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            match resolve_aac_anchor(cid) {
                                Some(expected_uri) if expected_uri == uri => {}
                                _ => {
                                    aac_ok = false;
                                    reasons.push(format!("aac_concept_unresolved:{cid}"));
                                }
                            }
                        }
                        None => {
                            aac_ok = false;
                            reasons.push("aac_concept_malformed".to_string());
                        }
                    }
                }
            }
            _ => {
                aac_ok = false;
                reasons.push("aac_concepts_missing".to_string());
            }
        }

        AccessibilityGateReport {
            passed: reasons.is_empty(),
            wcag_22_aa_captions_ok: captions_ok,
            easy_read_ok,
            easy_read_avg_words_per_sentence: avg_wps,
            unexplained_acronyms: acronyms,
            audio_description_ok: ad_ok,
            aac_concepts_resolved: aac_ok,
            failure_reasons: reasons,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scientific_gate_accepts_valid_six_kernel_lean_and_measured_j() {
        let gate = ScientificGate;
        let joules = 927.30e-6;
        let energy = EnergyCostSpec {
            evidence_class: "measured_j".to_string(),
            joules: Some(joules),
            meter_or_formula: "NVIDIA Jetson AGX Thor TI INA3221 VDD_CPU_SOC_MSS DC shunt".to_string(),
            board_metered: true,
            landauer_300k_bits_equiv: Some(compute_landauer_300k_bits(joules)),
        };
        let lean = LeanProofReceipt {
            lean_version: "4.36.0".to_string(),
            bwrap_sandboxed: true,
            kernels_verified: EXPECTED_SIX_LEAN_KERNELS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            theorem_count: 45,
            sorry_count: 0,
            axioms_used: vec!["propext".to_string()],
            of_reduce_bool_count: 0,
            opaque_bypass_count: 0,
        };
        let mut sat = SatMiterReceipt {
            suite_id: "xc7a200t-kv260-miter".to_string(),
            lhs_ir_hash: "a".repeat(64),
            rhs_ir_hash: "b".repeat(64),
            vector_count: 10_500,
            mismatch_count: 0,
            status: "unsat".to_string(),
            claimed_digest: None,
        };
        sat.claimed_digest = Some(sat.compute_digest());

        let report = gate.evaluate(&energy, Some(&lean), Some(&sat), None, false);
        assert!(report.passed, "expected pass: {:?}", report.failure_reasons);
        assert!(report.lean_kernel_checked);
        assert_eq!(report.kernel_count, Some(6));
        assert!(report.energy_non_mixing_ok);
    }

    #[test]
    fn scientific_gate_rejects_sorry_of_reduce_bool_and_energy_mixing() {
        let gate = ScientificGate;
        let joules = 12.5;
        let bad_energy = EnergyCostSpec {
            evidence_class: "measured_j".to_string(),
            joules: Some(joules),
            meter_or_formula: "INA238 shunt + Linux RAPL package counter".to_string(),
            board_metered: false,
            landauer_300k_bits_equiv: Some(compute_landauer_300k_bits(joules)),
        };
        let bad_lean = LeanProofReceipt {
            lean_version: "4.36.0".to_string(),
            bwrap_sandboxed: false,
            kernels_verified: vec!["lean4-v4.36.0".to_string()],
            theorem_count: 10,
            sorry_count: 1,
            axioms_used: vec!["MyCustomUnsafeAxiom".to_string()],
            of_reduce_bool_count: 2,
            opaque_bypass_count: 0,
        };
        let report = gate.evaluate(&bad_energy, Some(&bad_lean), None, None, false);
        assert!(!report.passed);
        assert!(!report.energy_non_mixing_ok);
        assert!(report
            .failure_reasons
            .iter()
            .any(|r| r.contains("measured_j_requires_board_metered_true")));
        assert!(report
            .failure_reasons
            .iter()
            .any(|r| r.contains("energy_classes_mixed_measured_and_reported")));
        assert!(report
            .failure_reasons
            .iter()
            .any(|r| r.contains("lean_sorry_nonzero:1")));
        assert!(report
            .failure_reasons
            .iter()
            .any(|r| r.contains("lean_of_reduce_bool_nonzero:2")));
        assert!(report
            .failure_reasons
            .iter()
            .any(|r| r.contains("lean_custom_axioms_or_opaque_nonzero:1")));
    }

    #[test]
    fn translation_gate_retries_on_first_failure_and_quarantines_on_second_consecutive_failure() {
        let gate = TranslationGate::default();
        let src = "Every safety check on CTA-T29 verifies 100 percent consent within 30 microcoulombs.";
        let good_es = "Cada control de seguridad en CTA-T29 verifica el 100 por ciento de consentimiento dentro de 30 microculombios.";
        let bad_es = "Cada control en CTA-T29 verifica el 99 por ciento dentro de 45 microculombios.";

        // Case A: Failure #1 -> automatic retry repairs numeric corruption -> passes!
        let cand_a = vec![TranslationCandidate {
            locale: "es".to_string(),
            title: "Cortafuegos de consentimiento".to_string(),
            plain_easy_read: bad_es.to_string(),
            reference_text: good_es.to_string(),
        }];
        let (rep_a, _) = gate.evaluate(
            src,
            &cand_a,
            Some(|c: &TranslationCandidate, _reasons: &[String], _attempt: usize| {
                TranslationCandidate {
                    locale: c.locale.clone(),
                    title: c.title.clone(),
                    plain_easy_read: good_es.to_string(),
                    reference_text: c.reference_text.clone(),
                }
            }),
            0,
            false,
        );
        assert!(rep_a.passed);
        assert!(rep_a.retry_triggered);
        assert_eq!(rep_a.consecutive_failures, 0);
        assert!(!rep_a.quarantined_do_not_ship);

        // Case B: Failure #1 + Retry ALSO fails -> 2 consecutive failures -> quarantined_do_not_ship!
        let (rep_b, _) = gate.evaluate(
            src,
            &cand_a,
            Some(|c: &TranslationCandidate, _reasons: &[String], _attempt: usize| c.clone()),
            0,
            false,
        );
        assert!(!rep_b.passed);
        assert!(rep_b.retry_triggered);
        assert_eq!(rep_b.consecutive_failures, 2);
        assert!(rep_b.quarantined_do_not_ship);
    }

    #[test]
    fn accessibility_gate_enforces_wcag_easy_read_ad_and_aac() {
        let gate = AccessibilityGate;
        let good_mv = json!({
            "text": {
                "uri": "https://research.openie.dev/papers/agency/",
                "media_type": "text/html",
                "summary": "Defines goal-holding agents under physical energy budgets."
            },
            "plain_easy_read": {
                "text": "An agent aims at a clear goal and acts within an energy budget. Among systems that finish the job right, the one using less energy wins.",
                "bullets": [
                    "Every action pays an energy price.",
                    "Finish the task right before ranking by energy."
                ],
                "avg_words_per_sentence": 11.0
            },
            "audio_description": {
                "track_uri": "https://commons.openie.dev/ad/paper/agency.vtt",
                "script": "A three-dimensional curve rises between slow idle drain on the left and fast switching heat on the right.",
                "voicing": "machine"
            },
            "aac_concepts": [
                {
                    "concept_id": "aac:goal-agent",
                    "label": "Agent aiming at a goal",
                    "symbol_anchor_uri": "https://commons.openie.dev/aac/goal-agent"
                },
                {
                    "concept_id": "aac:energy-budget",
                    "label": "Energy budget in joules",
                    "symbol_anchor_uri": "https://commons.openie.dev/aac/energy-budget"
                }
            ]
        });
        let rep = gate.evaluate(&good_mv, false);
        assert!(rep.passed, "expected pass: {:?}", rep.failure_reasons);

        // Adversarial: long >18 word sentence + unexplained acronyms GPU & MoE + broken AAC URI
        let bad_mv = json!({
            "text": {
                "uri": "https://research.openie.dev/papers/agency/",
                "media_type": "text/html",
                "summary": "Summary."
            },
            "plain_easy_read": {
                "text": "When a massive MoE cluster executes unverified speculative rollouts across eight interconnected GPU nodes without any hardware shunt telemetry or formal gate checks, energy explodes catastrophically.",
                "bullets": ["Check RAPL counters carefully."],
                "avg_words_per_sentence": 20.0
            },
            "aac_concepts": [
                {
                    "concept_id": "aac:nonexistent-symbol",
                    "label": "Broken",
                    "symbol_anchor_uri": "https://commons.openie.dev/aac/nonexistent-symbol"
                }
            ]
        });
        let bad_rep = gate.evaluate(&bad_mv, false);
        assert!(!bad_rep.passed);
        assert!(!bad_rep.easy_read_ok);
        assert!(bad_rep.unexplained_acronyms.contains(&"MoE".to_string()));
        assert!(bad_rep.unexplained_acronyms.contains(&"GPU".to_string()));
        assert!(bad_rep.unexplained_acronyms.contains(&"RAPL".to_string()));
        assert!(!bad_rep.audio_description_ok);
        assert!(!bad_rep.aac_concepts_resolved);
    }
}
