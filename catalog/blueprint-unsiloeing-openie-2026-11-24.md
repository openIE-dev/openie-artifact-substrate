# Blueprint for Unsiloeing the OpenIE Ecosystem (`2026-11-24`)

- **Document Slug**: `blueprint-unsiloeing-openie-2026-11-24`
- **License**: `CC0-1.0` (Public Domain Dedication — OpenIE Commons)
- **Canonical Substrate**: `https://github.com/openIE-dev/openie-artifact-substrate`
- **Transport Envelope**: `.WAI` (`WAI1`, `application/vnd.wai`, `wai.text.zstd` mandatory floor)
- **Gate Invariant**: `human_in_gate: false` (Zero Humans in the Gates)

---

## 1. Problem Statement: Siloed Excellence Is an Interface Bug

Across the Open Interface Engineering (OpenIE) ecosystem, verified scientific, media, educational, and embodied-robotics artifacts previously lived in isolated format silos:

1. **OpenIE Research Papers (`21` studies)**: Formal Lean 4.36.0 six-kernel proofs (`time-as-an-index`, `communication-avalanche`, `lut-adapt`, `rce`), deterministic integer/fixed-point harnesses (`deterministic-null`, `satb-harness`, `game-engines`, `rce-compile`, `rce-vc`), hardware-metered experiments (`gates`, `mei`, `jouleos`), and thermodynamic/economic foundations (`agency`, `satiation`, `three-body`, `ai-reads-human`, `spellcheck`, `ai-coding-market`, `interface-economics`, `latency`).
2. **OpenIE Research TV (`28` studies × `4` depth tiers = `112` cuts)**: `15s`, `45s`, `90s`, and `180s` studio explainer films with WebVTT captions, word-aligned cues, and three-dimensional technical cutaways across all `21` studies plus `7` flagship `*.openie.dev` channel openers (`eco-avalanche`, `eco-stack`, `eco-compute`, `eco-synthesis`, `eco-knowledge`, `eco-database`, `lut6-codon-nucleus`).
3. **OpenIE Research Radio (`15` autonomous broadcasts, `ep01..ep15`)**: Multi-voice dialogue broadcasts cross-examining live open-access preprints against Metered Commit Gates, Shape D controls, and physical shunt telemetry.
4. **Interactive Tutorials (`12` browser labs, `lab-01..lab-12`)**: Four-step `Predict -> Break -> Repair -> Verify` laboratories spanning Track A (*Communication Avalanche*) and Track B (*Core OpenIE & Silicon Stack*).
5. **The Commons & Accessibility Layers (`36` W3C SKOS AAC Concepts)**: Easy-Read plain-language summaries (`<= 18` words/sentence, zero unexplained acronyms), WCAG 2.2 AA captions/transcripts, audio-description scripts, Augmentative and Alternative Communication (AAC) concept anchors (`https://commons.openie.dev/aac/*`), and verified multilingual translations.
6. **Multi-Domain CC0 Prior-Art Corpora (`1,991` disclosures) & OpenLoco Morphologies**: `1,102` Free Humanoid + `344` Free Phone + `238` Free Wearable + `307` Free eVTOL defensive prior-art disclosures under `CC0-1.0`, plus `free-humanoid-platform` (the 17th OpenLoco morphology and its `10` tri-licensed `CC0-1.0` / `Apache-2.0` / `CERN-OHL-S-2.0` subsystems), all sharing one `./release.sh` + `WAI1` ceremony.

Without one shared content-addressed substrate, provenance links were URL strings instead of cryptographic hashes, energy telemetry risked losing its acquisition boundary, and accessibility or multilingual completeness could drift across channels.

---

## 2. Three-Step Unsiloeing Architecture

### Step 1 — Canonical OpenIE Artifact Schema (`openie-artifact-v1.schema.json`)

Every artifact in the OpenIE universe projects onto one JSON Schema Draft 2020-12 record with eight mandatory structural commitments:

1. **`canonical_id`**: `blake3:<kind>:<64-hex>` over the canonical UTF-8 payload across `paper`, `tv`, `radio`, `tutorial`, `humanoid_prior_art`, `humanoid_morphology`, `blueprint`, and `concept`.
2. **`provenance_chain`**: Dual `BLAKE3` + `SHA-256` payload digests, `RFC 8032` `Ed25519` public key and deterministic signature over `RFC 8785` (JCS) canonical JSON, UTC commit timestamp, content-addressed `lineage_parents[]` forming a cycle-free Merkle DAG, and cryptographic anchors (`git_commit`, `rfc3161_tsr`, `opentimestamps_ots`, `drand_round`, `jcr1_receipt_blake3`).
3. **`energy_cost_j`**: Strict four-way acquisition partition—`measured_j` (physical board shunt, `board_metered: true`), `reported_j` (chip/OS software counters, `board_metered: false`), `est_j` (analytical/datasheet bound, `board_metered: false`), or `unmetered` (`joules: null`, never fake zero)—paired with `300 K` Landauer bit-erasure equivalents (`E / (k_B * 300 * ln 2)`). **Cross-class summation is forbidden.**
4. **`difficulty_rung`**: Placement on the 9-Rung Computer Intelligence Avalanche (`rung: 1..9`, `phase: 1 | 2`, `compilation_threshold_crossed: boolean`), separating downward-compiled/kernel-settled Phase 1 regimes (Rungs 1–5) from open-world/embodied Phase 2 synthesis regimes (Rungs 6–9).
5. **`verification_status`**: Machine-only verdict (`status: "verified" | "flagged_do_not_ship" | "draft"`, `human_in_gate: false`) binding `scientific_gate`, `translation_gate`, and `accessibility_gate`.
6. **`modality_variants`**: Unified multimodal bundle (`text`, `audio`, `video` `15s`/`45s`/`90s`/`180s`, `structure_3d`, `plain_easy_read`, `audio_description`, `aac_concepts`, and `multilingual`).
7. **`license`**: Tri-tier SPDX hygiene—`CC0-1.0` (commons, corpora, summaries, blueprints, accessibility), `Apache-2.0` (software, compilers, labs, `.WAI` adapters), and `CERN-OHL-S-2.0` (physical hardware & OpenLoco morphologies).
8. **`interchange_envelope`**: Byte-exact binding (`envelope_blake3`, `envelope_bytes`, `capability`) to a conforming `.WAI` (`WAI1`, `application/vnd.wai`) container.

### Step 2 — Conforming `WAI1` Envelope Adapter (`Rust 1.100.0` + `Python 3.11+`)

Every canonical artifact travels inside a byte-exact `WAI1` container (`SPEC.md` §2 & §3):

```text
+--------+----------------+-------------------+----------------+-----------+
| "WAI1" | u32  man_len   | manifest (JSON)   | u32 payload_len| payload   |
| 4 B    | little-endian  | man_len bytes     | little-endian  | bytes     |
+--------+----------------+-------------------+----------------+-----------+
```

Both `crates/openie-wai-adapter` (safe Rust, `#![forbid(unsafe_code)]`) and `python/openie_artifact/wai_adapter.py` (zero-dependency Python) enforce:
- `man_len <= 2^27` checked before reading the manifest, nesting depth `<= 127`, JSON value count `<= 2^22`, unique member names after escape decoding, zero insignificant whitespace, and strict integer tokenization rejecting `-0`, `1.0`, and `1e0`.
- Universal mandatory-floor `wai.text.zstd` (`RFC 8878`) payload framing with `<= 2^27` decoded-length and window-size checks prior to allocation.
- Bit-for-bit cross-verified `BLAKE3` + `Ed25519` (`RFC 8032`) signatures over `RFC 8785` canonical JSON.

### Step 3 — Deterministic Verification Gates (`Zero Humans in the Gates`)

No human reviewer sits inside the commit path (`human_in_gate: false`):
- **`ScientificGate`**: Audits Lean `4.36.0` `bwrap` six-kernel quorum (`lean4-v4.36.0`, `lean4lean`, `nanoda`, `leanchecker`, `con-leche`, `con-ron`) with `0 sorry`, `0 custom axioms`, and `0 ofReduceBool`; verifies `BLAKE3` SAT/miter `unsat` equivalence digests; and enforces `measured_j` / `reported_j` / `est_j` / `unmetered` non-mixing.
- **`TranslationGate`**: Computes deterministic `BLEU-4`, `chrF++`, `128-D` `BLAKE3` semantic `COMET`-proxy similarity, and 100% numeric + formal-identifier conservation (`CTA-T29`, `LA-28`, `GE-H1`, `DNULLMM1`, `WAI1`, etc.). Failure #1 triggers an automatic deterministic retry callback; two consecutive failures stamp `flagged_do_not_ship` and block publication.
- **`AccessibilityGate`**: Enforces WCAG 2.2 AA caption/transcript pointers across text/audio/video cuts, Easy-Read average sentence length `<= 18.0` words with zero unexplained acronyms, audio-description track pointers, and resolution of every `aac:*` symbol against the OpenIE Commons AAC registry (`https://commons.openie.dev/aac/*`).

---

## 3. Cross-Ecosystem Graph Linkages

This Blueprint anchors the root cross-ecosystem convergence node in `catalog/unsiloed-artifacts.jsonl`, linking directly via content-addressed `BLAKE3` parent edges to:
- **Communication Tool Avalanche & Foundations**: `communication-avalanche`, `agency`, `gates`, `lut-adapt`, `rce` (`paper` + `tv` + `tutorial`).
- **OpenIE Research Radio**: `ep01-global-literature-radar` through `ep15-codon-lut6-m2-silicon` (`radio`).
- **Free Humanoid Commons & Hardware**: `rur-rossums-robots`, `wabot-1`, `icub` (`humanoid_prior_art`, `CC0-1.0`) and `free-humanoid-platform` (17th OpenLoco morphology, `humanoid_morphology`, `CERN-OHL-S-2.0`).
