# `openie-artifact-substrate`

**Canonical OpenIE Artifact Substrate, Conforming `WAI1` (`application/vnd.wai`) Envelope Adapter, and Deterministic Verification Gate Library (`Zero Humans in the Gates`).**

[![License: Apache-2.0](https://img.shields.io/badge/Code%20%26%20WAI1-Apache--2.0-blue.svg)](LICENSE)
[![Commons: CC0-1.0](https://img.shields.io/badge/Commons%20%26%20Corpora-CC0--1.0-brightgreen.svg)](LICENSING_HYGIENE.md)
[![Hardware: CERN-OHL-S-2.0](https://img.shields.io/badge/Morphologies-CERN--OHL--S--2.0-orange.svg)](LICENSING_HYGIENE.md)

---

## Overview

`openie-artifact-substrate` eliminates format siloing across the Open Interface Engineering (OpenIE) research, media, educational, commons, and open-robotics ecosystem by binding every artifact to:

1. **One Canonical Schema (`schema/openie-artifact-v1.schema.json`, Draft 2020-12)** covering content-addressed `BLAKE3` `canonical_id`s, `Ed25519` (`RFC 8032`) signatures over `RFC 8785` (JCS) canonical JSON, non-mixing `energy_cost_j` ledgers (`measured_j` | `reported_j` | `est_j` | `unmetered` + `300 K` Landauer bit-equivalents), 9-Rung Computer Intelligence Avalanche placement, multimodal variants, tri-tier SPDX licensing (`CC0-1.0`, `Apache-2.0`, `CERN-OHL-S-2.0`), and `WAI1` interchange metadata.
2. **Dual-Language Conforming `WAI1` Envelope Adapter (`crates/openie-wai-adapter` in `#![forbid(unsafe_code)]` Rust 1.100.0 + `python/openie_artifact/wai_adapter.py`)** implementing byte-exact `WAI1` framing (`SPEC.md` §2 & §3), strict token-level compact JSON validation (rejecting `-0`, `1.0`, `1e0` on integers, duplicate member names after escape decoding, insignificant whitespace, `man_len > 2^27`, nesting `> 127`, values `> 2^22`), `RFC 8878` `wai.text.zstd` mandatory-floor compression with pre-allocation `<= 2^27` window/content bounds, and bit-identical cross-language `BLAKE3` + `Ed25519` verification.
3. **Deterministic Verification Gate Library (`crates/openie-gates` + `python/openie_artifact/gates.py`)** enforcing `human_in_gate: false`:
   - **`ScientificGate`**: Validates `Lean 4.36.0` `bwrap` 6-kernel proof receipts (`lean4-v4.36.0`, `lean4lean`, `nanoda`, `leanchecker`, `con-leche`, `con-ron` with `0 sorry`, `0 custom axioms`, `0 ofReduceBool`), `BLAKE3` SAT/miter `unsat` equivalence digests, and strict energy-class non-mixing.
   - **`TranslationGate`**: Computes deterministic `BLEU-4`, `chrF++`, `128-D` `BLAKE3` semantic `COMET`-proxy similarity, and 100% numeric + formal-identifier conservation; triggers automatic retry on Failure #1 and stamps `flagged_do_not_ship` quarantine on 2 consecutive failures.
   - **`AccessibilityGate`**: Enforces WCAG 2.2 AA caption/transcript presence, Easy-Read sentence length (`<= 18.0` words/sentence avg) with zero unexplained acronyms, audio-description track pointers, and OpenIE Commons AAC symbol resolution (`https://commons.openie.dev/aac/*`).

---

## Unsiloed Catalog Summary (`catalog/unsiloed-artifacts.jsonl`)

| Artifact Domain (`artifact_kind`) | Records | Sub-Items / Scope | SPDX License |
| :--- | ---: | :--- | :--- |
| **`paper`** | `21` | All 21 OpenIE research studies & white papers | `Apache-2.0` / `CC0-1.0` |
| **`tv`** | `28` | All 28 Research TV studies × 4 depth slots = **`112` cuts** (`15s`, `45s`, `90s`, `180s`) | `CC0-1.0` |
| **`radio`** | `15` | All 15 Research Radio studio broadcasts (`ep01..ep15`) | `CC0-1.0` |
| **`tutorial`** | `12` | All 12 interactive `Predict -> Break -> Repair -> Verify` labs (`lab-01..lab-12`) | `Apache-2.0` |
| **`concept`** | `36` | All 36 W3C SKOS & WCAG 2.2 AA AAC Glossary Concepts (`research.openie.dev/glossary/concepts.json`) | `CC0-1.0` |
| **`humanoid_prior_art`** | `1,102` | Full Free Humanoid Prior-Art Corpus (`R.U.R.` 1920 -> `WABOT-1` -> modern humanoids) | `CC0-1.0` |
| **`phone_prior_art`** | `344` | Full Free Phone Handset & Baseband-Activation Prior-Art Corpus | `CC0-1.0` |
| **`wearable_prior_art`** | `238` | Full Free Wearable Body-Worn Sensor & Interface Prior-Art Corpus | `CC0-1.0` |
| **`evtol_prior_art`** | `307` | Full Free eVTOL & Distributed Electric Propulsion Prior-Art Corpus | `CC0-1.0` |
| **`humanoid_morphology`** | `1` | `free-humanoid-platform` (17th OpenLoco bipedal morphology) | `CERN-OHL-S-2.0` |
| **`hardware_subsystem`** | `10` | Tri-licensed `free-humanoid-platform` subsystems (`descriptor`, `datasets`, `prior-art`, `chassis-bom`, `firmware`, `control`, `sim`, `actuators`, `chassis`, `electronics`) | `CC0-1.0` / `Apache-2.0` / `CERN-OHL-S-2.0` |
| **`blueprint`** | `1` | [Blueprint for Unsiloeing the OpenIE Ecosystem](catalog/blueprint-unsiloeing-openie-2026-11-24.md) | `CC0-1.0` |
| **Total** | **`2,115`** | **118 persisted `.wai` envelopes in `catalog/envelopes/` + full cross-language Rust receipt + `./release.sh`** | — |

---

## Repository Layout

```text
openie-artifact-substrate/
├── Cargo.toml                                        # Rust workspace (openie-wai-adapter, openie-gates)
├── LICENSE                                           # Apache-2.0 full text
├── LICENSING_HYGIENE.md                              # Tri-tier SPDX policy (CC0-1.0, Apache-2.0, CERN-OHL-S-2.0)
├── pyproject.toml                                    # Zero-dependency Python package config
├── release.sh                                        # Universal OpenIE substrate release ceremony
├── schema/
│   └── openie-artifact-v1.schema.json                # JSON Schema Draft 2020-12
├── crates/
│   ├── openie-gates/src/lib.rs                       # Rust ScientificGate, TranslationGate, AccessibilityGate
│   └── openie-wai-adapter/
│       ├── src/lib.rs                                # Strict WAI1 container codec, JCS, BLAKE3 + Ed25519
│       └── src/bin/openie_substrate_cli.rs           # Cross-language catalog + .wai + Merkle DAG verifier
├── python/openie_artifact/
│   ├── crypto.py                                     # Pure-Python BLAKE3, RFC 8032 Ed25519, RFC 8785 JCS
│   ├── wai_adapter.py                                # Strict WAI1 codec & RFC 8878 zstd framing
│   ├── gates.py                                      # Python ScientificGate, TranslationGate, AccessibilityGate
│   └── schema_validator.py                           # Draft 2020-12 structural & semantic validator
├── python/openie_syndicate/
│   ├── oauth1.py                                     # RFC 5849 OAuth 1.0a HMAC-SHA1 & X weighted 280-char counter
│   ├── ledger.py                                     # Idempotent BLAKE3 syndication ledger & crosslink resolver
│   ├── x_medium_bridge.py                            # Bidirectional X <-> Medium essay/thread composer & v2/RSS sync
│   ├── tiktok_client.py                              # TikTok Content Posting API v2 (PULL_FROM_URL & FILE_UPLOAD)
│   ├── mirrors.py                                    # Resilient mirrors (Internet Archive IAS3, Mastodon, Bluesky)
│   └── ecosystem_matrix.py                           # 6-tier outbound/bidirectional/inbound ecosystem matrix
├── scripts/
│   ├── build_unsiloed_catalog.py                     # Deterministic ecosystem ingestion & WAI1 packager
│   ├── emit_substrate_release.py                     # WAI1 release envelope & Ed25519 JWP receipt emitter
│   ├── syndicate.py                                  # Deterministic X <-> Medium, TikTok & ecosystem syndication CLI
│   └── verify_release.sh                             # Offline release verification script
├── tests/                                            # Python unittest / pytest conformance & adversarial suite
└── catalog/
    ├── blueprint-unsiloeing-openie-2026-11-24.md     # Unsiloeing Blueprint Document (CC0-1.0)
    ├── unsiloed-artifacts.jsonl                      # 2,115 signed, gate-verified Canonical Artifacts
    ├── verification-receipt.json                     # Deterministic Rust cross-verification receipt
    └── envelopes/*.wai                               # Conforming WAI1 binary containers
```

---

## Verification & Reproduction

```bash
# 1. Run all Rust unit & adversarial tests (0 warnings)
cargo test --workspace

# 2. Cross-verify all 2,115 Python-signed records & 118 .wai envelopes using the Rust CLI
cargo run --release --bin openie_substrate_cli -- .

# 3. Run the Python conformance & adversarial test suite (zero external dependencies)
PYTHONPATH=python python3 -m unittest discover -s tests -v

# 4. Build deterministic substrate release tarball, WAI1 envelope & Ed25519 JWP receipt
./release.sh 2026.11.24 --dry-run
```
