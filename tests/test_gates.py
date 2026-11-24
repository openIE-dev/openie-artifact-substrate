# SPDX-License-Identifier: Apache-2.0
"""Comprehensive unit and adversarial tests for ScientificGate, TranslationGate, and AccessibilityGate."""

from __future__ import annotations

import unittest

from openie_artifact.gates import (
    EXPECTED_SIX_LEAN_KERNELS,
    AccessibilityGate,
    LeanProofReceipt,
    SatMiterReceipt,
    ScientificGate,
    TranslationCandidate,
    TranslationGate,
    VerificationOrchestrator,
    compute_landauer_300k_bits,
)


class TestVerificationGates(unittest.TestCase):
    def test_scientific_gate_valid_and_adversarial_failures(self) -> None:
        gate = ScientificGate()
        j = 927.30e-6
        valid_energy = {
            "evidence_class": "measured_j",
            "joules": j,
            "meter_or_formula": "NVIDIA Jetson AGX Thor TI INA3221 DC current-shunt",
            "board_metered": True,
            "landauer_300k_bits_equiv": compute_landauer_300k_bits(j),
        }
        lean_ok = LeanProofReceipt(
            lean_version="4.36.0",
            bwrap_sandboxed=True,
            kernels_verified=tuple(sorted(EXPECTED_SIX_LEAN_KERNELS)),
            theorem_count=45,
            sorry_count=0,
            axioms_used=("propext",),
            of_reduce_bool_count=0,
            opaque_bypass_count=0,
        )
        sat_base = SatMiterReceipt(
            suite_id="miter-1",
            lhs_ir_hash="1" * 64,
            rhs_ir_hash="2" * 64,
            vector_count=10500,
            mismatch_count=0,
            status="unsat",
        )
        sat_ok = SatMiterReceipt(
            suite_id="miter-1",
            lhs_ir_hash="1" * 64,
            rhs_ir_hash="2" * 64,
            vector_count=10500,
            mismatch_count=0,
            status="unsat",
            claimed_digest=sat_base.compute_digest(),
        )
        res = gate.evaluate(
            energy_cost_j=valid_energy,
            lean_receipt=lean_ok,
            sat_miter_receipt=sat_ok,
        )
        self.assertTrue(res["passed"])
        self.assertEqual(res["kernel_count"], 6)
        self.assertTrue(res["energy_non_mixing_ok"])

        # Adversarial 1: mixing measured_j + reported_j RAPL, sorry > 0, ofReduceBool > 0, custom axiom, missing kernel
        mixed_energy = {
            "evidence_class": "measured_j",
            "joules": j,
            "meter_or_formula": "INA238 shunt + Linux RAPL package counter",
            "board_metered": False,
            "landauer_300k_bits_equiv": compute_landauer_300k_bits(j),
        }
        bad_lean = LeanProofReceipt(
            lean_version="4.36.0",
            bwrap_sandboxed=False,
            kernels_verified=("lean4-v4.36.0", "nanoda"),
            theorem_count=10,
            sorry_count=1,
            axioms_used=("UnsafeAxiom",),
            of_reduce_bool_count=1,
            opaque_bypass_count=1,
        )
        bad_sat = SatMiterReceipt(
            suite_id="miter-1",
            lhs_ir_hash="1" * 64,
            rhs_ir_hash="2" * 64,
            vector_count=10500,
            mismatch_count=3,
            status="sat",
            claimed_digest="0" * 64,
        )
        bad_res = gate.evaluate(
            energy_cost_j=mixed_energy,
            lean_receipt=bad_lean,
            sat_miter_receipt=bad_sat,
        )
        self.assertFalse(bad_res["passed"])
        self.assertFalse(bad_res["energy_non_mixing_ok"])
        reasons_joined = " | ".join(bad_res["failure_reasons"])
        self.assertIn("measured_j_requires_board_metered_true", reasons_joined)
        self.assertIn("energy_classes_mixed_measured_and_reported", reasons_joined)
        self.assertIn("lean_bwrap_sandbox_required", reasons_joined)
        self.assertIn("lean_six_kernel_quorum_incomplete:2/6", reasons_joined)
        self.assertIn("lean_sorry_nonzero:1", reasons_joined)
        self.assertIn("lean_custom_axioms_or_opaque_nonzero:2", reasons_joined)
        self.assertIn("lean_of_reduce_bool_nonzero:1", reasons_joined)
        self.assertIn("sat_miter_not_unsat:sat", reasons_joined)
        self.assertIn("sat_miter_mismatches:3", reasons_joined)
        self.assertIn("sat_miter_digest_mismatch", reasons_joined)

        # Adversarial 2: unmetered carrying fake 0.0 joules rejected!
        fake_zero = {
            "evidence_class": "unmetered",
            "joules": 0.0,
            "meter_or_formula": "None",
            "board_metered": False,
            "landauer_300k_bits_equiv": None,
        }
        self.assertFalse(gate.evaluate(energy_cost_j=fake_zero)["passed"])

    def test_translation_gate_retry_and_two_strike_quarantine(self) -> None:
        gate = TranslationGate()
        src = "The hardware check CTA-T29 verifies 100 percent consent under 30 microcoulombs."
        ref_es = "El control físico CTA-T29 verifica el 100 por ciento de consentimiento bajo 30 microculombios."
        corrupted_es = "El control físico CTA-T29 verifica el 85 por ciento de consentimiento bajo 44 microculombios."

        # 1. Single failure repaired by automatic retry callback -> ships as verified!
        cand_bad = [
            TranslationCandidate(
                locale="es",
                title="Cortafuegos",
                plain_easy_read=corrupted_es,
                reference_text=ref_es,
            )
        ]
        rep_recovered, ml_recovered = gate.evaluate(
            source_en=src,
            candidates=cand_bad,
            retry_callback=lambda c, _reasons, _attempt: TranslationCandidate(
                locale=c.locale,
                title=c.title,
                plain_easy_read=ref_es,
                reference_text=c.reference_text,
            ),
        )
        self.assertTrue(rep_recovered["passed"])
        self.assertTrue(rep_recovered["retry_triggered"])
        self.assertEqual(rep_recovered["consecutive_failures"], 0)
        self.assertFalse(rep_recovered["quarantined_do_not_ship"])
        self.assertTrue(ml_recovered["es"]["numeric_id_conserved"])

        # 2. Two consecutive failures -> stamps quarantined_do_not_ship = True and orchestrator sets flagged_do_not_ship!
        orch = VerificationOrchestrator()
        vs_quarantined, _ = orch.run_all(
            energy_cost_j={
                "evidence_class": "unmetered",
                "joules": None,
                "meter_or_formula": "Unmetered test",
                "board_metered": False,
                "landauer_300k_bits_equiv": None,
            },
            modality_variants={
                "text": {
                    "uri": "https://research.openie.dev/papers/communication-avalanche/",
                    "media_type": "text/html",
                    "summary": "Summary.",
                },
                "plain_easy_read": {
                    "text": "This plain text uses short sentences. Every step is verified.",
                    "bullets": ["Short plain sentence one.", "Short plain sentence two."],
                    "avg_words_per_sentence": 5.0,
                },
                "audio_description": {
                    "track_uri": "https://commons.openie.dev/ad/test.vtt",
                    "script": "Spoken visual description.",
                    "voicing": "machine",
                },
                "aac_concepts": [
                    {
                        "concept_id": "aac:consent-firewall",
                        "label": "Opt-in neural consent switch",
                        "symbol_anchor_uri": "https://commons.openie.dev/aac/consent-firewall",
                    }
                ],
            },
            source_en_for_translation=src,
            translation_candidates=cand_bad,
            retry_callback=lambda c, _reasons, _attempt: c,  # retry also fails -> failure #2!
        )
        self.assertEqual(vs_quarantined["status"], "flagged_do_not_ship")
        self.assertTrue(vs_quarantined["translation_gate"]["quarantined_do_not_ship"])
        self.assertEqual(vs_quarantined["translation_gate"]["consecutive_failures"], 2)

        # 3. Zero Humans in the Gates: passing human_in_gate=True raises immediately!
        with self.assertRaises(ValueError):
            orch.run_all(
                energy_cost_j={
                    "evidence_class": "unmetered",
                    "joules": None,
                    "meter_or_formula": "Unmetered",
                    "board_metered": False,
                    "landauer_300k_bits_equiv": None,
                },
                modality_variants={},
                source_en_for_translation=src,
                translation_candidates=[],
                human_in_gate=True,
            )

    def test_accessibility_gate_adversarial_failures(self) -> None:
        gate = AccessibilityGate()
        bad_mv = {
            "video": {
                "15s": {
                    "video_uri": "https://research.openie.dev/media/tv/films/agency-15s.mp4",
                    "vtt_uri": "",  # missing WebVTT!
                    "duration_s": 22.3,
                    "bytes": 1000,
                    "sha256": "a" * 64,
                    "hook": "Hook",
                    "transcript": "",
                }
            },
            "plain_easy_read": {
                "text": (
                    "When an unverified distributed MoE cluster executes speculative multi-agent "
                    "rollouts across eight GPU nodes without checking hardware RAPL or ZMP constraints, "
                    "the system wastes enormous amounts of electricity every single second."
                ),
                "bullets": [
                    "Inspect LoRA adapters carefully whenever large distributed clusters execute long speculative multi-turn rollouts without deterministic commit gates."
                ],
                "avg_words_per_sentence": 24.0,
            },
            "aac_concepts": [
                {
                    "concept_id": "aac:unknown-concept",
                    "label": "Unknown",
                    "symbol_anchor_uri": "https://commons.openie.dev/aac/unknown-concept",
                }
            ],
        }
        rep = gate.evaluate(modality_variants=bad_mv)
        self.assertFalse(rep["passed"])
        self.assertFalse(rep["wcag_22_aa_captions_ok"])
        self.assertFalse(rep["easy_read_ok"])
        self.assertGreater(rep["easy_read_avg_words_per_sentence"], 18.0)
        for acr in ("MoE", "GPU", "RAPL", "ZMP", "LoRA"):
            self.assertIn(acr, rep["unexplained_acronyms"])
        self.assertFalse(rep["audio_description_ok"])
        self.assertFalse(rep["aac_concepts_resolved"])


if __name__ == "__main__":
    unittest.main()
