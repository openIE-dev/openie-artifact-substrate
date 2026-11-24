# SPDX-License-Identifier: Apache-2.0
"""Schema Draft 2020-12 validation, full catalog verification, and privacy-hygiene tests."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from openie_artifact.crypto import blake3_hex, sha256_hex, verify_canonical_artifact_signature
from openie_artifact.schema_validator import SchemaValidationError, validate_openie_artifact
from openie_artifact.wai_adapter import decode_wai1_envelope

REPO_ROOT = Path(__file__).resolve().parent.parent

# Build privacy scan regex dynamically so the test file itself contains zero literal forbidden tokens
_PRIV_OCTETS = ["91", "111", "64", "78", "98", "100"]
_PRIV_PARTS = [f"100\\.{o}\\." for o in _PRIV_OCTETS] + [
    "".join(chr(c) for c in (100, 99, 104, 97, 114, 108, 111, 116)),
    "".join(chr(c) for c in (99, 98, 105, 111, 64)),
]
FORBIDDEN_PRIVACY_RE = re.compile("|".join(_PRIV_PARTS), re.IGNORECASE)


class TestSchemaAndCatalog(unittest.TestCase):
    def test_schema_file_is_valid_draft_2020_12(self) -> None:
        schema_path = REPO_ROOT / "schema" / "openie-artifact-v1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(
            schema["$schema"], "https://json-schema.org/draft/2020-12/schema"
        )
        self.assertEqual(
            sorted(schema["required"]),
            sorted(
                [
                    "canonical_id",
                    "provenance_chain",
                    "energy_cost_j",
                    "difficulty_rung",
                    "verification_status",
                    "modality_variants",
                    "license",
                    "interchange_envelope",
                ]
            ),
        )

    def test_schema_validator_rejects_mixed_energy_and_invalid_license(self) -> None:
        catalog_path = REPO_ROOT / "catalog" / "unsiloed-artifacts.jsonl"
        if not catalog_path.exists():
            self.skipTest("Catalog not yet generated")
        first_line = catalog_path.read_text(encoding="utf-8").splitlines()[0]
        sample = json.loads(first_line)
        validate_openie_artifact(sample)

        # Reject invalid license
        bad_lic = json.loads(first_line)
        bad_lic["license"] = "CC-BY-NC-4.0"
        with self.assertRaises(SchemaValidationError):
            validate_openie_artifact(bad_lic)

        # Reject measured_j with board_metered=False
        bad_energy = json.loads(first_line)
        bad_energy["energy_cost_j"] = {
            "evidence_class": "measured_j",
            "joules": 1.0,
            "meter_or_formula": "INA238",
            "board_metered": False,
            "landauer_300k_bits_equiv": 3.48e20,
        }
        with self.assertRaises(SchemaValidationError):
            validate_openie_artifact(bad_energy)

        # Reject human_in_gate=True
        bad_human = json.loads(first_line)
        bad_human["verification_status"]["human_in_gate"] = True
        with self.assertRaises(SchemaValidationError):
            validate_openie_artifact(bad_human)

    def test_unsiloed_catalog_completeness_signatures_and_envelopes(self) -> None:
        catalog_path = REPO_ROOT / "catalog" / "unsiloed-artifacts.jsonl"
        if not catalog_path.exists():
            self.skipTest("Catalog not yet generated")

        lines = [
            ln for ln in catalog_path.read_text(encoding="utf-8").splitlines() if ln.strip()
        ]
        records = [json.loads(ln) for ln in lines]
        self.assertEqual(len(records), 2115)

        counts: dict[str, int] = {}
        tv_cuts_total = 0
        cids = set()
        for rec in records:
            validate_openie_artifact(rec)
            self.assertTrue(verify_canonical_artifact_signature(rec))
            cid = rec["canonical_id"]
            self.assertNotIn(cid, cids)
            cids.add(cid)
            kind = rec["artifact_kind"]
            counts[kind] = counts.get(kind, 0) + 1
            if kind == "tv":
                tv_cuts_total += len(rec["modality_variants"]["video"])

            env_uri = rec["interchange_envelope"].get("envelope_uri", "")
            if env_uri.startswith("catalog/envelopes/"):
                env_file = REPO_ROOT / env_uri
                self.assertTrue(env_file.exists(), f"Missing {env_uri}")
                raw = env_file.read_bytes()
                dec = decode_wai1_envelope(raw)
                self.assertEqual(
                    dec.envelope_blake3, rec["interchange_envelope"]["envelope_blake3"]
                )
                self.assertEqual(
                    dec.envelope_bytes, rec["interchange_envelope"]["envelope_bytes"]
                )
                assert dec.decoded_payload is not None
                self.assertEqual(
                    blake3_hex(dec.decoded_payload),
                    rec["provenance_chain"]["content_blake3"],
                )
                self.assertEqual(
                    sha256_hex(dec.decoded_payload),
                    rec["provenance_chain"]["sha256"],
                )

        self.assertEqual(counts["radio"], 15)
        self.assertEqual(counts["tv"], 28)
        self.assertEqual(tv_cuts_total, 112)
        self.assertEqual(counts["paper"], 21)
        self.assertEqual(counts["tutorial"], 12)
        self.assertEqual(counts["concept"], 36)
        self.assertEqual(counts["humanoid_prior_art"], 1102)
        self.assertEqual(counts["phone_prior_art"], 344)
        self.assertEqual(counts["wearable_prior_art"], 238)
        self.assertEqual(counts["evtol_prior_art"], 307)
        self.assertEqual(counts["humanoid_morphology"], 1)
        self.assertEqual(counts["hardware_subsystem"], 10)
        self.assertEqual(counts["blueprint"], 1)

        # Verify every lineage_parents edge points to a canonical_id inside the catalog
        for rec in records:
            for parent_cid in rec["provenance_chain"]["lineage_parents"]:
                self.assertIn(parent_cid, cids)

    def test_zero_private_ips_or_usernames_across_repo(self) -> None:
        for path in REPO_ROOT.rglob("*"):
            if not path.is_file():
                continue
            rel_parts = path.relative_to(REPO_ROOT).parts
            if any(
                p in {".git", "target", "__pycache__", ".pytest_cache"} for p in rel_parts
            ):
                continue
            raw = path.read_bytes()
            text = raw.decode("utf-8", errors="ignore")
            matches = FORBIDDEN_PRIVACY_RE.findall(text)
            self.assertEqual(
                matches,
                [],
                f"Forbidden host/user token found in {path.relative_to(REPO_ROOT)}: {matches}",
            )


if __name__ == "__main__":
    unittest.main()
