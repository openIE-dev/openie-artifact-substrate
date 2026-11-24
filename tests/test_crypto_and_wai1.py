# SPDX-License-Identifier: Apache-2.0
"""Unit and adversarial conformance tests for BLAKE3, RFC 8032 Ed25519, JCS, and WAI1."""

from __future__ import annotations

import struct
import unittest

from openie_artifact.crypto import (
    blake3_hex,
    canonical_jcs_bytes,
    derive_default_signing_seed,
    ed25519_keypair_from_seed,
    ed25519_sign,
    ed25519_verify,
    sign_canonical_artifact,
    verify_canonical_artifact_signature,
)
from openie_artifact.wai_adapter import (
    MAX_MANIFEST_BYTES,
    MAX_ZSTD_DECODED_BYTES,
    Wai1Error,
    decode_wai1_envelope,
    encode_wai1_envelope,
    zstd_encode_deterministic,
)


def _official_blake3_test_input(length: int) -> bytes:
    # Official BLAKE3 test_vectors.json input generator: bytes([i % 251 for i in range(length)])
    return bytes(i % 251 for i in range(length))


class TestCryptoAndWai1(unittest.TestCase):
    def test_blake3_official_vectors_single_and_multi_chunk(self) -> None:
        # Official BLAKE3 specification test vectors (0, 1, 63, 64, 65, 1024, 1025, 2048, 8192 bytes)
        expected = {
            0: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            1: "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
            63: "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
            64: "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
            65: "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
            1024: "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
            1025: "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
            2048: "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
            8192: "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63",
        }
        for length, digest_hex in expected.items():
            with self.subTest(length=length):
                self.assertEqual(blake3_hex(_official_blake3_test_input(length)), digest_hex)

    def test_ed25519_rfc8032_test_vectors(self) -> None:
        # RFC 8032 §7.1 TEST 1 (empty message)
        seed1 = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        )
        expected_pub1 = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        expected_sig1 = (
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        _, pub1 = ed25519_keypair_from_seed(seed1)
        self.assertEqual(pub1.hex(), expected_pub1)
        sig1 = ed25519_sign(seed1, b"")
        self.assertEqual(sig1.hex(), expected_sig1)
        self.assertTrue(ed25519_verify(pub1, b"", sig1))
        self.assertFalse(ed25519_verify(pub1, b"x", sig1))

        # RFC 8032 §7.1 TEST 2 (1-byte 0x72 message)
        seed2 = bytes.fromhex(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
        )
        expected_pub2 = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        expected_sig2 = (
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        )
        _, pub2 = ed25519_keypair_from_seed(seed2)
        self.assertEqual(pub2.hex(), expected_pub2)
        sig2 = ed25519_sign(seed2, b"\x72")
        self.assertEqual(sig2.hex(), expected_sig2)
        self.assertTrue(ed25519_verify(pub2, b"\x72", sig2))

    def test_jcs_canonicalization_and_artifact_signing(self) -> None:
        doc = {"b": 1, "a": [0.0, -0.0, 9.273e-4, 1e-7, 3.4831896e20, 3.4831896e21]}
        self.assertEqual(
            canonical_jcs_bytes(doc),
            b'{"a":[0,0,0.0009273,1e-7,348318960000000000000,3.4831896e+21],"b":1}',
        )

        seed = derive_default_signing_seed()
        art = {
            "canonical_id": "blake3:paper:" + ("a" * 64),
            "provenance_chain": {
                "content_blake3": "a" * 64,
                "sha256": "b" * 64,
                "ed25519_pubkey": "",
                "ed25519_sig": "",
                "tx_time_utc": "2026-11-24T18:00:00Z",
                "lineage_parents": [],
                "anchors": {},
            },
        }
        sign_canonical_artifact(art, seed)
        self.assertTrue(verify_canonical_artifact_signature(art))
        art["provenance_chain"]["sha256"] = "c" * 64
        self.assertFalse(verify_canonical_artifact_signature(art))

    def test_wai1_container_conformance_and_adversarial_rejections(self) -> None:
        plaintext = b'{"hello":"wai1","items":[1,2,3]}'
        zstd_payload = zstd_encode_deterministic(plaintext)
        manifest = {
            "wai": "1.0",
            "media": "text",
            "intent": "replicate",
            "model_requirement": {"capability": "wai.text.zstd", "fallback": None},
            "conditioning": {"kind": "zstd"},
            "security": {"encryption": "none", "kid": 0},
            "target": {"uncompressed_bytes": len(plaintext)},
        }
        wire = encode_wai1_envelope(manifest, zstd_payload)
        self.assertEqual(wire[:4], b"WAI1")
        dec = decode_wai1_envelope(wire)
        self.assertEqual(dec.decoded_payload, plaintext)
        self.assertEqual(dec.envelope_bytes, len(wire))

        def raw_container(man_str: str, pay: bytes = zstd_payload) -> bytes:
            mb = man_str.encode("utf-8")
            return b"WAI1" + struct.pack("<I", len(mb)) + mb + struct.pack("<I", len(pay)) + pay

        # 1. Bad magic ("WAI2")
        with self.assertRaises(Wai1Error) as ctx:
            decode_wai1_envelope(b"WAI2" + wire[4:])
        self.assertEqual(ctx.exception.code, "invalid_magic")

        # 2. man_len > 2^27 rejected immediately before reading manifest
        huge = b"WAI1" + struct.pack("<I", MAX_MANIFEST_BYTES + 1) + b"{}"
        with self.assertRaises(Wai1Error) as ctx:
            decode_wai1_envelope(huge)
        self.assertEqual(ctx.exception.code, "manifest_too_large")

        # 3. Nesting > 127 rejected
        deep_arr = "[" * 128 + "]" * 128
        deep_man = (
            '{"wai":"1.0","media":"text","intent":"replicate",'
            '"model_requirement":{"capability":"wai.text.zstd","fallback":null},'
            f'"conditioning":{{"kind":"zstd"}},"extra":{deep_arr}}}'
        )
        with self.assertRaises(Wai1Error) as ctx:
            decode_wai1_envelope(raw_container(deep_man))
        self.assertEqual(ctx.exception.code, "manifest_too_deep")

        # 4. Insignificant whitespace rejected
        ws_man = (
            '{"wai": "1.0","media":"text","intent":"replicate",'
            '"model_requirement":{"capability":"wai.text.zstd","fallback":null},'
            '"conditioning":{"kind":"zstd"}}'
        )
        with self.assertRaises(Wai1Error) as ctx:
            decode_wai1_envelope(raw_container(ws_man))
        self.assertEqual(ctx.exception.code, "manifest_whitespace")

        # 5. Duplicate member name after unicode escape (\u0077ai == wai) rejected
        dup_man = (
            '{"wai":"1.0","\\u0077ai":"1.0","media":"text","intent":"replicate",'
            '"model_requirement":{"capability":"wai.text.zstd","fallback":null},'
            '"conditioning":{"kind":"zstd"}}'
        )
        with self.assertRaises(Wai1Error) as ctx:
            decode_wai1_envelope(raw_container(dup_man))
        self.assertEqual(ctx.exception.code, "manifest_duplicate_member")

        # 6. Strict integer check rejects -0, 1.0, and 1e0 (even though json.loads("-0") == 0 in Python!)
        for non_int in ("-0", "1.0", "1e0"):
            bad_int_man = (
                '{"wai":"1.0","media":"text","intent":"replicate",'
                '"model_requirement":{"capability":"wai.text.zstd","fallback":null},'
                f'"conditioning":{{"kind":"zstd"}},"security":{{"encryption":"none","kid":{non_int}}}}}'
            )
            with self.assertRaises(Wai1Error, msg=f"Failed to reject {non_int}") as ctx:
                decode_wai1_envelope(raw_container(bad_int_man))
            self.assertEqual(ctx.exception.code, "manifest_non_integer")

        # 7. Companion-only capability in WAI1 rejected
        comp_man = (
            '{"wai":"1.0","media":"video","intent":"replicate",'
            '"model_requirement":{"capability":"wai.meta.hdr10plus","fallback":null},'
            '"conditioning":{"kind":"hdr10plus"}}'
        )
        with self.assertRaises(Wai1Error) as ctx:
            decode_wai1_envelope(raw_container(comp_man, b"\x00"))
        self.assertEqual(ctx.exception.code, "companion_in_wai1")

        # 8. Unknown major version ("2.0") rejected; unknown minor ("1.9") accepted!
        v2_man = (
            '{"wai":"2.0","media":"text","intent":"replicate",'
            '"model_requirement":{"capability":"wai.text.zstd","fallback":null},'
            '"conditioning":{"kind":"zstd"}}'
        )
        with self.assertRaises(Wai1Error) as ctx:
            decode_wai1_envelope(raw_container(v2_man))
        self.assertEqual(ctx.exception.code, "unknown_major_version")

        v19_man = (
            '{"wai":"1.9","media":"text","intent":"replicate",'
            '"model_requirement":{"capability":"wai.text.zstd","fallback":null},'
            '"conditioning":{"kind":"zstd"}}'
        )
        dec19 = decode_wai1_envelope(raw_container(v19_man))
        self.assertEqual(dec19.decoded_payload, plaintext)

        # 9. Zstandard frame declaring content size > 2^27 rejected before allocation
        # FHD = 0xA0 (Single_Segment=1, 4-byte FCS), FCS = MAX_ZSTD_DECODED_BYTES + 10
        forged_zstd = (
            struct.pack("<I", 0xFD2FB528)
            + bytes([0xA0])
            + struct.pack("<I", MAX_ZSTD_DECODED_BYTES + 10)
            + bytes([1, 0, 0])
        )
        forged_man = (
            '{"wai":"1.0","media":"text","intent":"replicate",'
            '"model_requirement":{"capability":"wai.text.zstd","fallback":null},'
            '"conditioning":{"kind":"zstd"}}'
        )
        with self.assertRaises(Wai1Error) as ctx:
            decode_wai1_envelope(raw_container(forged_man, forged_zstd))
        self.assertEqual(ctx.exception.code, "text_decoded_too_long")


if __name__ == "__main__":
    unittest.main()
