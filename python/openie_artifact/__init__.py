# SPDX-License-Identifier: Apache-2.0
"""Canonical OpenIE Artifact Substrate, WAI1 Envelope Adapter, and Deterministic Gates."""

from .crypto import (
    CANONICAL_SIGNING_DOMAIN,
    OPENIE_SUBSTRATE_DEFAULT_SEED_DOMAIN,
    blake3_bytes,
    blake3_hex,
    canonical_jcs_bytes,
    derive_default_signing_seed,
    ed25519_keypair_from_seed,
    ed25519_sign,
    ed25519_verify,
    sha256_hex,
    sign_canonical_artifact,
    verify_canonical_artifact_signature,
)
from .gates import (
    AAC_CONCEPT_REGISTRY,
    AccessibilityGate,
    LeanProofReceipt,
    SatMiterReceipt,
    ScientificGate,
    TranslationCandidate,
    TranslationGate,
    VerificationOrchestrator,
)
from .schema_validator import SchemaValidationError, validate_openie_artifact
from .wai_adapter import (
    WAI1_MAGIC,
    Wai1DecodedEnvelope,
    Wai1Error,
    decode_wai1_envelope,
    encode_wai1_envelope,
    wrap_artifact_in_wai1,
)

__all__ = [
    "AAC_CONCEPT_REGISTRY",
    "AccessibilityGate",
    "CANONICAL_SIGNING_DOMAIN",
    "LeanProofReceipt",
    "OPENIE_SUBSTRATE_DEFAULT_SEED_DOMAIN",
    "SatMiterReceipt",
    "SchemaValidationError",
    "ScientificGate",
    "TranslationCandidate",
    "TranslationGate",
    "VerificationOrchestrator",
    "WAI1_MAGIC",
    "Wai1DecodedEnvelope",
    "Wai1Error",
    "blake3_bytes",
    "blake3_hex",
    "canonical_jcs_bytes",
    "decode_wai1_envelope",
    "derive_default_signing_seed",
    "ed25519_keypair_from_seed",
    "ed25519_sign",
    "ed25519_verify",
    "encode_wai1_envelope",
    "sha256_hex",
    "sign_canonical_artifact",
    "validate_openie_artifact",
    "verify_canonical_artifact_signature",
    "wrap_artifact_in_wai1",
]
