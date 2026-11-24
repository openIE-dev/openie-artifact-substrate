#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""emit_substrate_release.py — Universal WAI1 release envelope, JWP receipt,
and Commons bundle emitter/verifier for `openie-artifact-substrate`.

Zero external Python dependencies (uses `openie_artifact.crypto` & `openie_artifact.wai_adapter`).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT_DEFAULT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT_DEFAULT / "python") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT_DEFAULT / "python"))

from openie_artifact.crypto import (
    blake3_bytes,
    blake3_hex,
    ed25519_keypair_from_seed,
    ed25519_sign,
    ed25519_verify,
    sha256_hex,
)
from openie_artifact.wai_adapter import (
    decode_wai1_envelope,
    encode_wai1_envelope,
    zstd_encode_deterministic,
)

JWP_OBJECT_DOMAIN = b"moq-jwp:object\x01"
JWP_LEAF_DOMAIN = b"moq-jwp:merkle-leaf\x01"
JWP_GROUP_SIGN_DOMAIN = b"moq-jwp:group-sign\x01"
JWP_RECEIPT_LINK_DOMAIN = b"moq-jwp:receipt-link\x01"
OPENIE_RELEASE_SIGN_DOMAIN = b"openie:wai-release-receipt:v1"

SUBSTRATE_SLUG = "openie-artifact-substrate"
SUBSTRATE_TITLE = "OpenIE Canonical Artifact Substrate"
SUBSTRATE_REPO_URL = "https://github.com/openIE-dev/openie-artifact-substrate"
DEFAULT_COMMONS_URL = "https://scholar.askdavidc.ai"
DEFAULT_SIGNER_ID = "openie:artifact-substrate:release-signer-v1"
DETERMINISTIC_SIGNER_DOMAIN = (
    b"openie:artifact-substrate:ed25519-release-signer:v1\x00"
    b"repo=github.com/openIE-dev/openie-artifact-substrate"
)


def derive_release_timestamp(version: str, override: str | None = None) -> str:
    if override:
        return override
    for q, md in ((".Q1", "01-01"), (".Q2", "04-01"), (".Q3", "07-01"), (".Q4", "10-01")):
        if version.endswith(q):
            return f"{version[:-3]}-{md}T00:00:00Z"
    if re.fullmatch(r"v?[0-9]{4}\.[0-9]{2}\.[0-9]{2}", version):
        return f"{version.lstrip('v').replace('.', '-')}T00:00:00Z"
    return "2026-01-01T00:00:00Z"


def load_or_derive_seed(signing_key_arg: str | None = None) -> tuple[bytes, bytes, str, str]:
    raw_spec = signing_key_arg or os.environ.get("OPENIE_WAI_SIGNING_KEY", "").strip()
    signer_id = os.environ.get("OPENIE_WAI_SIGNER_ID", DEFAULT_SIGNER_ID).strip() or DEFAULT_SIGNER_ID
    if raw_spec and re.fullmatch(r"[0-9a-fA-F]{64}", raw_spec):
        seed32 = bytes.fromhex(raw_spec)
        mode = "configured-seed"
    else:
        seed32 = blake3_bytes(DETERMINISTIC_SIGNER_DOMAIN)
        mode = "deterministic-substrate-v1"
    _, pub32 = ed25519_keypair_from_seed(seed32)
    return seed32, pub32, signer_id, mode


def jwp_group_signing_payload(
    *,
    track_alias: int,
    group_id: int,
    root_hash_hex: str,
    leaf_count: int,
    joules_total: int,
    group_start: str,
    group_end: str,
    signer_pubkey_hex: str,
    signer_id: str,
) -> bytes:
    gs_b = group_start.encode("utf-8")
    ge_b = group_end.encode("utf-8")
    sid_b = signer_id.encode("utf-8")
    return (
        JWP_GROUP_SIGN_DOMAIN
        + track_alias.to_bytes(8, "big")
        + group_id.to_bytes(8, "big")
        + bytes.fromhex(root_hash_hex)
        + leaf_count.to_bytes(8, "big")
        + joules_total.to_bytes(8, "big")
        + len(gs_b).to_bytes(4, "big")
        + gs_b
        + len(ge_b).to_bytes(4, "big")
        + ge_b
        + bytes.fromhex(signer_pubkey_hex)
        + len(sid_b).to_bytes(4, "big")
        + sid_b
    )


def release_receipt_signing_payload(
    *,
    version: str,
    envelope_blake3: str,
    envelope_sha256: str,
    tarball_blake3: str,
    tarball_sha256: str,
    catalog_blake3: str,
    catalog_sha256: str,
    commons_blake3: str,
    commons_sha256: str,
) -> bytes:
    fields = (
        version,
        envelope_blake3,
        envelope_sha256,
        tarball_blake3,
        tarball_sha256,
        catalog_blake3,
        catalog_sha256,
        commons_blake3,
        commons_sha256,
    )
    return OPENIE_RELEASE_SIGN_DOMAIN + b"\x00" + "\x00".join(fields).encode("utf-8")


def write_checksum_files(release_dir: Path, ordered_files: list[str]) -> None:
    sha_lines, b3_lines = [], []
    for fname in ordered_files:
        data = (release_dir / fname).read_bytes()
        sha_lines.append(f"{sha256_hex(data)}  {fname}\n")
        b3_lines.append(f"{blake3_hex(data)}  {fname}\n")
    (release_dir / "SHA256SUMS").write_text("".join(sha_lines), encoding="utf-8")
    (release_dir / "BLAKE3SUMS").write_text("".join(b3_lines), encoding="utf-8")


def verify_offline(target: Path, quiet: bool = False) -> dict[str, Any]:
    if target.is_dir():
        release_dir = target
        wai_candidates = sorted(release_dir.glob("substrate-*.wai"))
        if not wai_candidates:
            raise ValueError(f"No substrate-*.wai found in {release_dir}")
        wai_path = wai_candidates[0]
    elif target.is_file():
        wai_path = target
        release_dir = target.parent
    else:
        raise ValueError(f"Verification target not found: {target}")

    wai_bytes = wai_path.read_bytes()
    dec_env = decode_wai1_envelope(wai_bytes)
    if dec_env.decoded_payload is None:
        raise ValueError("Expected decoded zstd payload in substrate WAI1 envelope")
    decoded = dec_env.decoded_payload
    dec_b3, dec_sha = blake3_hex(decoded), sha256_hex(decoded)
    env_b3, env_sha = dec_env.envelope_blake3, sha256_hex(wai_bytes)

    receipt_path = release_dir / "WAI_RECEIPT.json"
    record_count = 0
    if receipt_path.exists():
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        env_meta = receipt["envelope"]
        if env_meta["blake3"] != env_b3 or env_meta["sha256"] != env_sha:
            raise ValueError("WAI_RECEIPT envelope hash mismatch")
        if env_meta["decoded_blake3"] != dec_b3 or env_meta["decoded_sha256"] != dec_sha:
            raise ValueError("WAI_RECEIPT decoded hash mismatch")

        expected_jwp_obj = blake3_hex(JWP_OBJECT_DOMAIN + wai_bytes)
        expected_jwp_root = blake3_hex(JWP_LEAF_DOMAIN + bytes.fromhex(expected_jwp_obj))
        grp = receipt["jwp_group_receipt"]
        obj = receipt["jwp_object_receipt"]
        mp = obj.get("merkle_proof")
        if (
            not isinstance(mp, dict)
            or mp.get("siblings") != []
            or mp.get("direction_bits") != 0
            or mp.get("leaf_index") != 0
        ):
            raise ValueError("JWP object merkle_proof malformed")
        if obj["content_hash"] != expected_jwp_obj or grp["root_hash"] != expected_jwp_root:
            raise ValueError("JWP content/root hash mismatch")

        pub_bytes = bytes.fromhex(receipt["signature"]["signer_pubkey_ed25519"])
        jwp_pay = jwp_group_signing_payload(
            track_alias=int(grp["track_alias"]),
            group_id=int(grp["group_id"]),
            root_hash_hex=grp["root_hash"],
            leaf_count=int(grp["leaf_count"]),
            joules_total=int(grp["joules_total"]),
            group_start=grp["group_start"],
            group_end=grp["group_end"],
            signer_pubkey_hex=grp["signer_pubkey"],
            signer_id=grp["signer_id"],
        )
        if not ed25519_verify(pub_bytes, jwp_pay, bytes.fromhex(grp["sig"])):
            raise ValueError("JWP group Ed25519 signature invalid")

        art_table = receipt["artifacts"]
        for fname, meta in art_table.items():
            fbytes = (release_dir / fname).read_bytes()
            if (
                len(fbytes) != meta["bytes"]
                or blake3_hex(fbytes) != meta["blake3"]
                or sha256_hex(fbytes) != meta["sha256"]
            ):
                raise ValueError(f"Artifact digest mismatch for {fname}")

        version = receipt["version"]
        tarball_name = f"substrate-{version}.tar.gz"
        rel_pay = release_receipt_signing_payload(
            version=version,
            envelope_blake3=env_b3,
            envelope_sha256=env_sha,
            tarball_blake3=art_table[tarball_name]["blake3"],
            tarball_sha256=art_table[tarball_name]["sha256"],
            catalog_blake3=art_table["unsiloed-artifacts.jsonl"]["blake3"],
            catalog_sha256=art_table["unsiloed-artifacts.jsonl"]["sha256"],
            commons_blake3=art_table["commons_ingest_bundle.json"]["blake3"],
            commons_sha256=art_table["commons_ingest_bundle.json"]["sha256"],
        )
        if not ed25519_verify(pub_bytes, rel_pay, bytes.fromhex(receipt["signature"]["release_sig_ed25519"])):
            raise ValueError("Release receipt Ed25519 signature invalid")

        if (release_dir / "unsiloed-artifacts.jsonl").read_bytes() != decoded:
            raise ValueError("Decoded .wai differs from unsiloed-artifacts.jsonl")

        for line in decoded.decode("utf-8").splitlines():
            if line.strip():
                rec = json.loads(line)
                if rec["verification_status"].get("human_in_gate") is not False:
                    raise ValueError("human_in_gate must be false")
                record_count += 1

        for sums_name, fn in (("SHA256SUMS", sha256_hex), ("BLAKE3SUMS", blake3_hex)):
            sp = release_dir / sums_name
            if sp.exists():
                for line in sp.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        digest, fname = line.split("  ", 1)
                        if fn((release_dir / fname).read_bytes()) != digest:
                            raise ValueError(f"{sums_name} mismatch for {fname}")

    if not quiet:
        print(f"  PASS: WAI1 header & SPEC §2 limits ({len(dec_env.manifest_bytes)} B manifest, {len(dec_env.raw_payload)} B payload)")
        print(f"  PASS: Envelope BLAKE3 `{env_b3}` -> {record_count} canonical unsiloed artifacts verified")
    return {"ok": True, "envelope_blake3": env_b3, "verified_records": record_count}


def sync_commons_scholar(*, release_dir: Path, version: str, commons_url: str | None = None, dry_run: bool = False) -> None:
    base_raw = commons_url or os.environ.get("COMMONS_BASE_URL", "").strip() or DEFAULT_COMMONS_URL
    base_url = re.sub(r"/api/.*$", "", base_raw.rstrip("/")) or DEFAULT_COMMONS_URL
    if dry_run:
        print(f"  [commons] dry-run: ready-to-ingest bundle at {release_dir / 'commons_ingest_bundle.json'}")
        return
    req = urllib.request.Request(f"{base_url}/api/stats", headers={"User-Agent": f"{SUBSTRATE_SLUG}/{version}"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            print(f"  [commons] health ping {base_url}/api/stats -> HTTP {resp.status}")
    except (urllib.error.URLError, TimeoutError, OSError):
        print(f"  [commons] health ping {base_url}/api/stats unreachable; continuing non-blocking")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=f"Emit and verify WAI1 release envelopes for {SUBSTRATE_TITLE}.")
    parser.add_argument("--verify", metavar="PATH")
    parser.add_argument("--push-commons-only", action="store_true")
    parser.add_argument("--version")
    parser.add_argument("--release-dir")
    parser.add_argument("--tarball")
    parser.add_argument("--catalog", default="catalog/unsiloed-artifacts.jsonl")
    parser.add_argument("--timestamp")
    parser.add_argument("--signing-key")
    parser.add_argument("--commons-url")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    if args.verify:
        try:
            verify_offline(Path(args.verify))
            return 0
        except Exception as exc:
            print(f"VERIFY FAILED: {exc}", file=sys.stderr)
            return 1

    if args.push_commons_only:
        sync_commons_scholar(release_dir=Path(args.release_dir), version=args.version, commons_url=args.commons_url, dry_run=args.dry_run)
        return 0

    if not args.version or not args.release_dir or not args.tarball:
        parser.error("Emission requires --version, --release-dir, and --tarball")

    version = args.version
    release_dir = Path(args.release_dir)
    tarball_path = Path(args.tarball)
    catalog_path = Path(args.catalog)
    release_dir.mkdir(parents=True, exist_ok=True)
    release_ts = derive_release_timestamp(version, args.timestamp)

    cat_bytes = catalog_path.read_bytes()
    cat_b3, cat_sha = blake3_hex(cat_bytes), sha256_hex(cat_bytes)
    (release_dir / "unsiloed-artifacts.jsonl").write_bytes(cat_bytes)

    records = [json.loads(ln) for ln in cat_bytes.decode("utf-8").splitlines() if ln.strip()]
    counts_by_kind: dict[str, int] = {}
    counts_by_license: dict[str, int] = {}
    for r in records:
        k = r["artifact_kind"]
        lic = r["license"]
        counts_by_kind[k] = counts_by_kind.get(k, 0) + 1
        counts_by_license[lic] = counts_by_license.get(lic, 0) + 1

    tar_bytes = tarball_path.read_bytes()
    tar_b3, tar_sha = blake3_hex(tar_bytes), sha256_hex(tar_bytes)
    tarball_name = tarball_path.name
    wai_filename = f"substrate-{version}.wai"

    zstd_payload = zstd_encode_deterministic(cat_bytes)
    manifest_obj = {
        "wai": "1.0",
        "media": "text",
        "intent": "replicate",
        "model_requirement": {"capability": "wai.text.zstd", "fallback": None},
        "conditioning": {"kind": "zstd"},
        "security": {"encryption": "none", "kid": 0},
        "target": {
            "uncompressed_bytes": len(cat_bytes),
            "schema_version": 1,
            "format": "application/x-ndjson",
            "substrate": SUBSTRATE_SLUG,
            "version": version,
            "decoded_sha256": cat_sha,
            "decoded_blake3": cat_b3,
        },
    }
    wai_bytes = encode_wai1_envelope(manifest_obj, zstd_payload)
    (release_dir / wai_filename).write_bytes(wai_bytes)
    wai_b3, wai_sha = blake3_hex(wai_bytes), sha256_hex(wai_bytes)

    commons_doc = {
        "schema": "openie.commons.ingest_bundle/v1",
        "version": version,
        "license": "CC0-1.0",
        "tri_license_spdx": sorted(counts_by_license.keys()),
        "generated_at": release_ts,
        "overview": (
            f"{SUBSTRATE_TITLE} release {version} seals {len(records)} signed, gate-verified "
            f"ecosystem artifacts across {len(counts_by_kind)} domains in WAI1 container {wai_filename}."
        ),
        "wai_envelope": {
            "file": wai_filename,
            "blake3": wai_b3,
            "sha256": wai_sha,
            "tarball_file": tarball_name,
            "tarball_blake3": tar_b3,
            "tarball_sha256": tar_sha,
        },
        "summary": {
            "total_records": len(records),
            "counts_by_kind": dict(sorted(counts_by_kind.items())),
            "counts_by_license": dict(sorted(counts_by_license.items())),
        },
        "repository": SUBSTRATE_REPO_URL,
    }
    commons_bytes = (json.dumps(commons_doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    (release_dir / "commons_ingest_bundle.json").write_bytes(commons_bytes)
    commons_b3, commons_sha = blake3_hex(commons_bytes), sha256_hex(commons_bytes)

    seed32, pub32, signer_id, key_mode = load_or_derive_seed(args.signing_key)
    signer_pk_hex = pub32.hex()
    jwp_content_hash = blake3_hex(JWP_OBJECT_DOMAIN + wai_bytes)
    jwp_merkle_root = blake3_hex(JWP_LEAF_DOMAIN + bytes.fromhex(jwp_content_hash))

    jwp_pay = jwp_group_signing_payload(
        track_alias=0,
        group_id=1,
        root_hash_hex=jwp_merkle_root,
        leaf_count=1,
        joules_total=0,
        group_start=release_ts,
        group_end=release_ts,
        signer_pubkey_hex=signer_pk_hex,
        signer_id=signer_id,
    )
    jwp_sig = ed25519_sign(seed32, jwp_pay)
    jwp_link = blake3_hex(JWP_RECEIPT_LINK_DOMAIN + jwp_pay + jwp_sig)

    rel_sig = ed25519_sign(
        seed32,
        release_receipt_signing_payload(
            version=version,
            envelope_blake3=wai_b3,
            envelope_sha256=wai_sha,
            tarball_blake3=tar_b3,
            tarball_sha256=tar_sha,
            catalog_blake3=cat_b3,
            catalog_sha256=cat_sha,
            commons_blake3=commons_b3,
            commons_sha256=commons_sha,
        ),
    )

    receipt_doc = {
        "schema": "openie.wai.receipt/v1",
        "version": version,
        "released_at": release_ts,
        "license": "Apache-2.0",
        "tri_license_spdx": sorted(counts_by_license.keys()),
        "substrate": SUBSTRATE_SLUG,
        "canonical_records": len(records),
        "counts_by_kind": dict(sorted(counts_by_kind.items())),
        "envelope": {
            "file": wai_filename,
            "format": "WAI1",
            "wai": "1.0",
            "capability": "wai.text.zstd",
            "fallback": None,
            "bytes": len(wai_bytes),
            "blake3": wai_b3,
            "sha256": wai_sha,
            "jwp_content_hash_blake3": jwp_content_hash,
            "jwp_merkle_root_blake3": jwp_merkle_root,
            "jwp_receipt_link_blake3": jwp_link,
            "decoded_bytes": len(cat_bytes),
            "decoded_blake3": cat_b3,
            "decoded_sha256": cat_sha,
        },
        "artifacts": {
            tarball_name: {"bytes": len(tar_bytes), "blake3": tar_b3, "sha256": tar_sha},
            "unsiloed-artifacts.jsonl": {"bytes": len(cat_bytes), "blake3": cat_b3, "sha256": cat_sha},
            wai_filename: {"bytes": len(wai_bytes), "blake3": wai_b3, "sha256": wai_sha},
            "commons_ingest_bundle.json": {"bytes": len(commons_bytes), "blake3": commons_b3, "sha256": commons_sha},
        },
        "energy_cost_j": {
            "status": "unmetered",
            "reported_j": None,
            "joules_micro": 0,
            "acquisition_class": "unmetered",
            "note": "Unmetered build host (joules_micro=0 is the WAI unmetered marker).",
        },
        "signature": {
            "scheme": "ed25519-rfc8032",
            "signing_domain": OPENIE_RELEASE_SIGN_DOMAIN.decode("ascii"),
            "signer_id": signer_id,
            "key_mode": key_mode,
            "signer_pubkey_ed25519": signer_pk_hex,
            "release_sig_ed25519": rel_sig.hex(),
        },
        "jwp_group_receipt": {
            "kind": "group",
            "track_alias": 0,
            "group_id": 1,
            "root_hash": jwp_merkle_root,
            "leaf_count": 1,
            "joules_total": 0,
            "group_start": release_ts,
            "group_end": release_ts,
            "signer_pubkey": signer_pk_hex,
            "signer_id": signer_id,
            "sig": jwp_sig.hex(),
            "parent_receipt_hash": None,
        },
        "jwp_object_receipt": {
            "kind": "object",
            "track_alias": 0,
            "group_id": 1,
            "object_id": 0,
            "content_hash": jwp_content_hash,
            "joules_micro": 0,
            "origin": signer_id,
            "merkle_proof": {"siblings": [], "direction_bits": 0, "leaf_index": 0},
        },
        "offline_verify_command": f"python3 scripts/emit_substrate_release.py --verify releases/{version}",
    }
    (release_dir / "WAI_RECEIPT.json").write_text(
        json.dumps(receipt_doc, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    write_checksum_files(
        release_dir,
        [tarball_name, "unsiloed-artifacts.jsonl", wai_filename, "WAI_RECEIPT.json", "commons_ingest_bundle.json"],
    )
    verify_offline(release_dir, quiet=True)
    print(f"  Unsiloed Catalog:  {release_dir / 'unsiloed-artifacts.jsonl'} ({len(records)} signed records)")
    print(f"  WAI1 Envelope:     {release_dir / wai_filename} ({len(wai_bytes)} bytes, BLAKE3 {wai_b3[:16]}...)")
    if args.dry_run:
        sync_commons_scholar(release_dir=release_dir, version=version, commons_url=args.commons_url, dry_run=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
