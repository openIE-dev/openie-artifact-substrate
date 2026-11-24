# SPDX-License-Identifier: Apache-2.0
"""Deterministic BLAKE3, RFC 8032 Ed25519, and RFC 8785 JCS canonicalization.

Zero external Python dependencies; bit-for-bit cross-verified against Rust
`blake3` 1.8 and `ed25519-dalek` 2.2.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
from typing import Any

CANONICAL_SIGNING_DOMAIN = b"openie-artifact-v1\x00"
OPENIE_SUBSTRATE_DEFAULT_SEED_DOMAIN = b"openie:substrate:catalog-ed25519-seed:v1"

# ---------------------------------------------------------------------------
# Pure-Python BLAKE3 (official specification: 1024-byte chunks, binary tree)
# ---------------------------------------------------------------------------

_BLAKE3_IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

_MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)

_CHUNK_START = 1 << 0
_CHUNK_END = 1 << 1
_PARENT = 1 << 2
_ROOT = 1 << 3
_BLOCK_LEN = 64
_CHUNK_LEN = 1024
_MASK32 = 0xFFFFFFFF


def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | ((x << (32 - n)) & _MASK32)) & _MASK32


def _g(s: list[int], a: int, b: int, c: int, d: int, mx: int, my: int) -> None:
    s[a] = (s[a] + s[b] + mx) & _MASK32
    s[d] = _rotr32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _MASK32
    s[b] = _rotr32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + my) & _MASK32
    s[d] = _rotr32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _MASK32
    s[b] = _rotr32(s[b] ^ s[c], 7)


def _round_fn(state: list[int], m: tuple[int, ...] | list[int]) -> None:
    _g(state, 0, 4, 8, 12, m[0], m[1])
    _g(state, 1, 5, 9, 13, m[2], m[3])
    _g(state, 2, 6, 10, 14, m[4], m[5])
    _g(state, 3, 7, 11, 15, m[6], m[7])
    _g(state, 0, 5, 10, 15, m[8], m[9])
    _g(state, 1, 6, 11, 12, m[10], m[11])
    _g(state, 2, 7, 8, 13, m[12], m[13])
    _g(state, 3, 4, 9, 14, m[14], m[15])


def _compress(
    cv: tuple[int, ...],
    block_words: tuple[int, ...],
    counter: int,
    block_len: int,
    flags: int,
) -> tuple[int, ...]:
    state = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        _BLAKE3_IV[0],
        _BLAKE3_IV[1],
        _BLAKE3_IV[2],
        _BLAKE3_IV[3],
        counter & _MASK32,
        (counter >> 32) & _MASK32,
        block_len & _MASK32,
        flags & _MASK32,
    ]
    m: tuple[int, ...] | list[int] = block_words
    for r in range(7):
        _round_fn(state, m)
        if r < 6:
            m = [m[i] for i in _MSG_PERMUTATION]
    return (
        state[0] ^ state[8],
        state[1] ^ state[9],
        state[2] ^ state[10],
        state[3] ^ state[11],
        state[4] ^ state[12],
        state[5] ^ state[13],
        state[6] ^ state[14],
        state[7] ^ state[15],
    )


def _words_from_block(block: bytes) -> tuple[int, ...]:
    if len(block) < _BLOCK_LEN:
        block = block + b"\x00" * (_BLOCK_LEN - len(block))
    return struct.unpack("<16I", block)


class _Blake3Output:
    __slots__ = ("input_cv", "block_words", "counter", "block_len", "flags")

    def __init__(
        self,
        input_cv: tuple[int, ...],
        block_words: tuple[int, ...],
        counter: int,
        block_len: int,
        flags: int,
    ) -> None:
        self.input_cv = input_cv
        self.block_words = block_words
        self.counter = counter
        self.block_len = block_len
        self.flags = flags

    def chaining_value(self) -> tuple[int, ...]:
        return _compress(
            self.input_cv,
            self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        )

    def root_bytes(self) -> bytes:
        words = _compress(
            self.input_cv,
            self.block_words,
            0,
            self.block_len,
            self.flags | _ROOT,
        )
        # Note: for a chunk root, counter is self.counter == 0 anyway (single chunk);
        # for a parent root, counter is 0 per BLAKE3 spec §2.1.
        if (self.flags & _PARENT) == 0 and self.counter != 0:
            words = _compress(
                self.input_cv,
                self.block_words,
                self.counter,
                self.block_len,
                self.flags | _ROOT,
            )
        return struct.pack("<8I", *words)


def _chunk_output(chunk: bytes, chunk_counter: int) -> _Blake3Output:
    cv = _BLAKE3_IV
    if len(chunk) == 0:
        return _Blake3Output(
            cv,
            (0,) * 16,
            chunk_counter,
            0,
            _CHUNK_START | _CHUNK_END,
        )
    num_blocks = (len(chunk) + _BLOCK_LEN - 1) // _BLOCK_LEN
    for b_idx in range(num_blocks - 1):
        blk = chunk[b_idx * _BLOCK_LEN : (b_idx + 1) * _BLOCK_LEN]
        flags = _CHUNK_START if b_idx == 0 else 0
        cv = _compress(cv, _words_from_block(blk), chunk_counter, _BLOCK_LEN, flags)
    last_blk = chunk[(num_blocks - 1) * _BLOCK_LEN :]
    last_flags = _CHUNK_END | (_CHUNK_START if num_blocks == 1 else 0)
    return _Blake3Output(
        cv,
        _words_from_block(last_blk),
        chunk_counter,
        len(last_blk),
        last_flags,
    )


def _parent_output(left_cv: tuple[int, ...], right_cv: tuple[int, ...]) -> _Blake3Output:
    return _Blake3Output(
        _BLAKE3_IV,
        left_cv + right_cv,
        0,
        _BLOCK_LEN,
        _PARENT,
    )


def blake3_bytes(data: bytes) -> bytes:
    """Compute 32-byte unkeyed BLAKE3 digest of `data`."""
    if len(data) <= _CHUNK_LEN:
        return _chunk_output(data, 0).root_bytes()

    num_chunks = (len(data) + _CHUNK_LEN - 1) // _CHUNK_LEN
    cv_stack: list[tuple[int, ...]] = []
    for chunk_idx in range(num_chunks - 1):
        chunk = data[chunk_idx * _CHUNK_LEN : (chunk_idx + 1) * _CHUNK_LEN]
        new_cv = _chunk_output(chunk, chunk_idx).chaining_value()
        total_chunks = chunk_idx + 1
        while (total_chunks & 1) == 0:
            left_cv = cv_stack.pop()
            new_cv = _parent_output(left_cv, new_cv).chaining_value()
            total_chunks >>= 1
        cv_stack.append(new_cv)

    last_chunk = data[(num_chunks - 1) * _CHUNK_LEN :]
    out = _chunk_output(last_chunk, num_chunks - 1)
    while cv_stack:
        left_cv = cv_stack.pop()
        out = _parent_output(left_cv, out.chaining_value())
    return out.root_bytes()


def blake3_hex(data: bytes) -> str:
    """Compute 64-character lowercase hexadecimal BLAKE3 digest."""
    return blake3_bytes(data).hex()


def sha256_hex(data: bytes) -> str:
    """Compute 64-character lowercase hexadecimal SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Pure-Python RFC 8032 Ed25519 (extended twisted Edwards coordinates)
# ---------------------------------------------------------------------------

_ED_P = (1 << 255) - 19
_ED_L = (1 << 252) + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_D2 = (2 * _ED_D) % _ED_P
_ED_SQRT_M1 = pow(2, (_ED_P - 1) // 4, _ED_P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _ED_P:
        return None
    y2 = (y * y) % _ED_P
    x2 = ((y2 - 1) * pow(_ED_D * y2 + 1, _ED_P - 2, _ED_P)) % _ED_P
    if x2 == 0:
        return 0 if sign == 0 else None
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P != 0:
        x = (x * _ED_SQRT_M1) % _ED_P
    if (x * x - x2) % _ED_P != 0:
        return None
    if (x & 1) != sign:
        x = _ED_P - x
    return x


_BY = (4 * pow(5, _ED_P - 2, _ED_P)) % _ED_P
_BX = _recover_x(_BY, 0)
assert _BX is not None
_ED_BASE = (_BX, _BY, 1, (_BX * _BY) % _ED_P)
_ED_IDENTITY = (0, 1, 1, 0)


def _point_add(
    p: tuple[int, int, int, int], q: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _ED_P
    b = ((y1 + x1) * (y2 + x2)) % _ED_P
    c = (t1 * _ED_D2 * t2) % _ED_P
    d = (z1 * 2 * z2) % _ED_P
    e = (b - a) % _ED_P
    f = (d - c) % _ED_P
    g = (d + c) % _ED_P
    h = (b + a) % _ED_P
    return ((e * f) % _ED_P, (g * h) % _ED_P, (f * g) % _ED_P, (e * h) % _ED_P)


def _point_double(p: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, _ = p
    a = (x1 * x1) % _ED_P
    b = (y1 * y1) % _ED_P
    c = (2 * z1 * z1) % _ED_P
    h = (a + b) % _ED_P
    xy = (x1 + y1) % _ED_P
    e = (h - xy * xy) % _ED_P
    g = (a - b) % _ED_P
    f = (c + g) % _ED_P
    return ((e * f) % _ED_P, (g * h) % _ED_P, (f * g) % _ED_P, (e * h) % _ED_P)


def _scalar_mul(s: int, p: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    res = _ED_IDENTITY
    addend = p
    k = s
    while k > 0:
        if k & 1:
            res = _point_add(res, addend)
        addend = _point_double(addend)
        k >>= 1
    return res


def _point_encode(p: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = p
    zi = pow(z, _ED_P - 2, _ED_P)
    xp = (x * zi) % _ED_P
    yp = (y * zi) % _ED_P
    out = bytearray(yp.to_bytes(32, "little"))
    out[31] |= (xp & 1) << 7
    return bytes(out)


def _point_decode_strict(enc: bytes) -> tuple[int, int, int, int] | None:
    if len(enc) != 32:
        return None
    y = int.from_bytes(enc, "little") & ((1 << 255) - 1)
    sign = (enc[31] >> 7) & 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    pt = (x, y, 1, (x * y) % _ED_P)
    # Enforce canonical encoding round-trip (rejects non-canonical y >= P or -0 x)
    if _point_encode(pt) != enc:
        return None
    return pt


def _point_equal(
    p: tuple[int, int, int, int], q: tuple[int, int, int, int]
) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return ((x1 * z2 - x2 * z1) % _ED_P == 0) and ((y1 * z2 - y2 * z1) % _ED_P == 0)


# Precompute 8-torsion check helper for strict verification matching ed25519-dalek verify_strict
def _is_small_order(p: tuple[int, int, int, int]) -> bool:
    p2 = _point_double(p)
    p4 = _point_double(p2)
    p8 = _point_double(p4)
    return _point_equal(p8, _ED_IDENTITY)


def derive_default_signing_seed() -> bytes:
    """Derive deterministic 32-byte OpenIE Substrate v1 public reference seed."""
    return blake3_bytes(OPENIE_SUBSTRATE_DEFAULT_SEED_DOMAIN)


def ed25519_keypair_from_seed(seed32: bytes) -> tuple[bytes, bytes]:
    """Return `(seed32, pubkey32)` per RFC 8032 §5.1.5."""
    if len(seed32) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    h = hashlib.sha512(seed32).digest()
    a_bytes = bytearray(h[:32])
    a_bytes[0] &= 248
    a_bytes[31] &= 127
    a_bytes[31] |= 64
    s = int.from_bytes(a_bytes, "little")
    pub = _point_encode(_scalar_mul(s, _ED_BASE))
    return seed32, pub


def ed25519_sign(seed32: bytes, message: bytes) -> bytes:
    """Deterministic 64-byte RFC 8032 §5.1.6 signature."""
    if len(seed32) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    h = hashlib.sha512(seed32).digest()
    a_bytes = bytearray(h[:32])
    a_bytes[0] &= 248
    a_bytes[31] &= 127
    a_bytes[31] |= 64
    s = int.from_bytes(a_bytes, "little")
    prefix = h[32:64]
    pub = _point_encode(_scalar_mul(s, _ED_BASE))

    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _ED_L
    r_enc = _point_encode(_scalar_mul(r, _ED_BASE))
    k = int.from_bytes(hashlib.sha512(r_enc + pub + message).digest(), "little") % _ED_L
    s_scalar = (r + k * s) % _ED_L
    return r_enc + s_scalar.to_bytes(32, "little")


def ed25519_verify(pubkey32: bytes, message: bytes, sig64: bytes) -> bool:
    """Strict Ed25519 verification matching `ed25519_dalek::VerifyingKey::verify_strict`."""
    if len(pubkey32) != 32 or len(sig64) != 64:
        return False
    a_pt = _point_decode_strict(pubkey32)
    r_pt = _point_decode_strict(sig64[:32])
    if a_pt is None or r_pt is None:
        return False
    if _is_small_order(a_pt) or _is_small_order(r_pt):
        return False
    s_scalar = int.from_bytes(sig64[32:], "little")
    if s_scalar >= _ED_L:
        return False
    k = (
        int.from_bytes(hashlib.sha512(sig64[:32] + pubkey32 + message).digest(), "little")
        % _ED_L
    )
    lhs = _scalar_mul(s_scalar, _ED_BASE)
    rhs = _point_add(r_pt, _scalar_mul(k, a_pt))
    return _point_equal(lhs, rhs)


# ---------------------------------------------------------------------------
# Deterministic RFC 8785 (JCS) Canonical JSON Serializer (cross-lang identical)
# ---------------------------------------------------------------------------


def _format_jcs_number(val: int | float) -> str:
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        return str(val)
    if not math.isfinite(val):
        raise ValueError("Non-finite float forbidden in canonical JSON")
    if val == 0.0:
        return "0"
    # Exact integer-valued float within IEEE-754 safe integer range -> integer digits if < 1e21
    sign = "-" if val < 0 else ""
    av = abs(val)
    # Use shortest round-trip decimal digits via repr(av), then format per ECMA-262 / RFC 8785 §3.2.2.3
    s = repr(av)
    if "e" in s or "E" in s:
        mant_str, exp_str = s.lower().split("e")
        digits = mant_str.replace(".", "")
        frac_len = len(mant_str.split(".")[1]) if "." in mant_str else 0
        exp10 = int(exp_str) - frac_len
    else:
        if "." in s:
            int_part, frac_part = s.split(".")
            if frac_part == "0":
                digits = int_part
                exp10 = 0
            else:
                raw = (int_part if int_part != "0" else "") + frac_part
                stripped = raw.lstrip("0")
                leading_zeros = len(raw) - len(stripped)
                digits = stripped.rstrip("0")
                trailing_trimmed = len(stripped) - len(digits)
                if int_part != "0":
                    exp10 = -len(frac_part) + trailing_trimmed
                else:
                    exp10 = -len(frac_part) + trailing_trimmed
        else:
            digits = s.rstrip("0") or "0"
            exp10 = len(s) - len(digits)

    # Number of significant digits k, value = int(digits) * 10**(n - k) where n = k + exp10
    k = len(digits)
    n = k + exp10
    if k <= n <= 21:
        return sign + digits + ("0" * (n - k))
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + ("0" * (-n)) + digits
    exp_val = n - 1
    exp_sign = "+" if exp_val >= 0 else "-"
    if k == 1:
        return f"{sign}{digits}e{exp_sign}{abs(exp_val)}"
    return f"{sign}{digits[0]}.{digits[1:]}e{exp_sign}{abs(exp_val)}"


def _encode_jcs_string(s: str) -> str:
    # RFC 8785 §3.2.2.2 string escaping (UTF-8 unescaped above U+001F except " and \)
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if cp == 0x08:
            out.append("\\b")
        elif cp == 0x09:
            out.append("\\t")
        elif cp == 0x0A:
            out.append("\\n")
        elif cp == 0x0C:
            out.append("\\f")
        elif cp == 0x0D:
            out.append("\\r")
        elif cp == 0x22:
            out.append('\\"')
        elif cp == 0x5C:
            out.append("\\\\")
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_sort_key(s: str) -> bytes:
    # RFC 8785 §3.2.3 sorts object keys by UTF-16BE code units
    return s.encode("utf-16-be")


def _serialize_jcs(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return _format_jcs_number(value)
    if isinstance(value, str):
        return _encode_jcs_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize_jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: _utf16_sort_key(str(kv[0])))
        return (
            "{"
            + ",".join(
                f"{_encode_jcs_string(str(k))}:{_serialize_jcs(v)}" for k, v in items
            )
            + "}"
        )
    raise TypeError(f"Unsupported type for JCS canonicalization: {type(value)!r}")


def canonical_jcs_bytes(value: Any) -> bytes:
    """Serialize `value` to canonical UTF-8 bytes per RFC 8785 (JCS)."""
    return _serialize_jcs(value).encode("utf-8")


def artifact_signing_preimage(artifact: dict[str, Any]) -> bytes:
    """Build deterministic domain-separated signing preimage for an OpenIE artifact.

    Covers all fields of `artifact` with `provenance_chain.ed25519_sig` set to `""`.
    """
    cloned = json.loads(json.dumps(artifact))
    prov = cloned.get("provenance_chain")
    if not isinstance(prov, dict):
        raise ValueError("artifact missing provenance_chain object")
    prov["ed25519_sig"] = ""
    return CANONICAL_SIGNING_DOMAIN + canonical_jcs_bytes(cloned)


def sign_canonical_artifact(artifact: dict[str, Any], seed32: bytes) -> dict[str, Any]:
    """Populate `ed25519_pubkey` and `ed25519_sig` in `artifact['provenance_chain']`."""
    _, pub = ed25519_keypair_from_seed(seed32)
    artifact["provenance_chain"]["ed25519_pubkey"] = pub.hex()
    preimage = artifact_signing_preimage(artifact)
    sig = ed25519_sign(seed32, preimage)
    artifact["provenance_chain"]["ed25519_sig"] = sig.hex()
    return artifact


def verify_canonical_artifact_signature(artifact: dict[str, Any]) -> bool:
    """Verify `provenance_chain.ed25519_sig` against `provenance_chain.ed25519_pubkey`."""
    prov = artifact.get("provenance_chain")
    if not isinstance(prov, dict):
        return False
    pub_hex = prov.get("ed25519_pubkey", "")
    sig_hex = prov.get("ed25519_sig", "")
    if (
        not isinstance(pub_hex, str)
        or not isinstance(sig_hex, str)
        or len(pub_hex) != 64
        or len(sig_hex) != 128
    ):
        return False
    try:
        pub = bytes.fromhex(pub_hex)
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        return False
    preimage = artifact_signing_preimage(artifact)
    return ed25519_verify(pub, preimage, sig)
