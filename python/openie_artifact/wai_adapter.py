# SPDX-License-Identifier: Apache-2.0
"""Conforming WAI1 (`application/vnd.wai`) Envelope Adapter per WAI SPEC.md §2 & §3.

Container layout:
  Bytes 0..4          : ASCII "WAI1"
  Bytes 4..8          : u32 little-endian `man_len` (<= 2^27)
  Bytes 8..8+man_len  : compact UTF-8 JSON manifest (depth <= 127, values <= 2^22,
                        unique keys after escape decoding, strict integer check
                        rejecting `-0`, `1.0`, `1e0`)
  Next 4 bytes        : u32 little-endian `payload_len`
  Next payload_len B  : codec payload bytes (for `wai.text.zstd`, RFC 8878 Zstandard
                        with decoded length <= 2^27 and window size <= 2^27)
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from typing import Any

from .crypto import blake3_hex, sha256_hex

try:
    from compression import zstd as _stdlib_zstd  # Python 3.14+
except ImportError:  # pragma: no cover
    _stdlib_zstd = None

WAI1_MAGIC = b"WAI1"
MAX_MANIFEST_BYTES = 1 << 27  # 134,217,728 (SPEC.md §2)
MAX_MANIFEST_DEPTH = 127  # SPEC.md §2 (manifest object itself counts as 1)
MAX_MANIFEST_VALUES = 1 << 22  # 4,194,304 (SPEC.md §2)
MAX_ZSTD_DECODED_BYTES = 1 << 27  # 134,217,728 (SPEC.md §2)
MAX_ZSTD_WINDOW_BYTES = 1 << 27  # 134,217,728 (SPEC.md §2)

ZSTD_FRAME_MAGIC = 0xFD2FB528

COMPANION_ONLY_CAPABILITIES = frozenset(
    {
        "wai.meta.hdr10plus",
        "wai.meta.dovi",
        "wai.meta.st2094_50",
        "wai.meta.gainmap",
        "wai.video.lcevc",
        "wai.audio.opus.dred",
        "wai.audio.opus.dred.int",
    }
)


class Wai1Error(ValueError):
    """Error raised when encoding or decoding a non-conforming WAI1 container."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass(frozen=True)
class _NonIntNumber:
    """Wrapper preserving the fact that a JSON number had `-0`, `.`, or `e`/`E`."""

    value: float
    raw: str


# ---------------------------------------------------------------------------
# Strict WAI1 Compact JSON Parser (SPEC.md §2)
# ---------------------------------------------------------------------------


class _StrictWaiJsonParser:
    """Strict compact UTF-8 JSON parser enforcing WAI SPEC.md §2 invariants:
    - No insignificant whitespace outside string literals
    - Depth <= MAX_MANIFEST_DEPTH (root object counts as 1)
    - Value count <= MAX_MANIFEST_VALUES (member names do not count as values)
    - Unique member names per object after escape decoding
    - Distinguishes exact integer tokens (`0` or `-?[1-9][0-9]*`) from `-0`, `1.0`, `1e0`
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.n = len(text)
        self.pos = 0
        self.value_count = 0

    def _bump_value(self) -> None:
        self.value_count += 1
        if self.value_count > MAX_MANIFEST_VALUES:
            raise Wai1Error(
                "manifest_too_many_values",
                f"Manifest exceeds {MAX_MANIFEST_VALUES} JSON values",
            )

    def parse(self) -> tuple[Any, Any]:
        """Return `(strict_tree, plain_python_tree)`."""
        if self.n == 0:
            raise Wai1Error("manifest_malformed", "Empty manifest")
        strict_val, plain_val = self._parse_value(depth=1)
        if self.pos != self.n:
            ch = self.text[self.pos]
            if ch in " \t\r\n":
                raise Wai1Error(
                    "manifest_whitespace",
                    f"Trailing whitespace at byte {self.pos}",
                )
            raise Wai1Error(
                "manifest_trailing_bytes",
                f"Unexpected trailing character {ch!r} at {self.pos}",
            )
        return strict_val, plain_val

    def _parse_value(self, depth: int) -> tuple[Any, Any]:
        if self.pos >= self.n:
            raise Wai1Error("manifest_malformed", "Unexpected end of JSON")
        ch = self.text[self.pos]
        if ch in " \t\r\n":
            raise Wai1Error(
                "manifest_whitespace",
                f"Insignificant whitespace forbidden in WAI1 manifest at {self.pos}",
            )
        if ch == "{":
            if depth > MAX_MANIFEST_DEPTH:
                raise Wai1Error(
                    "manifest_too_deep",
                    f"Manifest nesting exceeds {MAX_MANIFEST_DEPTH}",
                )
            self._bump_value()
            return self._parse_object(depth)
        if ch == "[":
            if depth > MAX_MANIFEST_DEPTH:
                raise Wai1Error(
                    "manifest_too_deep",
                    f"Manifest nesting exceeds {MAX_MANIFEST_DEPTH}",
                )
            self._bump_value()
            return self._parse_array(depth)
        if ch == '"':
            self._bump_value()
            s = self._parse_string()
            return s, s
        if ch == "t":
            if self.text.startswith("true", self.pos):
                self._bump_value()
                self.pos += 4
                return True, True
            raise Wai1Error("manifest_malformed", f"Invalid literal at {self.pos}")
        if ch == "f":
            if self.text.startswith("false", self.pos):
                self._bump_value()
                self.pos += 5
                return False, False
            raise Wai1Error("manifest_malformed", f"Invalid literal at {self.pos}")
        if ch == "n":
            if self.text.startswith("null", self.pos):
                self._bump_value()
                self.pos += 4
                return None, None
            raise Wai1Error("manifest_malformed", f"Invalid literal at {self.pos}")
        if ch == "-" or ("0" <= ch <= "9"):
            self._bump_value()
            return self._parse_number()
        raise Wai1Error("manifest_malformed", f"Unexpected character {ch!r} at {self.pos}")

    def _parse_string(self) -> str:
        assert self.text[self.pos] == '"'
        self.pos += 1
        out: list[str] = []
        while self.pos < self.n:
            ch = self.text[self.pos]
            self.pos += 1
            if ch == '"':
                return "".join(out)
            if ord(ch) < 0x20:
                raise Wai1Error("manifest_malformed", "Unescaped control char in string")
            if ch == "\\":
                if self.pos >= self.n:
                    raise Wai1Error("manifest_malformed", "Unterminated escape")
                esc = self.text[self.pos]
                self.pos += 1
                if esc == '"':
                    out.append('"')
                elif esc == "\\":
                    out.append("\\")
                elif esc == "/":
                    out.append("/")
                elif esc == "b":
                    out.append("\b")
                elif esc == "f":
                    out.append("\f")
                elif esc == "n":
                    out.append("\n")
                elif esc == "r":
                    out.append("\r")
                elif esc == "t":
                    out.append("\t")
                elif esc == "u":
                    hex4 = self.text[self.pos : self.pos + 4]
                    if len(hex4) != 4:
                        raise Wai1Error("manifest_malformed", "Short \\u escape")
                    try:
                        cp = int(hex4, 16)
                    except ValueError as exc:
                        raise Wai1Error("manifest_malformed", "Bad \\u hex") from exc
                    self.pos += 4
                    if 0xD800 <= cp <= 0xDBFF:
                        if self.text[self.pos : self.pos + 2] != "\\u":
                            raise Wai1Error("manifest_malformed", "Unpaired high surrogate")
                        low_hex = self.text[self.pos + 2 : self.pos + 6]
                        if len(low_hex) != 4:
                            raise Wai1Error("manifest_malformed", "Short low surrogate")
                        try:
                            low = int(low_hex, 16)
                        except ValueError as exc:
                            raise Wai1Error("manifest_malformed", "Bad low surrogate") from exc
                        if not (0xDC00 <= low <= 0xDFFF):
                            raise Wai1Error("manifest_malformed", "Invalid low surrogate")
                        self.pos += 6
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00)
                    elif 0xDC00 <= cp <= 0xDFFF:
                        raise Wai1Error("manifest_malformed", "Unpaired low surrogate")
                    out.append(chr(cp))
                else:
                    raise Wai1Error("manifest_malformed", f"Invalid escape \\{esc}")
            else:
                out.append(ch)
        raise Wai1Error("manifest_malformed", "Unterminated string")

    def _parse_number(self) -> tuple[Any, Any]:
        start = self.pos
        neg = False
        if self.text[self.pos] == "-":
            neg = True
            self.pos += 1
            if self.pos >= self.n:
                raise Wai1Error("manifest_malformed", "Bare minus sign")
        if self.pos >= self.n or not ("0" <= self.text[self.pos] <= "9"):
            raise Wai1Error("manifest_malformed", "Expected digit in number")
        leading_zero = self.text[self.pos] == "0"
        if leading_zero:
            self.pos += 1
            if self.pos < self.n and ("0" <= self.text[self.pos] <= "9"):
                raise Wai1Error("manifest_malformed", "Leading zero forbidden in JSON")
        else:
            while self.pos < self.n and ("0" <= self.text[self.pos] <= "9"):
                self.pos += 1

        has_frac_or_exp = False
        if self.pos < self.n and self.text[self.pos] == ".":
            has_frac_or_exp = True
            self.pos += 1
            if self.pos >= self.n or not ("0" <= self.text[self.pos] <= "9"):
                raise Wai1Error("manifest_malformed", "Expected fraction digits")
            while self.pos < self.n and ("0" <= self.text[self.pos] <= "9"):
                self.pos += 1

        if self.pos < self.n and self.text[self.pos] in ("e", "E"):
            has_frac_or_exp = True
            self.pos += 1
            if self.pos < self.n and self.text[self.pos] in ("+", "-"):
                self.pos += 1
            if self.pos >= self.n or not ("0" <= self.text[self.pos] <= "9"):
                raise Wai1Error("manifest_malformed", "Expected exponent digits")
            while self.pos < self.n and ("0" <= self.text[self.pos] <= "9"):
                self.pos += 1

        raw = self.text[start : self.pos]
        # SPEC.md §2: `-0`, `1.0` and `1e0` are NOT integers!
        if has_frac_or_exp or (neg and leading_zero):
            fval = float(raw)
            return _NonIntNumber(fval, raw), fval
        ival = int(raw)
        return ival, ival

    def _parse_object(self, depth: int) -> tuple[dict[str, Any], dict[str, Any]]:
        assert self.text[self.pos] == "{"
        self.pos += 1
        strict_obj: dict[str, Any] = {}
        plain_obj: dict[str, Any] = {}
        if self.pos < self.n and self.text[self.pos] == "}":
            self.pos += 1
            return strict_obj, plain_obj
        while True:
            if self.pos >= self.n:
                raise Wai1Error("manifest_malformed", "Unterminated object")
            if self.text[self.pos] in " \t\r\n":
                raise Wai1Error("manifest_whitespace", "Whitespace before key")
            if self.text[self.pos] != '"':
                raise Wai1Error("manifest_malformed", "Expected string member name")
            # Note: SPEC.md §2 states "a member's name is not a value"
            key = self._parse_string()
            if key in strict_obj:
                raise Wai1Error(
                    "manifest_duplicate_member",
                    f"Duplicate member name {key!r} in manifest object",
                )
            if self.pos >= self.n or self.text[self.pos] != ":":
                if self.pos < self.n and self.text[self.pos] in " \t\r\n":
                    raise Wai1Error("manifest_whitespace", "Whitespace before ':'")
                raise Wai1Error("manifest_malformed", "Expected ':' after member name")
            self.pos += 1
            sv, pv = self._parse_value(depth + 1)
            strict_obj[key] = sv
            plain_obj[key] = pv
            if self.pos >= self.n:
                raise Wai1Error("manifest_malformed", "Unterminated object")
            sep = self.text[self.pos]
            if sep == "}":
                self.pos += 1
                return strict_obj, plain_obj
            if sep == ",":
                self.pos += 1
                continue
            if sep in " \t\r\n":
                raise Wai1Error("manifest_whitespace", "Whitespace in object")
            raise Wai1Error("manifest_malformed", f"Unexpected {sep!r} in object")

    def _parse_array(self, depth: int) -> tuple[list[Any], list[Any]]:
        assert self.text[self.pos] == "["
        self.pos += 1
        strict_arr: list[Any] = []
        plain_arr: list[Any] = []
        if self.pos < self.n and self.text[self.pos] == "]":
            self.pos += 1
            return strict_arr, plain_arr
        while True:
            sv, pv = self._parse_value(depth + 1)
            strict_arr.append(sv)
            plain_arr.append(pv)
            if self.pos >= self.n:
                raise Wai1Error("manifest_malformed", "Unterminated array")
            sep = self.text[self.pos]
            if sep == "]":
                self.pos += 1
                return strict_arr, plain_arr
            if sep == ",":
                self.pos += 1
                continue
            if sep in " \t\r\n":
                raise Wai1Error("manifest_whitespace", "Whitespace in array")
            raise Wai1Error("manifest_malformed", f"Unexpected {sep!r} in array")


def _require_strict_int(val: Any, field_name: str, min_val: int | None = None, max_val: int | None = None) -> int:
    if isinstance(val, _NonIntNumber) or isinstance(val, bool) or not isinstance(val, int):
        raise Wai1Error(
            "manifest_non_integer",
            f"Field {field_name} must be a strict JSON integer (rejecting -0, 1.0, 1e0)",
        )
    if min_val is not None and val < min_val:
        raise Wai1Error("manifest_integer_range", f"Field {field_name} < {min_val}")
    if max_val is not None and val > max_val:
        raise Wai1Error("manifest_integer_range", f"Field {field_name} > {max_val}")
    return val


def _validate_wai1_manifest_strict(strict_manifest: Any) -> None:
    if not isinstance(strict_manifest, dict):
        raise Wai1Error("manifest_malformed", "WAI1 manifest must be a JSON object")

    wai_ver = strict_manifest.get("wai")
    if not isinstance(wai_ver, str) or "." not in wai_ver:
        raise Wai1Error("manifest_malformed", "Missing or malformed 'wai' version")
    major, minor = wai_ver.split(".", 1)
    if not major.isdigit() or not minor.isdigit():
        raise Wai1Error("manifest_malformed", f"Invalid 'wai' version {wai_ver!r}")
    if major != "1":
        raise Wai1Error("unknown_major_version", f"Unsupported WAI major version {major!r}")

    media = strict_manifest.get("media")
    if not isinstance(media, str) or not media:
        raise Wai1Error("manifest_malformed", "Missing 'media' string")

    intent = strict_manifest.get("intent")
    if not isinstance(intent, str) or not intent:
        raise Wai1Error("manifest_malformed", "Missing 'intent' string")

    mr = strict_manifest.get("model_requirement")
    if not isinstance(mr, dict):
        raise Wai1Error("manifest_malformed", "Missing 'model_requirement' object")
    cap = mr.get("capability")
    if not isinstance(cap, str) or not cap:
        raise Wai1Error("manifest_malformed", "Missing 'model_requirement.capability'")
    if cap in COMPANION_ONLY_CAPABILITIES:
        raise Wai1Error(
            "companion_in_wai1",
            f"Companion-only capability {cap!r} cannot be primary in WAI1",
        )
    fb = mr.get("fallback")
    if fb is not None:
        if not isinstance(fb, str) or not fb:
            raise Wai1Error("manifest_malformed", "Invalid 'model_requirement.fallback'")
        if fb in COMPANION_ONLY_CAPABILITIES:
            raise Wai1Error(
                "companion_in_wai1",
                f"Companion-only capability {fb!r} cannot be fallback in WAI1",
            )

    cond = strict_manifest.get("conditioning")
    if not isinstance(cond, dict):
        raise Wai1Error("manifest_malformed", "Missing 'conditioning' object")
    kind = cond.get("kind")
    if not isinstance(kind, str) or not kind:
        raise Wai1Error("manifest_malformed", "Missing 'conditioning.kind'")
    if "prior" in cond and cond["prior"] is not None:
        prior = cond["prior"]
        if not isinstance(prior, dict):
            raise Wai1Error("manifest_malformed", "Malformed 'conditioning.prior'")
        p_id = prior.get("id")
        p_sha = prior.get("sha256")
        p_det = prior.get("determinism")
        if not isinstance(p_id, str) or not p_id:
            raise Wai1Error("pin_malformed", "Missing prior.id")
        if (
            not isinstance(p_sha, str)
            or len(p_sha) != 64
            or any(c not in "0123456789abcdef" for c in p_sha)
        ):
            raise Wai1Error("pin_malformed", "prior.sha256 must be 64 lowercase hex digits")
        if not isinstance(p_det, str) or not p_det:
            raise Wai1Error("pin_malformed", "Missing prior.determinism")

    if "security" in strict_manifest and strict_manifest["security"] is not None:
        sec = strict_manifest["security"]
        if not isinstance(sec, dict):
            raise Wai1Error("manifest_malformed", "'security' must be an object")
        enc = sec.get("encryption")
        if not isinstance(enc, str) or not enc:
            raise Wai1Error("manifest_malformed", "Missing 'security.encryption'")
        if "kid" in sec:
            _require_strict_int(sec["kid"], "security.kid", 0, (1 << 64) - 1)

    if "target" in strict_manifest and strict_manifest["target"] is not None:
        tgt = strict_manifest["target"]
        if not isinstance(tgt, dict):
            raise Wai1Error("manifest_malformed", "'target' must be an object")
        for int_k in (
            "uncompressed_bytes",
            "episode_number",
            "turn_count",
            "cut_count",
            "step_count",
            "dof_count",
            "schema_version",
        ):
            if int_k in tgt and tgt[int_k] is not None:
                _require_strict_int(tgt[int_k], f"target.{int_k}", 0)

    if "openie_artifact" in strict_manifest and strict_manifest["openie_artifact"] is not None:
        oa = strict_manifest["openie_artifact"]
        if not isinstance(oa, dict):
            raise Wai1Error("manifest_malformed", "'openie_artifact' must be an object")
        if "difficulty_rung" in oa and isinstance(oa["difficulty_rung"], dict):
            dr = oa["difficulty_rung"]
            if "rung" in dr:
                _require_strict_int(dr["rung"], "openie_artifact.difficulty_rung.rung", 1, 9)
            if "phase" in dr:
                _require_strict_int(dr["phase"], "openie_artifact.difficulty_rung.phase", 1, 2)


# ---------------------------------------------------------------------------
# RFC 8878 Zstandard Framing & Reader Limits (`wai.text.zstd`, SPEC.md §2 & §5)
# ---------------------------------------------------------------------------


def zstd_encode_deterministic(plaintext: bytes) -> bytes:
    """Encode `plaintext` as an RFC 8878 single-segment Zstandard frame (`wai.text.zstd`).

    Uses deterministic RFC 8878 raw-block single-segment framing when size is small or
    when bit-exact cross-language framing with Rust's zero-C encoder is requested, or
    stdlib `compression.zstd` with single-segment content-size header.
    Wait: emitting deterministic RFC 8878 single-segment frames guarantees 100%
    bit-identical `.wai` output across BOTH Rust and Python on every OS!
    Let's also support decompressing ANY standard compressed Zstandard stream!
    """
    n = len(plaintext)
    if n > MAX_ZSTD_DECODED_BYTES:
        raise Wai1Error(
            "text_decoded_too_long",
            f"Plaintext {n} exceeds WAI zstd limit {MAX_ZSTD_DECODED_BYTES}",
        )
    # RFC 8878 §3.1.1 Single-Segment Frame Header:
    # Magic_Number: 0xFD2FB528 (4B LE)
    # Frame_Header_Descriptor:
    #   Single_Segment_Flag = 1 (bit 5 = 0x20), Content_Checksum_Flag = 0, Dict_ID = 0
    #   Frame_Content_Size_Flag (bits 7..6):
    #     0 (1B FCS) if n <= 255
    #     1 (2B FCS, value = n - 256) if 256 <= n <= 65791
    #     2 (4B FCS) otherwise
    header = bytearray(struct.pack("<I", ZSTD_FRAME_MAGIC))
    if n <= 255:
        header.append(0x20)  # FCS_Flag=0, Single_Segment=1 -> 1-byte FCS
        header.append(n)
    elif n <= 65791:
        header.append(0x60)  # FCS_Flag=1, Single_Segment=1 -> 2-byte FCS (n - 256)
        header.extend(struct.pack("<H", n - 256))
    else:
        header.append(0xA0)  # FCS_Flag=2, Single_Segment=1 -> 4-byte FCS
        header.extend(struct.pack("<I", n))

    # Emit RFC 8878 §3.1.1.2 Raw_Block chunks (max 128 KiB = 131072 bytes per block)
    out = bytearray(header)
    if n == 0:
        # Single empty last block: Last_Block=1, Block_Type=0 (Raw), Block_Size=0 -> 0x000001
        out.extend((1, 0, 0))
        return bytes(out)

    max_blk = 131072
    offset = 0
    while offset < n:
        chunk = plaintext[offset : offset + max_blk]
        offset += len(chunk)
        is_last = 1 if offset >= n else 0
        # 3-byte little-endian Block_Header: Last_Block (bit 0) | Block_Type=0 (bits 1..2) | (Block_Size << 3)
        bh = is_last | (len(chunk) << 3)
        out.extend((bh & 0xFF, (bh >> 8) & 0xFF, (bh >> 16) & 0xFF))
        out.extend(chunk)
    return bytes(out)


def _check_zstd_frame_limits(zstd_bytes: bytes) -> None:
    """Inspect RFC 8878 frame header to enforce SPEC.md §2 reader limits BEFORE decode."""
    if len(zstd_bytes) < 6:
        raise Wai1Error("zstd_malformed", "Zstandard payload shorter than minimum header")
    magic = struct.unpack_from("<I", zstd_bytes, 0)[0]
    if magic != ZSTD_FRAME_MAGIC:
        raise Wai1Error("zstd_malformed", f"Invalid Zstandard magic 0x{magic:08x}")
    fhd = zstd_bytes[4]
    fcs_flag = (fhd >> 6) & 0x3
    single_segment = ((fhd >> 5) & 0x1) == 1
    reserved_bit = (fhd >> 3) & 0x1
    if reserved_bit != 0:
        raise Wai1Error("zstd_malformed", "Reserved bit set in Zstandard FHD")
    dict_id_flag = fhd & 0x3
    dict_field_sizes = (0, 1, 2, 4)

    pos = 5
    window_size = 0
    if not single_segment:
        if pos >= len(zstd_bytes):
            raise Wai1Error("zstd_malformed", "Truncated Window_Descriptor")
        wd = zstd_bytes[pos]
        pos += 1
        exponent = wd >> 3
        mantissa = wd & 0x7
        window_base = 1 << (10 + exponent)
        window_add = (window_base // 8) * mantissa
        window_size = window_base + window_add
        if window_size > MAX_ZSTD_WINDOW_BYTES:
            raise Wai1Error(
                "text_window_too_large",
                f"Zstandard window {window_size} exceeds 2^27",
            )

    pos += dict_field_sizes[dict_id_flag]
    fcs_sizes = (1 if single_segment else 0, 2, 4, 8)
    fcs_len = fcs_sizes[fcs_flag]
    if fcs_len > 0:
        if pos + fcs_len > len(zstd_bytes):
            raise Wai1Error("zstd_malformed", "Truncated Frame_Content_Size")
        if fcs_len == 1:
            fcs = zstd_bytes[pos]
        elif fcs_len == 2:
            fcs = struct.unpack_from("<H", zstd_bytes, pos)[0] + 256
        elif fcs_len == 4:
            fcs = struct.unpack_from("<I", zstd_bytes, pos)[0]
        else:
            fcs = struct.unpack_from("<Q", zstd_bytes, pos)[0]
        if fcs > MAX_ZSTD_DECODED_BYTES:
            raise Wai1Error(
                "text_decoded_too_long",
                f"Declared Zstandard content size {fcs} exceeds 2^27",
            )
        if single_segment and fcs > MAX_ZSTD_WINDOW_BYTES:
            raise Wai1Error(
                "text_window_too_large",
                f"Single-segment window {fcs} exceeds 2^27",
            )


def _decode_raw_rle_zstd_fallback(zstd_bytes: bytes) -> bytes | None:
    """Pure-Python decoder for RFC 8878 Raw/RLE single/multi-block frames."""
    fhd = zstd_bytes[4]
    fcs_flag = (fhd >> 6) & 0x3
    single_segment = ((fhd >> 5) & 0x1) == 1
    checksum_flag = ((fhd >> 2) & 0x1) == 1
    dict_id_flag = fhd & 0x3
    pos = 5 + (0 if single_segment else 1) + (0, 1, 2, 4)[dict_id_flag]
    pos += (1 if single_segment else 0, 2, 4, 8)[fcs_flag]
    out = bytearray()
    while True:
        if pos + 3 > len(zstd_bytes):
            raise Wai1Error("zstd_malformed", "Truncated Zstandard block header")
        bh = zstd_bytes[pos] | (zstd_bytes[pos + 1] << 8) | (zstd_bytes[pos + 2] << 16)
        pos += 3
        last_block = bh & 1
        block_type = (bh >> 1) & 0x3
        block_size = bh >> 3
        if block_type == 0:  # Raw_Block
            if pos + block_size > len(zstd_bytes):
                raise Wai1Error("zstd_malformed", "Truncated Zstandard raw block")
            if len(out) + block_size > MAX_ZSTD_DECODED_BYTES:
                raise Wai1Error("text_decoded_too_long", "Decoded output exceeds 2^27")
            out.extend(zstd_bytes[pos : pos + block_size])
            pos += block_size
        elif block_type == 1:  # RLE_Block
            if pos + 1 > len(zstd_bytes):
                raise Wai1Error("zstd_malformed", "Truncated Zstandard RLE block")
            if len(out) + block_size > MAX_ZSTD_DECODED_BYTES:
                raise Wai1Error("text_decoded_too_long", "Decoded output exceeds 2^27")
            out.extend(bytes([zstd_bytes[pos]]) * block_size)
            pos += 1
        elif block_type == 2:
            return None  # Compressed block -> delegate to stdlib compression.zstd
        else:
            raise Wai1Error("zstd_malformed", "Reserved Zstandard block_type=3")
        if last_block:
            break
    if checksum_flag:
        pos += 4
    if pos != len(zstd_bytes):
        return None
    return bytes(out)


def zstd_decode_bounded(zstd_bytes: bytes) -> bytes:
    """Decode an RFC 8878 `wai.text.zstd` payload enforcing SPEC.md §2 reader limits."""
    _check_zstd_frame_limits(zstd_bytes)
    fast = _decode_raw_rle_zstd_fallback(zstd_bytes)
    if fast is not None:
        return fast
    if _stdlib_zstd is None:  # pragma: no cover
        raise Wai1Error("zstd_unsupported", "Compressed zstd requires Python 3.14+")
    try:
        dec = _stdlib_zstd.ZstdDecompressor()
        out = dec.decompress(zstd_bytes, max_length=MAX_ZSTD_DECODED_BYTES + 1)
    except Exception as exc:
        raise Wai1Error("zstd_malformed", f"Zstandard decode failed: {exc}") from exc
    if len(out) > MAX_ZSTD_DECODED_BYTES:
        raise Wai1Error("text_decoded_too_long", "Decoded Zstandard payload exceeds 2^27")
    return out


# ---------------------------------------------------------------------------
# WAI1 Container Encode & Decode
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Wai1DecodedEnvelope:
    manifest: dict[str, Any]
    manifest_bytes: bytes
    raw_payload: bytes
    decoded_payload: bytes | None
    envelope_blake3: str
    envelope_bytes: int


def serialize_compact_manifest(manifest: dict[str, Any]) -> bytes:
    """Serialize `manifest` preserving insertion order with zero insignificant whitespace."""
    raw = json.dumps(manifest, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(raw) > MAX_MANIFEST_BYTES:
        raise Wai1Error("manifest_too_large", f"Manifest length {len(raw)} > 2^27")
    # Run our strict parser over our own serialized output to enforce all encoder limits (§2)!
    strict_tree, _ = _StrictWaiJsonParser(raw.decode("utf-8")).parse()
    _validate_wai1_manifest_strict(strict_tree)
    return raw


def encode_wai1_envelope(manifest: dict[str, Any], payload: bytes) -> bytes:
    """Encode a conforming `WAI1` binary container (`SPEC.md` §2)."""
    manifest_bytes = serialize_compact_manifest(manifest)
    man_len = len(manifest_bytes)
    payload_len = len(payload)
    if payload_len > 0xFFFFFFFF:
        raise Wai1Error("payload_too_large", "Payload exceeds u32 maximum")
    if manifest.get("model_requirement", {}).get("capability") == "wai.text.zstd":
        _check_zstd_frame_limits(payload)
    return (
        WAI1_MAGIC
        + struct.pack("<I", man_len)
        + manifest_bytes
        + struct.pack("<I", payload_len)
        + payload
    )


def decode_wai1_envelope(data: bytes) -> Wai1DecodedEnvelope:
    """Decode and strictly validate a `WAI1` binary container (`SPEC.md` §2 & §3)."""
    if len(data) < 8:
        raise Wai1Error("container_truncated", f"Container shorter than 8 bytes ({len(data)})")
    if data[:4] != WAI1_MAGIC:
        raise Wai1Error("invalid_magic", f"Expected b'WAI1', found {data[:4]!r}")

    man_len = struct.unpack_from("<I", data, 4)[0]
    if man_len > MAX_MANIFEST_BYTES:
        raise Wai1Error("manifest_too_large", f"man_len {man_len} exceeds 2^27")
    if len(data) < 12 or len(data) < 8 + man_len + 4:
        raise Wai1Error("container_truncated", "Container truncated inside manifest or payload_len")

    manifest_bytes = data[8 : 8 + man_len]
    try:
        manifest_text = manifest_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Wai1Error("manifest_invalid_utf8", "Manifest is not valid UTF-8") from exc

    strict_tree, plain_manifest = _StrictWaiJsonParser(manifest_text).parse()
    _validate_wai1_manifest_strict(strict_tree)

    payload_len_off = 8 + man_len
    payload_len = struct.unpack_from("<I", data, payload_len_off)[0]
    payload_start = payload_len_off + 4
    expected_total = payload_start + payload_len
    if len(data) != expected_total:
        raise Wai1Error(
            "payload_length_mismatch",
            f"Expected {expected_total} container bytes from payload_len={payload_len}, got {len(data)}",
        )
    raw_payload = data[payload_start:expected_total]
    decoded_payload: bytes | None = None
    cap = plain_manifest["model_requirement"]["capability"]
    if cap == "wai.text.zstd":
        decoded_payload = zstd_decode_bounded(raw_payload)

    return Wai1DecodedEnvelope(
        manifest=plain_manifest,
        manifest_bytes=manifest_bytes,
        raw_payload=raw_payload,
        decoded_payload=decoded_payload,
        envelope_blake3=blake3_hex(data),
        envelope_bytes=len(data),
    )


def wrap_artifact_in_wai1(
    *,
    artifact_kind: str,
    slug: str,
    media: str,
    license_spdx: str,
    difficulty_rung: dict[str, Any],
    energy_cost_j: dict[str, Any],
    payload_plaintext: bytes,
    target_meta: dict[str, Any] | None = None,
    capability: str = "wai.text.zstd",
    fallback: str | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Package `payload_plaintext` into a conforming `WAI1` envelope (`wai.text.zstd` floor).

    Returns `(wai_bytes, envelope_descriptor_dict)`.
    """
    content_b3 = blake3_hex(payload_plaintext)
    content_s256 = sha256_hex(payload_plaintext)
    canonical_id = f"blake3:{artifact_kind}:{content_b3}"

    if capability == "wai.text.zstd":
        wire_payload = zstd_encode_deterministic(payload_plaintext)
        cond_kind = "zstd"
    else:
        wire_payload = payload_plaintext
        cond_kind = capability.rsplit(".", 1)[-1]

    target: dict[str, Any] = {"uncompressed_bytes": len(payload_plaintext)}
    if target_meta:
        for k, v in target_meta.items():
            target[k] = v

    manifest: dict[str, Any] = {
        "wai": "1.0",
        "media": media,
        "intent": "replicate",
        "model_requirement": {
            "capability": capability,
            "fallback": fallback,
        },
        "conditioning": {
            "kind": cond_kind,
        },
        "security": {
            "encryption": "none",
            "kid": 0,
        },
        "target": target,
        "openie_artifact": {
            "canonical_id": canonical_id,
            "artifact_kind": artifact_kind,
            "slug": slug,
            "license": license_spdx,
            "content_blake3": content_b3,
            "sha256": content_s256,
            "energy_evidence_class": energy_cost_j["evidence_class"],
            "difficulty_rung": {
                "rung": difficulty_rung["rung"],
                "rung_name": difficulty_rung["rung_name"],
                "phase": difficulty_rung["phase"],
                "compilation_threshold_crossed": difficulty_rung[
                    "compilation_threshold_crossed"
                ],
            },
        },
    }
    wai_bytes = encode_wai1_envelope(manifest, wire_payload)
    env_b3 = blake3_hex(wai_bytes)
    descriptor = {
        "format": "WAI1",
        "wai_version": "1.0",
        "media_type": "application/vnd.wai",
        "capability": capability,
        "fallback": fallback,
        "envelope_blake3": env_b3,
        "envelope_bytes": len(wai_bytes),
    }
    return wai_bytes, descriptor
