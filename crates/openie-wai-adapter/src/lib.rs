// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]

//! Conforming `WAI1` (`application/vnd.wai`) Envelope Adapter and Canonical OpenIE
//! Artifact Substrate (`openie-wai-adapter`, Steps 1 & 2).
//!
//! Enforces WAI `SPEC.md` §2 & §3 byte-level rules:
//! - Bytes `0..4`: ASCII `"WAI1"`
//! - Bytes `4..8`: `u32` little-endian `man_len` (`<= 2^27`, checked before reading manifest)
//! - Bytes `8..8+man_len`: compact UTF-8 JSON manifest (`depth <= 127`, `values <= 2^22`,
//!   unique member names per object after escape decoding, zero insignificant whitespace,
//!   strict integer check rejecting `-0`, `1.0`, `1e0`)
//! - Next 4 bytes: `u32` little-endian `payload_len` + `payload` bytes
//! - `wai.text.zstd`: RFC 8878 Zstandard framing with `<= 2^27` content & window size guards
//! - Deterministic `BLAKE3` + `Ed25519` (`ed25519-dalek` strict RFC 8032) over RFC 8785 JCS
//!   canonical JSON, bit-for-bit cross-verified with Python `openie_artifact`.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ruzstd::StreamingDecoder;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Read;

pub const WAI1_MAGIC: &[u8; 4] = b"WAI1";
pub const MAX_MANIFEST_BYTES: usize = 1 << 27; // 134,217,728
pub const MAX_MANIFEST_DEPTH: usize = 127;
pub const MAX_MANIFEST_VALUES: usize = 1 << 22; // 4,194,304
pub const MAX_ZSTD_DECODED_BYTES: usize = 1 << 27;
pub const MAX_ZSTD_WINDOW_BYTES: usize = 1 << 27;
pub const ZSTD_FRAME_MAGIC: u32 = 0xFD2F_B528;

pub const CANONICAL_SIGNING_DOMAIN: &[u8] = b"openie-artifact-v1\x00";
pub const OPENIE_SUBSTRATE_DEFAULT_SEED_DOMAIN: &[u8] =
    b"openie:substrate:catalog-ed25519-seed:v1";

pub const COMPANION_ONLY_CAPABILITIES: [&str; 7] = [
    "wai.meta.hdr10plus",
    "wai.meta.dovi",
    "wai.meta.st2094_50",
    "wai.meta.gainmap",
    "wai.video.lcevc",
    "wai.audio.opus.dred",
    "wai.audio.opus.dred.int",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wai1Error {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for Wai1Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Wai1Error {}

impl Wai1Error {
    pub fn new(code: &'static str, msg: impl Into<String>) -> Self {
        Self {
            code,
            message: msg.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Cryptographic Primitives (BLAKE3, SHA-256, Ed25519, RFC 8785 JCS)
// ---------------------------------------------------------------------------

pub fn blake3_hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn derive_default_signing_seed() -> [u8; 32] {
    *blake3::hash(OPENIE_SUBSTRATE_DEFAULT_SEED_DOMAIN).as_bytes()
}

pub fn ed25519_pubkey_from_seed(seed32: &[u8; 32]) -> [u8; 32] {
    let sk = SigningKey::from_bytes(seed32);
    sk.verifying_key().to_bytes()
}

pub fn ed25519_sign(seed32: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let sk = SigningKey::from_bytes(seed32);
    sk.sign(message).to_bytes()
}

pub fn ed25519_verify_strict(pubkey32: &[u8; 32], message: &[u8], sig64: &[u8; 64]) -> bool {
    let vk = match VerifyingKey::from_bytes(pubkey32) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(sig64);
    vk.verify_strict(message, &sig).is_ok()
}

/// Format an IEEE-754 finite f64 according to RFC 8785 (JCS) / ECMA-262 §7.1.12.1.
pub fn format_jcs_f64(val: f64) -> Result<String, Wai1Error> {
    if !val.is_finite() {
        return Err(Wai1Error::new(
            "non_finite_float",
            "Non-finite float forbidden in JCS",
        ));
    }
    if val == 0.0 {
        return Ok("0".to_string());
    }
    let sign = if val.is_sign_negative() { "-" } else { "" };
    let av = val.abs();
    // Rust's shortest round-trip Display on f64 (Dragonbox/Ryū) produces exact shortest digits.
    // Parse significant digits and decimal exponent to format per ECMA-262 / RFC 8785 §3.2.2.3.
    let s = format!("{av:?}");
    let (digits, exp10): (String, i32) = if let Some((m, e)) = s.split_once('e') {
        let frac_len = m.split_once('.').map(|(_, f)| f.len() as i32).unwrap_or(0);
        let raw_digits: String = m.chars().filter(|&c| c != '.').collect();
        let trimmed = raw_digits.trim_end_matches('0');
        let d = if trimmed.is_empty() { "0" } else { trimmed };
        let trailing = raw_digits.len() as i32 - d.len() as i32;
        let parsed_e: i32 = e
            .parse()
            .map_err(|_| Wai1Error::new("jcs_float", "Failed exponent parse"))?;
        (d.to_string(), parsed_e - frac_len + trailing)
    } else if let Some((ip, fp)) = s.split_once('.') {
        if fp == "0" {
            let trimmed = ip.trim_end_matches('0');
            if trimmed.is_empty() {
                ("0".to_string(), 0)
            } else {
                let trailing = ip.len() as i32 - trimmed.len() as i32;
                (trimmed.to_string(), trailing)
            }
        } else {
            let combined = if ip == "0" {
                fp.to_string()
            } else {
                format!("{ip}{fp}")
            };
            let stripped = combined.trim_start_matches('0');
            let trimmed = stripped.trim_end_matches('0');
            let trailing = stripped.len() as i32 - trimmed.len() as i32;
            (trimmed.to_string(), -(fp.len() as i32) + trailing)
        }
    } else {
        let trimmed = s.trim_end_matches('0');
        let trailing = s.len() as i32 - trimmed.len() as i32;
        (trimmed.to_string(), trailing)
    };

    let k = digits.len() as i32;
    let n = k + exp10;
    if k <= n && n <= 21 {
        let zeros = "0".repeat((n - k) as usize);
        Ok(format!("{sign}{digits}{zeros}"))
    } else if 0 < n && n <= 21 {
        let split = n as usize;
        Ok(format!("{sign}{}.{}", &digits[..split], &digits[split..]))
    } else if -6 < n && n <= 0 {
        let zeros = "0".repeat((-n) as usize);
        Ok(format!("{sign}0.{zeros}{digits}"))
    } else {
        let exp_val = n - 1;
        let exp_sign = if exp_val >= 0 { "+" } else { "-" };
        let exp_abs = exp_val.abs();
        if k == 1 {
            Ok(format!("{sign}{digits}e{exp_sign}{exp_abs}"))
        } else {
            Ok(format!(
                "{sign}{}.{}e{exp_sign}{exp_abs}",
                &digits[..1],
                &digits[1..]
            ))
        }
    }
}

fn encode_jcs_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        let cp = ch as u32;
        match cp {
            0x08 => out.push_str("\\b"),
            0x09 => out.push_str("\\t"),
            0x0A => out.push_str("\\n"),
            0x0C => out.push_str("\\f"),
            0x0D => out.push_str("\\r"),
            0x22 => out.push_str("\\\""),
            0x5C => out.push_str("\\\\"),
            0x00..=0x1F => out.push_str(&format!("\\u{cp:04x}")),
            _ => out.push(ch),
        }
    }
    out.push('"');
}

fn utf16_key(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn write_jcs_value(val: &Value, out: &mut String) -> Result<(), Wai1Error> {
    match val {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(num) => {
            if let Some(i) = num.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = num.as_u64() {
                out.push_str(&u.to_string());
            } else if let Some(f) = num.as_f64() {
                out.push_str(&format_jcs_f64(f)?);
            } else {
                return Err(Wai1Error::new("jcs_number", "Unsupported JSON number"));
            }
        }
        Value::String(s) => encode_jcs_string(s, out),
        Value::Array(arr) => {
            out.push('[');
            for (idx, item) in arr.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_jcs_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|(ka, _), (kb, _)| utf16_key(ka).cmp(&utf16_key(kb)));
            out.push('{');
            for (idx, (k, v)) in entries.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                encode_jcs_string(k, out);
                out.push(':');
                write_jcs_value(v, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

pub fn canonical_jcs_bytes(val: &Value) -> Result<Vec<u8>, Wai1Error> {
    let mut s = String::new();
    write_jcs_value(val, &mut s)?;
    Ok(s.into_bytes())
}

pub fn artifact_signing_preimage(artifact: &Value) -> Result<Vec<u8>, Wai1Error> {
    let mut cloned = artifact.clone();
    let prov = cloned
        .get_mut("provenance_chain")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| Wai1Error::new("missing_provenance", "Missing provenance_chain"))?;
    prov.insert("ed25519_sig".to_string(), Value::String(String::new()));
    let jcs = canonical_jcs_bytes(&cloned)?;
    let mut preimage = Vec::with_capacity(CANONICAL_SIGNING_DOMAIN.len() + jcs.len());
    preimage.extend_from_slice(CANONICAL_SIGNING_DOMAIN);
    preimage.extend_from_slice(&jcs);
    Ok(preimage)
}

pub fn sign_canonical_artifact(artifact: &mut Value, seed32: &[u8; 32]) -> Result<(), Wai1Error> {
    let pubkey = ed25519_pubkey_from_seed(seed32);
    {
        let prov = artifact
            .get_mut("provenance_chain")
            .and_then(|v| v.as_object_mut())
            .ok_or_else(|| Wai1Error::new("missing_provenance", "Missing provenance_chain"))?;
        prov.insert("ed25519_pubkey".to_string(), Value::String(hex::encode(pubkey)));
    }
    let preimage = artifact_signing_preimage(artifact)?;
    let sig = ed25519_sign(seed32, &preimage);
    let prov = artifact
        .get_mut("provenance_chain")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| Wai1Error::new("missing_provenance", "Missing provenance_chain"))?;
    prov.insert("ed25519_sig".to_string(), Value::String(hex::encode(sig)));
    Ok(())
}

pub fn verify_canonical_artifact_signature(artifact: &Value) -> Result<bool, Wai1Error> {
    let prov = artifact
        .get("provenance_chain")
        .and_then(|v| v.as_object())
        .ok_or_else(|| Wai1Error::new("missing_provenance", "Missing provenance_chain"))?;
    let pub_hex = prov
        .get("ed25519_pubkey")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let sig_hex = prov
        .get("ed25519_sig")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if pub_hex.len() != 64 || sig_hex.len() != 128 {
        return Ok(false);
    }
    let pub_bytes: [u8; 32] = match hex::decode(pub_hex) {
        Ok(v) => match v.try_into() {
            Ok(arr) => arr,
            Err(_) => return Ok(false),
        },
        Err(_) => return Ok(false),
    };
    let sig_bytes: [u8; 64] = match hex::decode(sig_hex) {
        Ok(v) => match v.try_into() {
            Ok(arr) => arr,
            Err(_) => return Ok(false),
        },
        Err(_) => return Ok(false),
    };
    let preimage = artifact_signing_preimage(artifact)?;
    Ok(ed25519_verify_strict(&pub_bytes, &preimage, &sig_bytes))
}

// ---------------------------------------------------------------------------
// Strict WAI1 Wire JSON Parser (`SPEC.md` §2)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum StrictJsonValue {
    Null,
    Bool(bool),
    StrictInt(i128),
    NonIntNumber(f64),
    String(String),
    Array(Vec<StrictJsonValue>),
    Object(Vec<(String, StrictJsonValue)>),
}

impl StrictJsonValue {
    fn get_field(&self, key: &str) -> Option<&StrictJsonValue> {
        match self {
            StrictJsonValue::Object(entries) => {
                entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
            }
            _ => None,
        }
    }

    fn to_serde_value(&self) -> Value {
        match self {
            StrictJsonValue::Null => Value::Null,
            StrictJsonValue::Bool(b) => Value::Bool(*b),
            StrictJsonValue::StrictInt(i) => {
                if let Ok(u) = u64::try_from(*i) {
                    Value::Number(u.into())
                } else if let Ok(si) = i64::try_from(*i) {
                    Value::Number(si.into())
                } else {
                    serde_json::Number::from_f64(*i as f64)
                        .map(Value::Number)
                        .unwrap_or(Value::Null)
                }
            }
            StrictJsonValue::NonIntNumber(f) => serde_json::Number::from_f64(*f)
                .map(Value::Number)
                .unwrap_or(Value::Null),
            StrictJsonValue::String(s) => Value::String(s.clone()),
            StrictJsonValue::Array(arr) => {
                Value::Array(arr.iter().map(|v| v.to_serde_value()).collect())
            }
            StrictJsonValue::Object(entries) => {
                let mut map = Map::new();
                for (k, v) in entries {
                    map.insert(k.clone(), v.to_serde_value());
                }
                Value::Object(map)
            }
        }
    }
}

struct StrictWaiJsonParser<'a> {
    bytes: &'a [u8],
    text: &'a str,
    pos: usize,
    value_count: usize,
}

impl<'a> StrictWaiJsonParser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            text,
            pos: 0,
            value_count: 0,
        }
    }

    fn bump_value(&mut self) -> Result<(), Wai1Error> {
        self.value_count += 1;
        if self.value_count > MAX_MANIFEST_VALUES {
            return Err(Wai1Error::new(
                "manifest_too_many_values",
                format!("Manifest exceeds {MAX_MANIFEST_VALUES} JSON values"),
            ));
        }
        Ok(())
    }

    fn parse(mut self) -> Result<StrictJsonValue, Wai1Error> {
        if self.bytes.is_empty() {
            return Err(Wai1Error::new("manifest_malformed", "Empty manifest"));
        }
        let val = self.parse_value(1)?;
        if self.pos != self.bytes.len() {
            let b = self.bytes[self.pos];
            if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
                return Err(Wai1Error::new(
                    "manifest_whitespace",
                    "Trailing whitespace forbidden in WAI1 manifest",
                ));
            }
            return Err(Wai1Error::new(
                "manifest_trailing_bytes",
                "Unexpected trailing bytes after manifest object",
            ));
        }
        Ok(val)
    }

    fn parse_value(&mut self, depth: usize) -> Result<StrictJsonValue, Wai1Error> {
        if self.pos >= self.bytes.len() {
            return Err(Wai1Error::new("manifest_malformed", "Unexpected EOF"));
        }
        let b = self.bytes[self.pos];
        if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            return Err(Wai1Error::new(
                "manifest_whitespace",
                format!("Insignificant whitespace forbidden at byte {}", self.pos),
            ));
        }
        match b {
            b'{' => {
                if depth > MAX_MANIFEST_DEPTH {
                    return Err(Wai1Error::new(
                        "manifest_too_deep",
                        format!("Manifest nesting exceeds {MAX_MANIFEST_DEPTH}"),
                    ));
                }
                self.bump_value()?;
                self.parse_object(depth)
            }
            b'[' => {
                if depth > MAX_MANIFEST_DEPTH {
                    return Err(Wai1Error::new(
                        "manifest_too_deep",
                        format!("Manifest nesting exceeds {MAX_MANIFEST_DEPTH}"),
                    ));
                }
                self.bump_value()?;
                self.parse_array(depth)
            }
            b'"' => {
                self.bump_value()?;
                Ok(StrictJsonValue::String(self.parse_string()?))
            }
            b't' => {
                if self.bytes[self.pos..].starts_with(b"true") {
                    self.bump_value()?;
                    self.pos += 4;
                    Ok(StrictJsonValue::Bool(true))
                } else {
                    Err(Wai1Error::new("manifest_malformed", "Invalid literal"))
                }
            }
            b'f' => {
                if self.bytes[self.pos..].starts_with(b"false") {
                    self.bump_value()?;
                    self.pos += 5;
                    Ok(StrictJsonValue::Bool(false))
                } else {
                    Err(Wai1Error::new("manifest_malformed", "Invalid literal"))
                }
            }
            b'n' => {
                if self.bytes[self.pos..].starts_with(b"null") {
                    self.bump_value()?;
                    self.pos += 4;
                    Ok(StrictJsonValue::Null)
                } else {
                    Err(Wai1Error::new("manifest_malformed", "Invalid literal"))
                }
            }
            b'-' | b'0'..=b'9' => {
                self.bump_value()?;
                self.parse_number()
            }
            _ => Err(Wai1Error::new(
                "manifest_malformed",
                format!("Unexpected byte 0x{b:02x} at {}", self.pos),
            )),
        }
    }

    fn parse_string(&mut self) -> Result<String, Wai1Error> {
        self.pos += 1; // skip opening '"'
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b == b'"' {
                self.pos += 1;
                return Ok(out);
            }
            if b < 0x20 {
                return Err(Wai1Error::new(
                    "manifest_malformed",
                    "Unescaped control character in string",
                ));
            }
            if b == b'\\' {
                self.pos += 1;
                if self.pos >= self.bytes.len() {
                    return Err(Wai1Error::new("manifest_malformed", "Unterminated escape"));
                }
                let esc = self.bytes[self.pos];
                self.pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000C}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        if self.pos + 4 > self.bytes.len() {
                            return Err(Wai1Error::new("manifest_malformed", "Short \\u escape"));
                        }
                        let hex_str = &self.text[self.pos..self.pos + 4];
                        let cp = u16::from_str_radix(hex_str, 16)
                            .map_err(|_| Wai1Error::new("manifest_malformed", "Bad \\u hex"))?;
                        self.pos += 4;
                        if (0xD800..=0xDBFF).contains(&cp) {
                            if self.pos + 6 > self.bytes.len()
                                || &self.bytes[self.pos..self.pos + 2] != b"\\u"
                            {
                                return Err(Wai1Error::new(
                                    "manifest_malformed",
                                    "Unpaired high surrogate",
                                ));
                            }
                            let low_str = &self.text[self.pos + 2..self.pos + 6];
                            let low = u16::from_str_radix(low_str, 16).map_err(|_| {
                                Wai1Error::new("manifest_malformed", "Bad low surrogate")
                            })?;
                            if !(0xDC00..=0xDFFF).contains(&low) {
                                return Err(Wai1Error::new(
                                    "manifest_malformed",
                                    "Invalid low surrogate",
                                ));
                            }
                            self.pos += 6;
                            let combined =
                                0x10000u32 + (((cp - 0xD800) as u32) << 10) + ((low - 0xDC00) as u32);
                            let ch = char::from_u32(combined).ok_or_else(|| {
                                Wai1Error::new("manifest_malformed", "Invalid codepoint")
                            })?;
                            out.push(ch);
                        } else if (0xDC00..=0xDFFF).contains(&cp) {
                            return Err(Wai1Error::new(
                                "manifest_malformed",
                                "Unpaired low surrogate",
                            ));
                        } else {
                            let ch = char::from_u32(cp as u32).ok_or_else(|| {
                                Wai1Error::new("manifest_malformed", "Invalid codepoint")
                            })?;
                            out.push(ch);
                        }
                    }
                    _ => {
                        return Err(Wai1Error::new("manifest_malformed", "Invalid escape char"));
                    }
                }
            } else {
                let ch = self.text[self.pos..]
                    .chars()
                    .next()
                    .ok_or_else(|| Wai1Error::new("manifest_malformed", "UTF-8 error"))?;
                self.pos += ch.len_utf8();
                out.push(ch);
            }
        }
        Err(Wai1Error::new("manifest_malformed", "Unterminated string"))
    }

    fn parse_number(&mut self) -> Result<StrictJsonValue, Wai1Error> {
        let start = self.pos;
        let mut neg = false;
        if self.bytes[self.pos] == b'-' {
            neg = true;
            self.pos += 1;
            if self.pos >= self.bytes.len() {
                return Err(Wai1Error::new("manifest_malformed", "Bare minus"));
            }
        }
        if self.pos >= self.bytes.len() || !self.bytes[self.pos].is_ascii_digit() {
            return Err(Wai1Error::new("manifest_malformed", "Expected digit"));
        }
        let leading_zero = self.bytes[self.pos] == b'0';
        if leading_zero {
            self.pos += 1;
            if self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
                return Err(Wai1Error::new(
                    "manifest_malformed",
                    "Leading zero forbidden in JSON number",
                ));
            }
        } else {
            while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
        }

        let mut has_frac_or_exp = false;
        if self.pos < self.bytes.len() && self.bytes[self.pos] == b'.' {
            has_frac_or_exp = true;
            self.pos += 1;
            if self.pos >= self.bytes.len() || !self.bytes[self.pos].is_ascii_digit() {
                return Err(Wai1Error::new(
                    "manifest_malformed",
                    "Expected fraction digits",
                ));
            }
            while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
        }
        if self.pos < self.bytes.len() && matches!(self.bytes[self.pos], b'e' | b'E') {
            has_frac_or_exp = true;
            self.pos += 1;
            if self.pos < self.bytes.len() && matches!(self.bytes[self.pos], b'+' | b'-') {
                self.pos += 1;
            }
            if self.pos >= self.bytes.len() || !self.bytes[self.pos].is_ascii_digit() {
                return Err(Wai1Error::new(
                    "manifest_malformed",
                    "Expected exponent digits",
                ));
            }
            while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
        }

        let raw = &self.text[start..self.pos];
        // WAI SPEC.md §2: `-0`, `1.0`, `1e0` are NOT integers!
        if has_frac_or_exp || (neg && leading_zero) {
            let fv: f64 = raw
                .parse()
                .map_err(|_| Wai1Error::new("manifest_malformed", "Float parse error"))?;
            if !fv.is_finite() {
                return Err(Wai1Error::new("manifest_malformed", "Number overflow"));
            }
            Ok(StrictJsonValue::NonIntNumber(fv))
        } else {
            let iv: i128 = raw
                .parse()
                .map_err(|_| Wai1Error::new("manifest_malformed", "Integer overflow"))?;
            Ok(StrictJsonValue::StrictInt(iv))
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<StrictJsonValue, Wai1Error> {
        self.pos += 1; // '{'
        let mut entries = Vec::new();
        let mut seen = BTreeSet::new();
        if self.pos < self.bytes.len() && self.bytes[self.pos] == b'}' {
            self.pos += 1;
            return Ok(StrictJsonValue::Object(entries));
        }
        loop {
            if self.pos >= self.bytes.len() {
                return Err(Wai1Error::new("manifest_malformed", "Unterminated object"));
            }
            if matches!(self.bytes[self.pos], b' ' | b'\t' | b'\r' | b'\n') {
                return Err(Wai1Error::new(
                    "manifest_whitespace",
                    "Whitespace before member key",
                ));
            }
            if self.bytes[self.pos] != b'"' {
                return Err(Wai1Error::new(
                    "manifest_malformed",
                    "Expected string member key",
                ));
            }
            let key = self.parse_string()?;
            if !seen.insert(key.clone()) {
                return Err(Wai1Error::new(
                    "manifest_duplicate_member",
                    format!("Duplicate member name '{key}' in object"),
                ));
            }
            if self.pos >= self.bytes.len() || self.bytes[self.pos] != b':' {
                if self.pos < self.bytes.len()
                    && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\r' | b'\n')
                {
                    return Err(Wai1Error::new(
                        "manifest_whitespace",
                        "Whitespace before ':'",
                    ));
                }
                return Err(Wai1Error::new("manifest_malformed", "Expected ':'"));
            }
            self.pos += 1;
            let val = self.parse_value(depth + 1)?;
            entries.push((key, val));
            if self.pos >= self.bytes.len() {
                return Err(Wai1Error::new("manifest_malformed", "Unterminated object"));
            }
            match self.bytes[self.pos] {
                b'}' => {
                    self.pos += 1;
                    return Ok(StrictJsonValue::Object(entries));
                }
                b',' => {
                    self.pos += 1;
                }
                b' ' | b'\t' | b'\r' | b'\n' => {
                    return Err(Wai1Error::new(
                        "manifest_whitespace",
                        "Whitespace inside object",
                    ));
                }
                _ => {
                    return Err(Wai1Error::new(
                        "manifest_malformed",
                        "Expected ',' or '}' in object",
                    ));
                }
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<StrictJsonValue, Wai1Error> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        if self.pos < self.bytes.len() && self.bytes[self.pos] == b']' {
            self.pos += 1;
            return Ok(StrictJsonValue::Array(items));
        }
        loop {
            let val = self.parse_value(depth + 1)?;
            items.push(val);
            if self.pos >= self.bytes.len() {
                return Err(Wai1Error::new("manifest_malformed", "Unterminated array"));
            }
            match self.bytes[self.pos] {
                b']' => {
                    self.pos += 1;
                    return Ok(StrictJsonValue::Array(items));
                }
                b',' => {
                    self.pos += 1;
                }
                b' ' | b'\t' | b'\r' | b'\n' => {
                    return Err(Wai1Error::new(
                        "manifest_whitespace",
                        "Whitespace inside array",
                    ));
                }
                _ => {
                    return Err(Wai1Error::new(
                        "manifest_malformed",
                        "Expected ',' or ']' in array",
                    ));
                }
            }
        }
    }
}

fn require_strict_int(
    val: &StrictJsonValue,
    field: &'static str,
    min_val: Option<i128>,
    max_val: Option<i128>,
) -> Result<i128, Wai1Error> {
    match val {
        StrictJsonValue::StrictInt(i) => {
            if let Some(lo) = min_val {
                if *i < lo {
                    return Err(Wai1Error::new(
                        "manifest_integer_range",
                        format!("{field} < {lo}"),
                    ));
                }
            }
            if let Some(hi) = max_val {
                if *i > hi {
                    return Err(Wai1Error::new(
                        "manifest_integer_range",
                        format!("{field} > {hi}"),
                    ));
                }
            }
            Ok(*i)
        }
        _ => Err(Wai1Error::new(
            "manifest_non_integer",
            format!("{field} must be a strict JSON integer (rejecting -0, 1.0, 1e0)"),
        )),
    }
}

fn validate_wai1_manifest_strict(root: &StrictJsonValue) -> Result<(), Wai1Error> {
    if !matches!(root, StrictJsonValue::Object(_)) {
        return Err(Wai1Error::new(
            "manifest_malformed",
            "WAI1 manifest must be a JSON object",
        ));
    }

    let wai_ver = match root.get_field("wai") {
        Some(StrictJsonValue::String(s)) => s.as_str(),
        _ => return Err(Wai1Error::new("manifest_malformed", "Missing 'wai' string")),
    };
    let (major, minor) = wai_ver
        .split_once('.')
        .ok_or_else(|| Wai1Error::new("manifest_malformed", "Malformed 'wai' version"))?;
    if major.is_empty()
        || minor.is_empty()
        || !major.bytes().all(|b| b.is_ascii_digit())
        || !minor.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Wai1Error::new("manifest_malformed", "Invalid 'wai' digits"));
    }
    if major != "1" {
        return Err(Wai1Error::new(
            "unknown_major_version",
            format!("Unsupported WAI major version '{major}'"),
        ));
    }

    match root.get_field("media") {
        Some(StrictJsonValue::String(s)) if !s.is_empty() => {}
        _ => return Err(Wai1Error::new("manifest_malformed", "Missing 'media'")),
    }
    match root.get_field("intent") {
        Some(StrictJsonValue::String(s)) if !s.is_empty() => {}
        _ => return Err(Wai1Error::new("manifest_malformed", "Missing 'intent'")),
    }

    let mr = root
        .get_field("model_requirement")
        .ok_or_else(|| Wai1Error::new("manifest_malformed", "Missing 'model_requirement'"))?;
    let cap = match mr.get_field("capability") {
        Some(StrictJsonValue::String(s)) if !s.is_empty() => s.as_str(),
        _ => {
            return Err(Wai1Error::new(
                "manifest_malformed",
                "Missing 'model_requirement.capability'",
            ))
        }
    };
    if COMPANION_ONLY_CAPABILITIES.contains(&cap) {
        return Err(Wai1Error::new(
            "companion_in_wai1",
            format!("Companion-only capability '{cap}' forbidden in WAI1"),
        ));
    }
    match mr.get_field("fallback") {
        Some(StrictJsonValue::Null) | None => {}
        Some(StrictJsonValue::String(fb)) if !fb.is_empty() => {
            if COMPANION_ONLY_CAPABILITIES.contains(&fb.as_str()) {
                return Err(Wai1Error::new(
                    "companion_in_wai1",
                    format!("Companion-only fallback '{fb}' forbidden in WAI1"),
                ));
            }
        }
        _ => {
            return Err(Wai1Error::new(
                "manifest_malformed",
                "Invalid 'model_requirement.fallback'",
            ))
        }
    }

    let cond = root
        .get_field("conditioning")
        .ok_or_else(|| Wai1Error::new("manifest_malformed", "Missing 'conditioning'"))?;
    match cond.get_field("kind") {
        Some(StrictJsonValue::String(s)) if !s.is_empty() => {}
        _ => {
            return Err(Wai1Error::new(
                "manifest_malformed",
                "Missing 'conditioning.kind'",
            ))
        }
    }
    if let Some(prior) = cond.get_field("prior") {
        if !matches!(prior, StrictJsonValue::Null) {
            if !matches!(prior, StrictJsonValue::Object(_)) {
                return Err(Wai1Error::new(
                    "manifest_malformed",
                    "'conditioning.prior' must be object",
                ));
            }
            match prior.get_field("id") {
                Some(StrictJsonValue::String(s)) if !s.is_empty() => {}
                _ => return Err(Wai1Error::new("pin_malformed", "Missing prior.id")),
            }
            match prior.get_field("sha256") {
                Some(StrictJsonValue::String(s))
                    if s.len() == 64
                        && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) => {}
                _ => return Err(Wai1Error::new("pin_malformed", "Invalid prior.sha256")),
            }
            match prior.get_field("determinism") {
                Some(StrictJsonValue::String(s)) if !s.is_empty() => {}
                _ => return Err(Wai1Error::new("pin_malformed", "Missing prior.determinism")),
            }
        }
    }

    if let Some(sec) = root.get_field("security") {
        if !matches!(sec, StrictJsonValue::Null) {
            if !matches!(sec, StrictJsonValue::Object(_)) {
                return Err(Wai1Error::new(
                    "manifest_malformed",
                    "'security' must be object",
                ));
            }
            match sec.get_field("encryption") {
                Some(StrictJsonValue::String(s)) if !s.is_empty() => {}
                _ => {
                    return Err(Wai1Error::new(
                        "manifest_malformed",
                        "Missing 'security.encryption'",
                    ))
                }
            }
            if let Some(kid_val) = sec.get_field("kid") {
                require_strict_int(kid_val, "security.kid", Some(0), Some(u64::MAX as i128))?;
            }
        }
    }

    if let Some(tgt) = root.get_field("target") {
        if !matches!(tgt, StrictJsonValue::Null) {
            if !matches!(tgt, StrictJsonValue::Object(_)) {
                return Err(Wai1Error::new(
                    "manifest_malformed",
                    "'target' must be object",
                ));
            }
            for k in [
                "uncompressed_bytes",
                "episode_number",
                "turn_count",
                "cut_count",
                "step_count",
                "dof_count",
                "schema_version",
            ] {
                if let Some(v) = tgt.get_field(k) {
                    if !matches!(v, StrictJsonValue::Null) {
                        require_strict_int(v, "target.<int>", Some(0), None)?;
                    }
                }
            }
        }
    }

    if let Some(oa) = root.get_field("openie_artifact") {
        if !matches!(oa, StrictJsonValue::Null) {
            if !matches!(oa, StrictJsonValue::Object(_)) {
                return Err(Wai1Error::new(
                    "manifest_malformed",
                    "'openie_artifact' must be object",
                ));
            }
            if let Some(dr) = oa.get_field("difficulty_rung") {
                if let Some(r) = dr.get_field("rung") {
                    require_strict_int(r, "difficulty_rung.rung", Some(1), Some(9))?;
                }
                if let Some(p) = dr.get_field("phase") {
                    require_strict_int(p, "difficulty_rung.phase", Some(1), Some(2))?;
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// RFC 8878 Zstandard Framing & Reader Limits (`wai.text.zstd`, SPEC.md §2)
// ---------------------------------------------------------------------------

pub fn zstd_encode_deterministic(plaintext: &[u8]) -> Result<Vec<u8>, Wai1Error> {
    let n = plaintext.len();
    if n > MAX_ZSTD_DECODED_BYTES {
        return Err(Wai1Error::new(
            "text_decoded_too_long",
            format!("Plaintext {n} exceeds 2^27"),
        ));
    }
    let mut out = Vec::with_capacity(n + 16);
    out.extend_from_slice(&ZSTD_FRAME_MAGIC.to_le_bytes());
    if n <= 255 {
        out.push(0x20);
        out.push(n as u8);
    } else if n <= 65_791 {
        out.push(0x60);
        out.extend_from_slice(&((n - 256) as u16).to_le_bytes());
    } else {
        out.push(0xA0);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    }

    if n == 0 {
        out.extend_from_slice(&[1, 0, 0]);
        return Ok(out);
    }

    let max_blk = 131_072usize;
    let mut offset = 0usize;
    while offset < n {
        let end = (offset + max_blk).min(n);
        let chunk = &plaintext[offset..end];
        offset = end;
        let is_last: u32 = if offset >= n { 1 } else { 0 };
        let bh: u32 = is_last | ((chunk.len() as u32) << 3);
        out.push((bh & 0xFF) as u8);
        out.push(((bh >> 8) & 0xFF) as u8);
        out.push(((bh >> 16) & 0xFF) as u8);
        out.extend_from_slice(chunk);
    }
    Ok(out)
}

pub fn check_zstd_frame_limits(zstd_bytes: &[u8]) -> Result<(), Wai1Error> {
    if zstd_bytes.len() < 6 {
        return Err(Wai1Error::new(
            "zstd_malformed",
            "Zstandard frame shorter than 6 bytes",
        ));
    }
    let magic = u32::from_le_bytes([zstd_bytes[0], zstd_bytes[1], zstd_bytes[2], zstd_bytes[3]]);
    if magic != ZSTD_FRAME_MAGIC {
        return Err(Wai1Error::new(
            "zstd_malformed",
            format!("Invalid Zstandard magic 0x{magic:08x}"),
        ));
    }
    let fhd = zstd_bytes[4];
    let fcs_flag = (fhd >> 6) & 0x3;
    let single_segment = ((fhd >> 5) & 0x1) == 1;
    let reserved_bit = (fhd >> 3) & 0x1;
    if reserved_bit != 0 {
        return Err(Wai1Error::new("zstd_malformed", "Reserved bit set in FHD"));
    }
    let dict_id_flag = (fhd & 0x3) as usize;
    let dict_sizes = [0usize, 1, 2, 4];

    let mut pos = 5usize;
    if !single_segment {
        if pos >= zstd_bytes.len() {
            return Err(Wai1Error::new("zstd_malformed", "Truncated Window_Descriptor"));
        }
        let wd = zstd_bytes[pos];
        pos += 1;
        let exponent = (wd >> 3) as u32;
        let mantissa = (wd & 0x7) as u64;
        let shift = 10u32 + exponent;
        if shift >= 63 {
            return Err(Wai1Error::new(
                "text_window_too_large",
                "Zstandard window exponent overflow",
            ));
        }
        let window_base = 1u64 << shift;
        let window_size = window_base + (window_base / 8) * mantissa;
        if window_size > MAX_ZSTD_WINDOW_BYTES as u64 {
            return Err(Wai1Error::new(
                "text_window_too_large",
                format!("Zstandard window {window_size} exceeds 2^27"),
            ));
        }
    }

    pos += dict_sizes[dict_id_flag];
    let fcs_len = match fcs_flag {
        0 => usize::from(single_segment),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if fcs_len > 0 {
        if pos + fcs_len > zstd_bytes.len() {
            return Err(Wai1Error::new(
                "zstd_malformed",
                "Truncated Frame_Content_Size",
            ));
        }
        let fcs: u64 = match fcs_len {
            1 => zstd_bytes[pos] as u64,
            2 => u16::from_le_bytes([zstd_bytes[pos], zstd_bytes[pos + 1]]) as u64 + 256,
            4 => u32::from_le_bytes([
                zstd_bytes[pos],
                zstd_bytes[pos + 1],
                zstd_bytes[pos + 2],
                zstd_bytes[pos + 3],
            ]) as u64,
            _ => u64::from_le_bytes([
                zstd_bytes[pos],
                zstd_bytes[pos + 1],
                zstd_bytes[pos + 2],
                zstd_bytes[pos + 3],
                zstd_bytes[pos + 4],
                zstd_bytes[pos + 5],
                zstd_bytes[pos + 6],
                zstd_bytes[pos + 7],
            ]),
        };
        if fcs > MAX_ZSTD_DECODED_BYTES as u64 {
            return Err(Wai1Error::new(
                "text_decoded_too_long",
                format!("Declared Zstandard content size {fcs} exceeds 2^27"),
            ));
        }
        if single_segment && fcs > MAX_ZSTD_WINDOW_BYTES as u64 {
            return Err(Wai1Error::new(
                "text_window_too_large",
                format!("Single-segment window {fcs} exceeds 2^27"),
            ));
        }
    }
    Ok(())
}

pub fn zstd_decode_bounded(zstd_bytes: &[u8]) -> Result<Vec<u8>, Wai1Error> {
    check_zstd_frame_limits(zstd_bytes)?;
    let mut decoder = StreamingDecoder::new(zstd_bytes)
        .map_err(|e| Wai1Error::new("zstd_malformed", format!("ruzstd init failed: {e}")))?;
    let mut out = Vec::new();
    let mut buf = [0u8; 16_384];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|e| Wai1Error::new("zstd_malformed", format!("ruzstd read failed: {e}")))?;
        if n == 0 {
            break;
        }
        if out.len() + n > MAX_ZSTD_DECODED_BYTES {
            return Err(Wai1Error::new(
                "text_decoded_too_long",
                "Decoded Zstandard payload exceeds 2^27",
            ));
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// WAI1 Container Encode & Decode (`SPEC.md` §2 & §3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Wai1DecodedEnvelope {
    pub manifest: Value,
    pub manifest_bytes: Vec<u8>,
    pub raw_payload: Vec<u8>,
    pub decoded_payload: Option<Vec<u8>>,
    pub envelope_blake3: String,
    pub envelope_bytes: usize,
}

pub fn serialize_compact_manifest(manifest: &Value) -> Result<Vec<u8>, Wai1Error> {
    let raw = serde_json::to_vec(manifest)
        .map_err(|e| Wai1Error::new("manifest_serialize", e.to_string()))?;
    if raw.len() > MAX_MANIFEST_BYTES {
        return Err(Wai1Error::new(
            "manifest_too_large",
            format!("Manifest length {} exceeds 2^27", raw.len()),
        ));
    }
    let text = std::str::from_utf8(&raw)
        .map_err(|_| Wai1Error::new("manifest_invalid_utf8", "Manifest not UTF-8"))?;
    let strict_root = StrictWaiJsonParser::new(text).parse()?;
    validate_wai1_manifest_strict(&strict_root)?;
    Ok(raw)
}

pub fn encode_wai1_envelope(manifest: &Value, payload: &[u8]) -> Result<Vec<u8>, Wai1Error> {
    let manifest_bytes = serialize_compact_manifest(manifest)?;
    let man_len = u32::try_from(manifest_bytes.len())
        .map_err(|_| Wai1Error::new("manifest_too_large", "Manifest exceeds u32"))?;
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| Wai1Error::new("payload_too_large", "Payload exceeds u32"))?;

    if manifest
        .get("model_requirement")
        .and_then(|m| m.get("capability"))
        .and_then(|c| c.as_str())
        == Some("wai.text.zstd")
    {
        check_zstd_frame_limits(payload)?;
    }

    let mut out = Vec::with_capacity(12 + manifest_bytes.len() + payload.len());
    out.extend_from_slice(WAI1_MAGIC);
    out.extend_from_slice(&man_len.to_le_bytes());
    out.extend_from_slice(&manifest_bytes);
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn decode_wai1_envelope(data: &[u8]) -> Result<Wai1DecodedEnvelope, Wai1Error> {
    if data.len() < 8 {
        return Err(Wai1Error::new(
            "container_truncated",
            format!("Container shorter than 8 bytes ({})", data.len()),
        ));
    }
    if &data[0..4] != WAI1_MAGIC {
        return Err(Wai1Error::new(
            "invalid_magic",
            "First 4 bytes must be ASCII 'WAI1'",
        ));
    }

    let man_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    // SPEC.md §2: refuse past 2^27 from `man_len` alone BEFORE reading manifest!
    if man_len > MAX_MANIFEST_BYTES {
        return Err(Wai1Error::new(
            "manifest_too_large",
            format!("man_len {man_len} exceeds 2^27"),
        ));
    }
    if data.len() < 12 || data.len() < 8 + man_len + 4 {
        return Err(Wai1Error::new(
            "container_truncated",
            "Container truncated inside manifest or payload_len",
        ));
    }

    let manifest_slice = &data[8..8 + man_len];
    let manifest_text = std::str::from_utf8(manifest_slice)
        .map_err(|_| Wai1Error::new("manifest_invalid_utf8", "Manifest is not valid UTF-8"))?;

    let strict_root = StrictWaiJsonParser::new(manifest_text).parse()?;
    validate_wai1_manifest_strict(&strict_root)?;
    let manifest = strict_root.to_serde_value();

    let pl_off = 8 + man_len;
    let payload_len = u32::from_le_bytes([
        data[pl_off],
        data[pl_off + 1],
        data[pl_off + 2],
        data[pl_off + 3],
    ]) as usize;
    let payload_start = pl_off + 4;
    let expected_total = payload_start
        .checked_add(payload_len)
        .ok_or_else(|| Wai1Error::new("payload_length_mismatch", "Overflow"))?;
    if data.len() != expected_total {
        return Err(Wai1Error::new(
            "payload_length_mismatch",
            format!(
                "Expected {expected_total} container bytes from payload_len={payload_len}, got {}",
                data.len()
            ),
        ));
    }

    let raw_payload = data[payload_start..expected_total].to_vec();
    let cap = manifest["model_requirement"]["capability"]
        .as_str()
        .unwrap_or("");
    let decoded_payload = if cap == "wai.text.zstd" {
        Some(zstd_decode_bounded(&raw_payload)?)
    } else {
        None
    };

    Ok(Wai1DecodedEnvelope {
        manifest,
        manifest_bytes: manifest_slice.to_vec(),
        raw_payload,
        decoded_payload,
        envelope_blake3: blake3_hex(data),
        envelope_bytes: data.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_manifest() -> Value {
        json!({
            "wai": "1.0",
            "media": "text",
            "intent": "replicate",
            "model_requirement": {
                "capability": "wai.text.zstd",
                "fallback": null
            },
            "conditioning": {
                "kind": "zstd"
            },
            "security": {
                "encryption": "none",
                "kid": 0
            },
            "target": {
                "uncompressed_bytes": 29
            }
        })
    }

    #[test]
    fn wai1_roundtrip_zstd_and_hashes_match() {
        let pt = b"OpenIE canonical WAI1 payload";
        let zstd = zstd_encode_deterministic(pt).expect("zstd encode");
        let man = sample_manifest();
        let bytes = encode_wai1_envelope(&man, &zstd).expect("wai1 encode");
        assert_eq!(&bytes[0..4], b"WAI1");

        let dec = decode_wai1_envelope(&bytes).expect("wai1 decode");
        assert_eq!(dec.decoded_payload.as_deref(), Some(&pt[..]));
        assert_eq!(dec.envelope_bytes, bytes.len());
        assert_eq!(dec.envelope_blake3, blake3_hex(&bytes));
    }

    #[test]
    fn wai1_rejects_bad_magic_whitespace_duplicate_keys_and_non_strict_integers() {
        let pt = zstd_encode_deterministic(b"abc").unwrap();

        // 1. Bad magic ("WAI2")
        let mut bad = encode_wai1_envelope(&sample_manifest(), &pt).unwrap();
        bad[3] = b'2';
        assert_eq!(decode_wai1_envelope(&bad).unwrap_err().code, "invalid_magic");

        // 2. man_len > 2^27 rejected immediately from header without needing body
        let mut huge_hdr = Vec::new();
        huge_hdr.extend_from_slice(b"WAI1");
        huge_hdr.extend_from_slice(&((MAX_MANIFEST_BYTES as u32) + 1).to_le_bytes());
        huge_hdr.extend_from_slice(&[0u8; 16]);
        assert_eq!(
            decode_wai1_envelope(&huge_hdr).unwrap_err().code,
            "manifest_too_large"
        );

        // Helper to craft raw wire container with custom manifest string
        let make_raw = |m_str: &str| -> Vec<u8> {
            let mut v = Vec::new();
            v.extend_from_slice(b"WAI1");
            v.extend_from_slice(&(m_str.len() as u32).to_le_bytes());
            v.extend_from_slice(m_str.as_bytes());
            v.extend_from_slice(&(pt.len() as u32).to_le_bytes());
            v.extend_from_slice(&pt);
            v
        };

        // 3. Insignificant whitespace rejected
        let ws_man = "{\"wai\": \"1.0\",\"media\":\"text\",\"intent\":\"replicate\",\"model_requirement\":{\"capability\":\"wai.text.zstd\",\"fallback\":null},\"conditioning\":{\"kind\":\"zstd\"}}";
        assert_eq!(
            decode_wai1_envelope(&make_raw(ws_man)).unwrap_err().code,
            "manifest_whitespace"
        );

        // 4. Duplicate key via unicode escape (\u0077ai == wai) rejected!
        let dup_man = "{\"wai\":\"1.0\",\"\\u0077ai\":\"1.0\",\"media\":\"text\",\"intent\":\"replicate\",\"model_requirement\":{\"capability\":\"wai.text.zstd\",\"fallback\":null},\"conditioning\":{\"kind\":\"zstd\"}}";
        assert_eq!(
            decode_wai1_envelope(&make_raw(dup_man)).unwrap_err().code,
            "manifest_duplicate_member"
        );

        // 5. Strict integer check rejects -0, 1.0, and 1e0 in security.kid!
        for bad_int in ["-0", "1.0", "1e0"] {
            let m = format!(
                "{{\"wai\":\"1.0\",\"media\":\"text\",\"intent\":\"replicate\",\"model_requirement\":{{\"capability\":\"wai.text.zstd\",\"fallback\":null}},\"conditioning\":{{\"kind\":\"zstd\"}},\"security\":{{\"encryption\":\"none\",\"kid\":{bad_int}}}}}"
            );
            assert_eq!(
                decode_wai1_envelope(&make_raw(&m)).unwrap_err().code,
                "manifest_non_integer",
                "failed to reject {bad_int}"
            );
        }
    }

    #[test]
    fn blake3_multi_chunk_vectors_match_python_exactly() {
        let cases = [
            (0usize, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
            (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"),
            (63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"),
            (64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"),
            (65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"),
            (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"),
            (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"),
            (2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"),
            (8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63"),
        ];
        for (len, expected) in cases {
            let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            assert_eq!(blake3_hex(&input), expected, "mismatch at len={len}");
        }
    }

    #[test]
    fn jcs_number_and_ed25519_signing_roundtrip() {
        assert_eq!(format_jcs_f64(0.0).unwrap(), "0");
        assert_eq!(format_jcs_f64(-0.0).unwrap(), "0");
        assert_eq!(format_jcs_f64(1.0).unwrap(), "1");
        assert_eq!(format_jcs_f64(9.273e-4).unwrap(), "0.0009273");
        assert_eq!(format_jcs_f64(1e-7).unwrap(), "1e-7");
        assert_eq!(format_jcs_f64(3.4831896e20).unwrap(), "348318960000000000000");
        assert_eq!(format_jcs_f64(3.4831896e21).unwrap(), "3.4831896e+21");

        let seed = derive_default_signing_seed();
        let mut art = json!({
            "canonical_id": format!("blake3:paper:{}", "a".repeat(64)),
            "provenance_chain": {
                "content_blake3": "a".repeat(64),
                "sha256": "b".repeat(64),
                "ed25519_pubkey": "",
                "ed25519_sig": "",
                "tx_time_utc": "2026-11-24T12:00:00Z",
                "lineage_parents": [],
                "anchors": {}
            }
        });
        sign_canonical_artifact(&mut art, &seed).unwrap();
        assert!(verify_canonical_artifact_signature(&art).unwrap());

        // Tampering invalidates signature
        art["provenance_chain"]["tx_time_utc"] = Value::String("2026-11-24T12:00:01Z".to_string());
        assert!(!verify_canonical_artifact_signature(&art).unwrap());
    }
}
