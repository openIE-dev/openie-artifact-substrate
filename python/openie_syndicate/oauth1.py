# SPDX-License-Identifier: Apache-2.0
"""RFC 5849 OAuth 1.0a HMAC-SHA1 signer and X (Twitter) weighted character counter.

Pure Python standard library implementation with zero external dependencies.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import time
import unicodedata
import urllib.parse
from dataclasses import dataclass
from typing import Sequence

X_TCO_URL_WEIGHT = 23
X_MAX_WEIGHTED_CHARS = 280

# Matches http:// or https:// URLs bounded by whitespace or string edges,
# excluding trailing sentence punctuation if not balanced inside the URL.
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def _trim_url_match(raw_url: str) -> tuple[str, str]:
    """Split trailing prose punctuation off a matched URL when unbalanced."""
    trailing = ""
    url = raw_url
    while url and url[-1] in ".,;:!?)":
        if url[-1] == ")" and url.count("(") >= url.count(")"):
            break
        trailing = url[-1] + trailing
        url = url[:-1]
    return url, trailing


def _codepoint_weight(cp: int) -> int:
    """Return X twitter-text v3 character weight (1 for Latin/punctuation, 2 for CJK/emoji)."""
    if (
        (0x0000 <= cp <= 0x10FF)
        or (0x2000 <= cp <= 0x200D)
        or (0x2010 <= cp <= 0x201F)
        or (0x2032 <= cp <= 0x2037)
    ):
        return 1
    return 2


def weighted_len(text: str) -> int:
    """Compute X's exact weighted character count (`https?://...` = 23 chars, NFC normalized)."""
    norm = unicodedata.normalize("NFC", text)
    total = 0
    cursor = 0
    for match in _URL_RE.finditer(norm):
        start, end = match.span()
        if start > cursor:
            total += sum(_codepoint_weight(ord(ch)) for ch in norm[cursor:start])
        url_part, trailing = _trim_url_match(match.group(0))
        if len(url_part) > len("https://"):
            total += X_TCO_URL_WEIGHT
        else:
            total += sum(_codepoint_weight(ord(ch)) for ch in url_part)
        if trailing:
            total += sum(_codepoint_weight(ord(ch)) for ch in trailing)
        cursor = end
    if cursor < len(norm):
        total += sum(_codepoint_weight(ord(ch)) for ch in norm[cursor:])
    return total


def extract_urls(text: str) -> list[str]:
    """Extract all HTTP(S) URLs from `text`."""
    norm = unicodedata.normalize("NFC", text)
    urls: list[str] = []
    for match in _URL_RE.finditer(norm):
        url_part, _ = _trim_url_match(match.group(0))
        if len(url_part) > len("https://"):
            urls.append(url_part)
    return urls


# ---------------------------------------------------------------------------
# RFC 5849 OAuth 1.0a HMAC-SHA1 Signer
# ---------------------------------------------------------------------------


def percent_encode(val: str) -> str:
    """RFC 5849 §3.6 percent-encoding (`ALPHA`, `DIGIT`, `-`, `.`, `_`, `~` unescaped)."""
    return urllib.parse.quote(str(val).encode("utf-8"), safe="-._~")


def normalize_base_uri(url: str) -> str:
    """RFC 5849 §3.4.1.2 Base String URI normalization."""
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    if not scheme or not parsed.hostname:
        raise ValueError(f"Invalid OAuth 1.0a request URL: {url!r}")
    host = parsed.hostname.lower()
    port = parsed.port
    if port is not None and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        authority = f"{host}:{port}"
    else:
        authority = host
    path = parsed.path or "/"
    return f"{scheme}://{authority}{path}"


def collect_query_params(url: str) -> list[tuple[str, str]]:
    """Decode query parameters from `url` per RFC 5849 §3.4.1.3.1."""
    parsed = urllib.parse.urlsplit(url)
    if not parsed.query:
        return []
    out: list[tuple[str, str]] = []
    for part in parsed.query.split("&"):
        if "=" in part:
            k_raw, v_raw = part.split("=", 1)
        else:
            k_raw, v_raw = part, ""
        # Query strings decode '+' as space per x-www-form-urlencoded rules in RFC 5849 §3.4.1.3.1
        k = urllib.parse.unquote_plus(k_raw)
        v = urllib.parse.unquote_plus(v_raw)
        out.append((k, v))
    return out


def parse_form_urlencoded(body: str) -> list[tuple[str, str]]:
    """Decode `application/x-www-form-urlencoded` body per RFC 5849 §3.4.1.3.1."""
    if not body:
        return []
    out: list[tuple[str, str]] = []
    for part in body.split("&"):
        if "=" in part:
            k_raw, v_raw = part.split("=", 1)
        else:
            k_raw, v_raw = part, ""
        out.append((urllib.parse.unquote_plus(k_raw), urllib.parse.unquote_plus(v_raw)))
    return out


def normalize_parameters(params: Sequence[tuple[str, str]]) -> str:
    """RFC 5849 §3.4.1.3.2 Parameter Normalization."""
    encoded = [
        (percent_encode(k), percent_encode(v))
        for k, v in params
        if k != "oauth_signature"
    ]
    encoded.sort(key=lambda kv: (kv[0], kv[1]))
    return "&".join(f"{k}={v}" for k, v in encoded)


def build_signature_base_string(
    method: str,
    url: str,
    oauth_params: Sequence[tuple[str, str]],
    body_form_params: Sequence[tuple[str, str]] = (),
) -> str:
    """RFC 5849 §3.4.1.1 Signature Base String construction."""
    query_params = collect_query_params(url)
    merged: list[tuple[str, str]] = []
    merged.extend(query_params)
    merged.extend(oauth_params)
    merged.extend(body_form_params)
    base_uri = normalize_base_uri(url)
    norm_params = normalize_parameters(merged)
    return "&".join(
        [
            percent_encode(method.upper()),
            percent_encode(base_uri),
            percent_encode(norm_params),
        ]
    )


def sign_hmac_sha1(
    base_string: str, client_secret: str, token_secret: str = ""
) -> str:
    """RFC 5849 §3.4.2 HMAC-SHA1 signature in Base64."""
    signing_key = f"{percent_encode(client_secret)}&{percent_encode(token_secret)}"
    digest = hmac.new(
        signing_key.encode("ascii"),
        base_string.encode("ascii"),
        hashlib.sha1,
    ).digest()
    return base64.b64encode(digest).decode("ascii")


@dataclass(frozen=True)
class OAuth1Credentials:
    """Runtime OAuth 1.0a credentials loaded from environment variables."""

    api_key: str
    api_secret: str
    access_token: str
    access_token_secret: str

    @classmethod
    def from_env(cls) -> OAuth1Credentials:
        return cls(
            api_key=os.environ.get("X_API_KEY", ""),
            api_secret=os.environ.get("X_API_SECRET", ""),
            access_token=os.environ.get("X_ACCESS_TOKEN", ""),
            access_token_secret=os.environ.get("X_ACCESS_TOKEN_SECRET", ""),
        )

    def is_configured(self) -> bool:
        return all(
            (
                self.api_key,
                self.api_secret,
                self.access_token,
                self.access_token_secret,
            )
        )


def build_oauth1_authorization_header(
    *,
    method: str,
    url: str,
    credentials: OAuth1Credentials,
    body_form_params: Sequence[tuple[str, str]] = (),
    timestamp: str | None = None,
    nonce: str | None = None,
    version: str | None = "1.0",
    realm: str | None = None,
) -> str:
    """Construct an RFC 5849 §3.5.1 `Authorization: OAuth ...` header."""
    ts = timestamp if timestamp is not None else str(int(time.time()))
    nc = nonce if nonce is not None else secrets.token_hex(16)
    oauth_params: list[tuple[str, str]] = [
        ("oauth_consumer_key", credentials.api_key),
        ("oauth_nonce", nc),
        ("oauth_signature_method", "HMAC-SHA1"),
        ("oauth_timestamp", ts),
        ("oauth_token", credentials.access_token),
    ]
    if version is not None:
        oauth_params.append(("oauth_version", version))

    base_str = build_signature_base_string(
        method=method,
        url=url,
        oauth_params=oauth_params,
        body_form_params=body_form_params,
    )
    sig = sign_hmac_sha1(
        base_str,
        client_secret=credentials.api_secret,
        token_secret=credentials.access_token_secret,
    )
    header_items: list[tuple[str, str]] = []
    if realm is not None:
        header_items.append(("realm", realm))
    header_items.extend(sorted(oauth_params, key=lambda kv: kv[0]))
    header_items.append(("oauth_signature", sig))
    formatted = ", ".join(
        f'{percent_encode(k)}="{percent_encode(v)}"' for k, v in header_items
    )
    return f"OAuth {formatted}"
