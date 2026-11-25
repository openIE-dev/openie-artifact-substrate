#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Push changed `medium-live-status.json` directly to Cloudflare R2 (`blog.openie.dev`).

Pure Python standard library (`urllib.request`, `hashlib`, `json`, `os`, `pathlib`).
Zero-rebuild auto-hydration helper invoked by `openie-medium-x-sync.service`:
  - Reads `~/openie-syndicate/state/medium-live-status.json`
  - Resolves `CF_API_TOKEN` from process env, `~/.config/openie-radio/env`, or `~/.env`
  - If `CF_API_TOKEN` is absent, logs a clear message and exits `0` gracefully
  - Computes SHA-256 and skips upload if identical to `~/openie-syndicate/state/.last_r2_pushed_sha256`
    (unless `--force` is passed)
  - PUTs to Cloudflare R2 object `sites/blog-openie-web/syndication/medium-live-status.json`
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

DEFAULT_CF_ACCOUNT_ID = "7dadbd54ecf4252302933a4a8b011e56"
DEFAULT_R2_BUCKET = "openie-edge-sites"
DEFAULT_R2_OBJECT_KEY = "sites/blog-openie-web/syndication/medium-live-status.json"
DEFAULT_R2_ENDPOINT = (
    f"https://api.cloudflare.com/client/v4/accounts/{DEFAULT_CF_ACCOUNT_ID}"
    f"/r2/buckets/{DEFAULT_R2_BUCKET}/objects/{DEFAULT_R2_OBJECT_KEY}"
)

R2Transport = Callable[[str, str, dict[str, str], bytes], tuple[int, bytes]]


def _default_put_transport(
    method: str, url: str, headers: dict[str, str], body: bytes
) -> tuple[int, bytes]:
    req = urllib.request.Request(url=url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return int(resp.status), resp.read()
    except urllib.error.HTTPError as exc:
        err_bytes = exc.read() if exc.fp is not None else b""
        return int(exc.code), err_bytes


def _parse_dotenv_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in {"'", '"'}:
            val = val[1:-1]
        if key:
            values[key] = val
    return values


def resolve_cf_api_token(extra_env_files: list[Path] | None = None) -> str:
    """Resolve `CF_API_TOKEN` from environment or standard user env files."""
    direct = os.environ.get("CF_API_TOKEN", "").strip()
    if direct:
        return direct

    home = Path.home()
    candidates = extra_env_files if extra_env_files is not None else [
        home / ".config" / "openie-radio" / "env",
        home / ".env",
    ]
    for env_file in candidates:
        parsed = _parse_dotenv_file(env_file)
        tok = parsed.get("CF_API_TOKEN", "").strip()
        if tok:
            return tok
    return ""


def push_medium_status_to_r2(
    *,
    status_path: Path,
    stamp_path: Path,
    endpoint_url: str = DEFAULT_R2_ENDPOINT,
    cf_api_token: str | None = None,
    force: bool = False,
    transport: R2Transport | None = None,
) -> dict[str, object]:
    """Conditionally upload `medium-live-status.json` to Cloudflare R2."""
    token = cf_api_token.strip() if cf_api_token is not None else resolve_cf_api_token()
    if not token:
        return {
            "status": "skipped_no_token",
            "reason": "CF_API_TOKEN absent in environment and ~/.config/openie-radio/env / ~/.env",
        }

    if not status_path.is_file():
        return {
            "status": "skipped_missing_status_file",
            "status_path": str(status_path),
        }

    payload_bytes = status_path.read_bytes()
    doc = json.loads(payload_bytes.decode("utf-8"))
    if not isinstance(doc, dict) or doc.get("schema") != "openie.medium_live_status.v1":
        raise ValueError(f"Invalid schema in {status_path}: expected openie.medium_live_status.v1")

    digest = hashlib.sha256(payload_bytes).hexdigest()
    prev_digest = (
        stamp_path.read_text(encoding="utf-8").strip() if stamp_path.is_file() else ""
    )

    if not force and prev_digest == digest:
        return {
            "status": "skipped_unchanged",
            "sha256": digest,
            "live_medium_count": doc.get("live_medium_count", 0),
        }

    put_fn = transport or _default_put_transport
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "public, max-age=60",
        "User-Agent": "OpenIE-Syndicate-R2Push/1.0 (+https://blog.openie.dev)",
    }
    http_status, resp_body = put_fn("PUT", endpoint_url, headers, payload_bytes)
    if http_status < 200 or http_status >= 300:
        detail = resp_body.decode("utf-8", errors="replace")[:400]
        raise RuntimeError(f"Cloudflare R2 PUT failed with HTTP {http_status}: {detail}")

    stamp_path.parent.mkdir(parents=True, exist_ok=True)
    stamp_path.write_text(digest + "\n", encoding="utf-8")
    return {
        "status": "uploaded",
        "http_status": http_status,
        "sha256": digest,
        "live_medium_count": doc.get("live_medium_count", 0),
        "endpoint_url": endpoint_url,
    }


def main(argv: list[str] | None = None) -> int:
    default_state_dir = Path.home() / "openie-syndicate" / "state"
    parser = argparse.ArgumentParser(
        description="Push changed medium-live-status.json to Cloudflare R2 for zero-rebuild hydration."
    )
    parser.add_argument(
        "--status-file",
        type=Path,
        default=default_state_dir / "medium-live-status.json",
        help="Path to medium-live-status.json",
    )
    parser.add_argument(
        "--stamp-file",
        type=Path,
        default=default_state_dir / ".last_r2_pushed_sha256",
        help="Path to last uploaded SHA-256 stamp file",
    )
    parser.add_argument(
        "--endpoint-url",
        type=str,
        default=os.environ.get("OPENIE_MEDIUM_STATUS_R2_URL", DEFAULT_R2_ENDPOINT),
        help="Cloudflare R2 REST object endpoint URL",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Upload even if SHA-256 matches .last_r2_pushed_sha256",
    )
    args = parser.parse_args(argv)

    try:
        result = push_medium_status_to_r2(
            status_path=args.status_file,
            stamp_path=args.stamp_file,
            endpoint_url=args.endpoint_url,
            force=args.force,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[push_medium_status_r2] ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"[push_medium_status_r2] {json.dumps(result)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
