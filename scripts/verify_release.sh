#!/usr/bin/env bash
# verify_release.sh — verify an OpenIE Artifact Substrate release offline
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: $0 <version-tag>"
  exit 1
fi

VERSION="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RELEASE_DIR="${REPO_ROOT}/releases/${VERSION}"

if [ ! -d "$RELEASE_DIR" ]; then
  echo "ERROR: $RELEASE_DIR not found."
  exit 1
fi

cd "$RELEASE_DIR"
echo "=== Verifying OpenIE Artifact Substrate release ${VERSION} ==="
sha256sum -c SHA256SUMS
python3 "${REPO_ROOT}/scripts/emit_substrate_release.py" --verify .
echo "=== Verification complete ==="
