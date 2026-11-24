#!/usr/bin/env bash
# release.sh — universal OpenIE Artifact Substrate release ceremony
#
# Validates the full unsiloed catalog (Python conformance suite + cross-language
# verification receipt), packages a deterministic GNU tarball, wraps the
# canonical catalog in a conforming WAI1 binary container + Ed25519 JWP receipt,
# and emits SHA256SUMS + BLAKE3SUMS.
#
# Usage:
#   ./release.sh <version-tag> [--dry-run]

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: $0 <version-tag> [--dry-run]"
  echo "example: $0 2026.11.24 --dry-run"
  exit 1
fi

VERSION="$1"
DRY_RUN=0
if [ "${2:-}" = "--dry-run" ]; then
  DRY_RUN=1
  echo "[dry-run mode: will build deterministic tarball and WAI1 substrate envelope, skip TSA submissions and git tag]"
fi

if ! echo "$VERSION" | grep -Eq '^v?[0-9]{4}\.(Q[1-4]|[0-9]{2}\.[0-9]{2})$|^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "ERROR: version tag '$VERSION' should match YYYY.QN, YYYY.MM.DD, or vX.Y.Z"
  exit 1
fi

RELEASE_DIR="releases/${VERSION}"
TARBALL_NAME="substrate-${VERSION}.tar.gz"
TARBALL_PATH="${RELEASE_DIR}/${TARBALL_NAME}"
WAI_NAME="substrate-${VERSION}.wai"
WAI_PATH="${RELEASE_DIR}/${WAI_NAME}"

echo "=== Preflight checks ==="

need_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: required tool '$1' not found in PATH"
    exit 1
  fi
}
need_tool python3
need_tool openssl
need_tool curl
need_tool sha256sum
need_tool git

if command -v gtar >/dev/null 2>&1; then
  TAR=gtar
elif tar --version 2>/dev/null | grep -q "GNU tar"; then
  TAR=tar
else
  echo "ERROR: GNU tar required (bsdtar lacks --sort)."
  exit 1
fi

for req in Cargo.toml pyproject.toml schema/openie-artifact-v1.schema.json catalog/unsiloed-artifacts.jsonl catalog/verification-receipt.json; do
  if [ ! -f "$req" ]; then
    echo "ERROR: required substrate file '$req' not found. Run from repo root."
    exit 1
  fi
done

if [ "$DRY_RUN" -eq 0 ]; then
  need_tool ots
  if ! git diff --quiet HEAD 2>/dev/null; then
    echo "ERROR: working tree has uncommitted changes."
    git status --short
    exit 1
  fi
  if git rev-parse "$VERSION" >/dev/null 2>&1; then
    echo "ERROR: tag '$VERSION' already exists."
    exit 1
  fi
  if [ -d "$RELEASE_DIR" ]; then
    echo "ERROR: $RELEASE_DIR already exists."
    exit 1
  fi
fi

echo "  Preflight OK."

echo ""
echo "=== Step 1: validate schema, gates, and unsiloed catalog ==="
PYTHONPATH=python python3 -m unittest discover -s tests
echo "  Conformance & adversarial gate suite passed."

echo ""
echo "=== Step 2: build deterministic GNU tarball ==="
mkdir -p "$RELEASE_DIR"

case "$VERSION" in
  *.Q1) MTIME="${VERSION%.Q1}-01-01" ;;
  *.Q2) MTIME="${VERSION%.Q2}-04-01" ;;
  *.Q3) MTIME="${VERSION%.Q3}-07-01" ;;
  *.Q4) MTIME="${VERSION%.Q4}-10-01" ;;
  *.[0-9][0-9].[0-9][0-9]) MTIME=$(echo "${VERSION#v}" | tr '.' '-') ;;
  v*) MTIME="2026-01-01" ;;
  *) MTIME="2026-01-01" ;;
esac

TAR_INPUTS=(
  Cargo.toml
  pyproject.toml
  LICENSE
  LICENSING_HYGIENE.md
  README.md
  schema/
  crates/
  python/
  scripts/
  tests/
  catalog/
)
if [ -f Cargo.lock ]; then
  TAR_INPUTS+=(Cargo.lock)
fi

$TAR --use-compress-program='gzip -n' -cf "$TARBALL_PATH" \
  --sort=name \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --owner=0 --group=0 --numeric-owner \
  --mtime="${MTIME}T00:00:00Z" \
  --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
  "${TAR_INPUTS[@]}"

HASH=$(sha256sum "$TARBALL_PATH" | cut -d' ' -f1)
echo "  Tarball: ${TARBALL_PATH}"
echo "  SHA-256: ${HASH}"

echo ""
echo "=== Step 3: emit WAI1 substrate envelope, JWP receipt & Commons bundle ==="
EMIT_FLAGS=(
  --version "$VERSION"
  --release-dir "$RELEASE_DIR"
  --tarball "$TARBALL_PATH"
  --catalog "catalog/unsiloed-artifacts.jsonl"
  --timestamp "${MTIME}T00:00:00Z"
)
if [ "$DRY_RUN" -eq 1 ]; then
  EMIT_FLAGS+=(--dry-run)
fi
python3 scripts/emit_substrate_release.py "${EMIT_FLAGS[@]}"

TARBALL_B3=$(grep "  ${TARBALL_NAME}\$" "${RELEASE_DIR}/BLAKE3SUMS" | cut -d' ' -f1)
WAI_SHA=$(grep "  ${WAI_NAME}\$" "${RELEASE_DIR}/SHA256SUMS" | cut -d' ' -f1)
WAI_B3=$(grep "  ${WAI_NAME}\$" "${RELEASE_DIR}/BLAKE3SUMS" | cut -d' ' -f1)
RECEIPT_SHA=$(grep "  WAI_RECEIPT.json\$" "${RELEASE_DIR}/SHA256SUMS" | cut -d' ' -f1)
RECEIPT_B3=$(grep "  WAI_RECEIPT.json\$" "${RELEASE_DIR}/BLAKE3SUMS" | cut -d' ' -f1)
CAT_SHA=$(grep "  unsiloed-artifacts.jsonl\$" "${RELEASE_DIR}/SHA256SUMS" | cut -d' ' -f1)
CAT_B3=$(grep "  unsiloed-artifacts.jsonl\$" "${RELEASE_DIR}/BLAKE3SUMS" | cut -d' ' -f1)
COMMONS_SHA=$(grep "  commons_ingest_bundle.json\$" "${RELEASE_DIR}/SHA256SUMS" | cut -d' ' -f1)
COMMONS_B3=$(grep "  commons_ingest_bundle.json\$" "${RELEASE_DIR}/BLAKE3SUMS" | cut -d' ' -f1)
RECORDS=$(wc -l < "${RELEASE_DIR}/unsiloed-artifacts.jsonl" | tr -d ' ')

write_manifest() {
  local manifest_date="$1"
  cat > "${RELEASE_DIR}/MANIFEST.md" <<EOF
# OpenIE Artifact Substrate Release ${VERSION}

| | |
|---|---|
| Date (UTC) | ${manifest_date} |
| Tarball | \`${TARBALL_NAME}\` |
| Tarball SHA-256 | \`${HASH}\` |
| Tarball BLAKE3 | \`${TARBALL_B3}\` |
| WAI1 Envelope | \`${WAI_NAME}\` |
| WAI1 SHA-256 | \`${WAI_SHA}\` |
| WAI1 BLAKE3 | \`${WAI_B3}\` |
| Canonical Records | ${RECORDS} |

## Release artifacts & digests

| Artifact | SHA-256 | BLAKE3 |
|---|---|---|
| \`${TARBALL_NAME}\` | \`${HASH}\` | \`${TARBALL_B3}\` |
| \`unsiloed-artifacts.jsonl\` | \`${CAT_SHA}\` | \`${CAT_B3}\` |
| \`${WAI_NAME}\` | \`${WAI_SHA}\` | \`${WAI_B3}\` |
| \`WAI_RECEIPT.json\` | \`${RECEIPT_SHA}\` | \`${RECEIPT_B3}\` |
| \`commons_ingest_bundle.json\` | \`${COMMONS_SHA}\` | \`${COMMONS_B3}\` |
EOF
}

if [ "$DRY_RUN" -eq 1 ]; then
  write_manifest "${MTIME}T00:00:00Z"
  echo ""
  echo "=== Dry-run complete ==="
  echo "Tarball built at:      ${TARBALL_PATH}"
  echo "WAI1 envelope at:      ${WAI_PATH}"
  echo "Hashes recorded at:    ${RELEASE_DIR}/SHA256SUMS & ${RELEASE_DIR}/BLAKE3SUMS"
  echo "Manifest recorded at:  ${RELEASE_DIR}/MANIFEST.md"
  exit 0
fi

echo ""
echo "=== Step 4: RFC 3161 & OpenTimestamps anchoring ==="
openssl ts -query -data "$TARBALL_PATH" -sha256 -cert -no_nonce -out "${RELEASE_DIR}/request.tsq"
openssl ts -query -data "${RELEASE_DIR}/WAI_RECEIPT.json" -sha256 -cert -no_nonce -out "${RELEASE_DIR}/wai_receipt.tsq"
curl -sS --max-time 30 --fail -H "Content-Type: application/timestamp-query" --data-binary @"${RELEASE_DIR}/request.tsq" https://freetsa.org/tsr -o "${RELEASE_DIR}/freetsa.tsr" || rm -f "${RELEASE_DIR}/freetsa.tsr"
curl -sS --max-time 30 --fail -H "Content-Type: application/timestamp-query" --data-binary @"${RELEASE_DIR}/request.tsq" http://timestamp.digicert.com -o "${RELEASE_DIR}/digicert.tsr" || rm -f "${RELEASE_DIR}/digicert.tsr"
ots stamp "$TARBALL_PATH"
ots stamp "${RELEASE_DIR}/WAI_RECEIPT.json"
python3 scripts/emit_substrate_release.py --push-commons-only --version "$VERSION" --release-dir "$RELEASE_DIR"
write_manifest "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

git add "$RELEASE_DIR"
git commit -m "release: ${VERSION} (${RECORDS} canonical unsiloed artifacts)"
git tag -a "$VERSION" -m "OpenIE Artifact Substrate release ${VERSION}"
echo "  Tagged ${VERSION}."
