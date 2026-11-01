#!/usr/bin/env bash
# upgrade-p30.sh — Automates Protocol 30 upgrade execution (Issue #37)
#
# Prerequisite: Cooldown window must have elapsed (2026-11-03T21:30:21Z).
# Runbook reference: ARCHITECTURE §12, docs/site/status.md.

set -euo pipefail

TARGET_DATE="2026-11-03T21:30:21Z"
TARGET_EPOCH=$(date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$TARGET_DATE" +%s 2>/dev/null || date -u -d "$TARGET_DATE" +%s)
CURRENT_EPOCH=$(date -u +%s)

echo "=== SoroSentinel Intel Protocol 30 Upgrade Helper ==="
echo "Target cooldown eligibility: $TARGET_DATE (epoch: $TARGET_EPOCH)"
echo "Current system time:         $(date -u +"%Y-%m-%dT%H:%M:%SZ") (epoch: $CURRENT_EPOCH)"

if [ "$CURRENT_EPOCH" -lt "$TARGET_EPOCH" ]; then
  DIFF=$((TARGET_EPOCH - CURRENT_EPOCH))
  HOURS=$((DIFF / 3600))
  MINUTES=$(((DIFF % 3600) / 60))
  echo ""
  echo "[-] ERROR: Cooldown period has not elapsed yet per AGENTS.md §6."
  echo "    Eligible in: ${HOURS}h ${MINUTES}m (at ${TARGET_DATE})."
  echo "    Do not bypass without maintainer written approval."
  exit 1
fi

echo "[+] Cooldown cleared. Proceeding with Protocol 30 upgrade..."

cd "$(dirname "$0")/.."

echo "[+] Bumping go-stellar-sdk to v0.8.0..."
go get github.com/stellar/go-stellar-sdk@v0.8.0
go mod tidy

echo "[+] Updating MaxProtocol to 30 in xdrcompat..."
sed -i '' 's/const MaxProtocol = 29/const MaxProtocol = 30/' internal/ingest/xdrcompat/xdrcompat.go

echo "[+] Running test suite and verification..."
make verify

echo "[+] Protocol 30 upgrade verified successfully!"
