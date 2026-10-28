#!/usr/bin/env bash
# One-command local demo on TESTNET (docs/runbooks/local-demo.md):
#   1. start the local Intel stack (deploy/docker-compose.yml) via Docker/Colima
#   2. issue a look-alike USDC on testnet with throwaway Friendbot accounts
#   3. wait until intel-worker publishes a signed snapshot containing it
#   4. look the asset up through the read API
#   5. run Guard's examples/analyze-transaction on an unsigned trustline
#      transaction to it (and a control to the reference issuer)
#
# Testnet only: the worker is fixed to testnet and the RPC endpoint must
# report the testnet passphrase. The snapshot signing key is a throwaway test
# key generated inside the stack. No secret key is printed; the addresses
# shown are throwaway testnet accounts. Containers and volumes it started are
# removed on exit unless DEMO_KEEP_STACK=1.
#
# Env: GUARD_REPO (default ../Sorosentinel-guard next to this checkout),
#      INTEL_API_PORT (18080), INTEL_RPC_URL (testnet default),
#      DEMO_SNAPSHOT_TIMEOUT seconds (420), DEMO_KEEP_STACK (unset).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# From a git worktree, the sibling repos sit next to the main checkout.
COMMON="$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || echo "$ROOT/.git")"
GUARD_REPO="${GUARD_REPO:-$(dirname "$COMMON")/../Sorosentinel-guard}"
EXAMPLE="$GUARD_REPO/examples/analyze-transaction/analyze.mts"

export INTEL_RPC_URL="${INTEL_RPC_URL:-https://soroban-testnet.stellar.org}"
export INTEL_API_PORT="${INTEL_API_PORT:-18080}"
export INTEL_SIGNING_KEY_ID="demo-test-key"
export INTEL_SNAPSHOT_INTERVAL="${INTEL_SNAPSHOT_INTERVAL:-30s}"
SNAPSHOT_TIMEOUT="${DEMO_SNAPSHOT_TIMEOUT:-420}"
API="http://127.0.0.1:$INTEL_API_PORT"
TESTNET_PASSPHRASE="Test SDF Network ; September 2015"

step() { printf '\n==> %s\n' "$*"; }
die() { printf 'demo: %s\n' "$*" >&2; exit 1; }

# --- prerequisites -----------------------------------------------------------
step "[1/7] Checking prerequisites"
for bin in docker node curl openssl shasum; do
  command -v "$bin" >/dev/null || die "$bin is required (see docs/runbooks/local-demo.md)"
done
if docker compose version >/dev/null 2>&1; then COMPOSE_BIN=(docker compose)
elif command -v docker-compose >/dev/null; then COMPOSE_BIN=(docker-compose)
else die "Docker Compose is required"; fi
node -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a>23||(a===23&&b>=6)?0:1)' \
  || die "Node 23.6 or newer is required (Guard runs through Node's type stripping)"
[ -f "$EXAMPLE" ] || die "Guard example not found at $EXAMPLE (set GUARD_REPO)"
[ -d "$GUARD_REPO/packages/core/node_modules/@stellar/stellar-sdk" ] \
  || die "run 'pnpm install' in $GUARD_REPO first"
if ! docker info >/dev/null 2>&1; then
  command -v colima >/dev/null || die "Docker is not running and Colima is not installed"
  echo "Docker is not running; starting Colima"
  colima start
fi

rpc() { curl -fsS --max-time 20 -X POST "$INTEL_RPC_URL" -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\"}"; }
json() { node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const v=new Function("o","return o"+process.argv[1])(JSON.parse(s));console.log(typeof v==="string"?v:JSON.stringify(v))})' "$1"; }

[ "$(rpc getNetwork | json .result.passphrase)" = "$TESTNET_PASSPHRASE" ] \
  || die "$INTEL_RPC_URL is not a testnet RPC endpoint; this demo runs on testnet only"
echo "RPC $INTEL_RPC_URL is testnet"

# --- stack -------------------------------------------------------------------
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sorosentinel-demo.XXXXXX")" # public data only
export INTEL_DB_PASSWORD="$(openssl rand -hex 16)"                # throwaway, never printed
export INTEL_START_LEDGER="$(rpc getLatestLedger | json .result.sequence)"
compose() { "${COMPOSE_BIN[@]}" -f "$ROOT/deploy/docker-compose.yml" "$@"; }

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo; echo "demo failed; last worker log lines (counts only, no addresses):"
    compose logs --no-color --tail 15 intel-worker 2>/dev/null || true
  fi
  if [ -n "${DEMO_KEEP_STACK:-}" ]; then
    echo "DEMO_KEEP_STACK set: stack left running; stop it with:"
    echo "  ${COMPOSE_BIN[*]} -f deploy/docker-compose.yml down -v"
  else
    step "Cleaning up containers and volumes"
    compose --profile tools down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

step "[2/7] Building images and starting the Intel stack (worker from testnet ledger $INTEL_START_LEDGER)"
# Plain `docker build` (no buildx needed); retried because registry pulls can be flaky.
for img in intel-worker intel-api demo-tools; do
  for attempt in 1 2 3; do
    docker build -q -f "$ROOT/deploy/docker/Dockerfile.$img" -t "sorosentinel-$img:local" "$ROOT" >/dev/null 2>"$WORK/build.log" && break
    [ "$attempt" = 3 ] && { cat "$WORK/build.log" >&2; die "building $img failed"; }
    sleep 5
  done
done
compose up -d --no-build postgres migrate keygen intel-worker intel-api >"$WORK/up.log" 2>&1 \
  || { cat "$WORK/up.log" >&2; die "starting the stack failed"; }
compose ps --format '  {{.Service}}: {{.State}}' 2>/dev/null || compose ps
compose logs --no-color keygen | grep -o 'TEST-ONLY.*' || true

for _ in $(seq 60); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "$API/v1/snapshots/latest?network=testnet" || true)"
  [ "$code" = 200 ] || [ "$code" = 404 ] && break
  sleep 2
done
[ "$code" = 200 ] || [ "$code" = 404 ] || die "read API did not come up on $API"
echo "read API up on $API"

# --- look-alike --------------------------------------------------------------
step "[3/7] Issuing a look-alike USDC on testnet (throwaway Friendbot accounts)"
compose run --rm --no-deps demo-tools >"$WORK/issue.json" 2>"$WORK/issue.log" \
  || { grep -v ' Container ' "$WORK/issue.log" >&2; die "issuing the look-alike failed"; }
ISSUER="$(json .issuer <"$WORK/issue.json")"
json .lookalike_tx <"$WORK/issue.json" >"$WORK/lookalike.b64"
json .control_tx <"$WORK/issue.json" >"$WORK/control.b64"
echo "issuer:          $ISSUER (home_domain $(json .issuer_home_domain <"$WORK/issue.json"))"
echo "holder:          $(json .holder <"$WORK/issue.json") opened a USDC trustline in ledger $(json .trustline_ledger <"$WORK/issue.json")"
echo "signer:          $(json .signer <"$WORK/issue.json") (unsigned transactions only)"
echo "reference USDC:  $(json .reference_issuer <"$WORK/issue.json")"

# --- snapshot ----------------------------------------------------------------
ENTRY="$(printf 'testnet|asset|USDC:%s' "$ISSUER" | shasum -a 256 | cut -c1-32)"
step "[4/7] Waiting for a signed snapshot containing entry $ENTRY"
deadline=$((SECONDS + SNAPSHOT_TIMEOUT))
until curl -fsS "$API/v1/snapshots/latest?network=testnet" -o "$WORK/snapshot.json" 2>/dev/null \
  && grep -q "\"$ENTRY\"" "$WORK/snapshot.json"; do
  [ -n "$(compose ps -q --status running intel-worker)" ] || die "intel-worker stopped"
  [ "$SECONDS" -lt "$deadline" ] || die "no snapshot with the entry after ${SNAPSHOT_TIMEOUT}s"
  printf '.'
  sleep 5
done
echo
echo "snapshot version $(json .version <"$WORK/snapshot.json"), $(json '.entries.length' <"$WORK/snapshot.json") entries, key_id $(json .key_id <"$WORK/snapshot.json"), generated_at $(json .generated_at <"$WORK/snapshot.json")"

# --- read API ----------------------------------------------------------------
step "[5/7] Read API: GET /v1/entities/asset/USDC:<issuer>?network=testnet"
curl -fsS "$API/v1/entities/asset/USDC:$ISSUER?network=testnet" >"$WORK/entity.json"
node -e 'const fs=require("fs"); console.log(JSON.stringify(JSON.parse(fs.readFileSync(process.argv[1],"utf8")),null,2))' "$WORK/entity.json"

# --- Guard -------------------------------------------------------------------
docker cp "$(compose ps -aq keygen)":/data/keys/pubkey.hex "$WORK/pubkey.hex" >/dev/null
guard() { node --no-warnings "$EXAMPLE" --network testnet --snapshot "$WORK/snapshot.json" \
  --key-id "$INTEL_SIGNING_KEY_ID" --public-key "$(cat "$WORK/pubkey.hex")" --xdr-file "$1"; }

step "[6/7] Guard: unsigned trustline to the look-alike USDC (pinned key $(cut -c1-16 "$WORK/pubkey.hex")...)"
guard "$WORK/lookalike.b64" | tee "$WORK/guard-lookalike.txt"
step "[7/7] Guard control: unsigned trustline to the reference USDC issuer"
guard "$WORK/control.b64" | tee "$WORK/guard-control.txt"

grep -q '^status: findings_present' "$WORK/guard-lookalike.txt" && grep -q 'G-TRUST-FLAGGED' "$WORK/guard-lookalike.txt" \
  || die "Guard did not report G-TRUST-FLAGGED for the look-alike"
grep -q '^snapshot: verified' "$WORK/guard-lookalike.txt" || die "Guard did not verify the snapshot"
! grep -q 'G-TRUST-FLAGGED' "$WORK/guard-control.txt" || die "Guard flagged the reference issuer"

step "Summary"
cat <<EOF
network:              testnet
look-alike asset:     USDC:$ISSUER
snapshot:             version $(json .version <"$WORK/snapshot.json"), entry $ENTRY, signed by test key $INTEL_SIGNING_KEY_ID
read API signal:      $(json .signal_level <"$WORK/entity.json")
Guard (look-alike):   $(grep '^status:' "$WORK/guard-lookalike.txt" | cut -d' ' -f2), $(grep -o 'G-TRUST-FLAGGED' "$WORK/guard-lookalike.txt" | head -1), snapshot $(grep '^snapshot:' "$WORK/guard-lookalike.txt" | cut -d' ' -f2)
Guard (control):      $(grep '^status:' "$WORK/guard-control.txt" | cut -d' ' -f2), no G-TRUST-FLAGGED, snapshot $(grep '^snapshot:' "$WORK/guard-control.txt" | cut -d' ' -f2)
EOF
