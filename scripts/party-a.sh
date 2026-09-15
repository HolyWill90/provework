#!/usr/bin/env bash
# Party A — the job owner: start a coordinator that accepts remote
# submissions and pays the ledger. Run this on the machine that WANTS
# the computation done.
#
# usage: party-a.sh [work-dir] [pool-size]
#   work-dir   defaults to ./provework-demo
#   pool-size  how many untrusted workers to wait for (default 2)
set -e
cd "$(dirname "$0")/.."

WORK="${1:-./provework-demo}"
POOL="${2:-2}"

mkdir -p "$WORK/jobs" "$WORK/store" "$WORK/results"

echo "== Party A: coordinator on 0.0.0.0:7777 (TLS, PoW, submissions on) =="
echo "   work dir:     $WORK"
echo "   ledger:       $WORK/ledger.json"
echo "   results:      $WORK/results/  (evidence per job)"
echo "   pool:         waiting for $POOL worker(s)"
echo

cargo run --release -p coordinator -- serve \
    --jobs-dir "$WORK/jobs" \
    --store "$WORK/store" \
    --ledger "$WORK/ledger.json" \
    --results-dir "$WORK/results" \
    --pool "$POOL" \
    --identity-pow-bits 22 \
    --tls \
    --accept-submissions
