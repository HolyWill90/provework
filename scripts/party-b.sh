#!/usr/bin/env bash
# Party B — the executor: join a coordinator's fleet as an untrusted
# worker. Run this on the machine that WILL RUN the computation.
#
# usage: party-b.sh <coordinator-addr> [worker-id]
#   coordinator-addr  e.g. 203.0.113.7:7777 (Party A's public address)
#   worker-id         defaults to worker-<hostname>
set -e
cd "$(dirname "$0")/.."

SERVER="${1:?usage: party-b.sh <coordinator-addr> [worker-id]}"
ID="${2:-worker-$(hostname | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9' | cut -c1-12)}"

echo "== Party B: joining $SERVER as '$ID' (untrusted executor) =="
echo "   identity:  $ID.key  (created on first use)"
echo "   store:     ./$ID-store  (hash-verified blob cache)"
echo

cargo run --release -p worker -- daemon \
    --server "$SERVER" \
    --id "$ID" \
    --identity "$ID.key" \
    --store-dir "$ID-store"
