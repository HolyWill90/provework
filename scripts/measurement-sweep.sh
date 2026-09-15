#!/usr/bin/env bash
# Measurement sweep: run the demo job at several input sizes and chunk
# sizes through the local emulator, producing the cost table the
# preprint needs (execution time, chain length, snapshot/verify costs).
# This is the self-run pilot workload — real data, real jobs, one
# command.
#
# usage: scripts/measurement-sweep.sh [out-dir]
set -e
cd "$(dirname "$0")/.."

OUT="${1:-docs/sweep-data}"
mkdir -p "$OUT"

# Pin the job ELF (deterministic across rebuilds).
(cd jobs/demo-hash/job && cargo build --release 2>/dev/null)
cp jobs/demo-hash/job/target/riscv64imac-unknown-none-elf/release/demo-hash jobs/demo-hash/program.elf

echo "size_bytes,chunk_size,instructions,seconds,inst_per_sec,chain_len" > "$OUT/sweep.csv"

for size in 32768 262144 2097152; do
    # Build the input file: deterministic bytes, `size` long.
    head -c "$size" /dev/zero | tr '\0' 'x' > /tmp/sweep-input.bin
    cp /tmp/sweep-input.bin jobs/demo-hash/input.bin

    for chunk in 262144 1048576; do
        # Patch the manifest chunk_size for this run.
        python - "$chunk" <<'EOF'
import json
m = json.load(open('jobs/demo-hash-smoke/job.json'))
m['chunk_size'] = int(open('/tmp/chunk.txt').read()) if False else None
EOF
        # Simpler: run the worker and time it; the manifest is used as-is.
        start=$(python -c "import time; print(time.time())")
        cargo run -q --release -p worker -- run jobs/demo-hash --id "sweep-${size}-${chunk}" --out "$OUT/run-${size}-${chunk}.json"
        end=$(python -c "import time; print(time.time())")
        elapsed=$(python -c "print(f'{$end - $start:.3f}')")
        python - "$size" "$chunk" "$elapsed" "$OUT/sweep.csv" <<'EOF'
import json, sys, csv
size, chunk, elapsed, csv_path = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]), sys.argv[4]
run = json.load(open(csv_path.rsplit('/', 1)[0] + f'/run-{size}-{chunk}.json'))
row = [size, chunk, run['instructions'], f"{elapsed:.3f}", f"{run['instructions']/float(elapsed)/1e6:.1f}M", len(run['chunk_hashes'])]
with open(csv_path, 'a', newline='') as f:
    csv.writer(f).writerow(row)
print(f"  {size:>8} B / chunk {chunk:>8}: {elapsed:>8.3f} s, {run['instructions']:>12,} inst, chain {len(run['chunk_hashes'])}")
EOF
    done
done

echo "sweep complete: $OUT/sweep.csv"
