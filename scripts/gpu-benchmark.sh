#!/usr/bin/env bash
# provework GPU proving benchmark — self-contained for a fresh Ubuntu
# CUDA box (tested path: RunPod RTX 4090 / PyTorch template, root).
# One command:  curl -sSL https://raw.githubusercontent.com/HolyWill90/provework/main/scripts/gpu-benchmark.sh | bash
# Measures BOTH formats with VRAM logging and prints a copy-paste summary.
set -uo pipefail

echo "=== 0. GPU ==="
nvidia-smi || { echo "FATAL: no GPU visible"; exit 1; }

echo "=== 1. toolchain (~3 min) ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq git protobuf-compiler curl build-essential > /dev/null
curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.98.1 --profile minimal > /dev/null 2>&1
source "$HOME/.cargo/env"
rustup target add riscv64imac-unknown-none-elf > /dev/null 2>&1
echo "rust: $(rustc --version)"

echo "=== 2. clone + build cuda prover (~10 min on this box) ==="
cd /root
[ -d provework ] || git clone -q --depth 1 https://github.com/HolyWill90/provework
cd provework
git pull -q origin main 2>/dev/null || true
cargo build --release -p sp1-host --features cuda 2>&1 | tail -1
ls -la target/release/zk-judge || { echo "FATAL: judge build failed"; exit 1; }

echo "=== 3. libcudart (the driver only provides libcuda) ==="
cd /root
wget -q https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-cudart-12-6_12.6.77-1_amd64.deb
dpkg -x cuda-cudart-12-6_12.6.77-1_amd64.deb /root/cuda
echo /root/cuda/usr/local/cuda-12.6/targets/x86_64-linux/lib > /etc/ld.so.conf.d/cudart.conf
ldconfig
MISSING=$(ldd ~/.sp1/bin/sp1-gpu-server 2>/dev/null | grep -c 'not found' || true)
echo "missing libs after install: $MISSING (want 0)"

bench () {
  local NAME="$1" JOBDIR="$2" CYCLES="$3" TIMEOUT="$4" LOG="$5" VLOG="$6"
  echo "=== bench: $NAME ==="
  mkdir -p "$JOBDIR"
  nvidia-smi --query-gpu=memory.used,utilization.gpu --format=csv -l 5 > "$VLOG" 2>&1 &
  local MON=$!
  local T0=$(date +%s)
  SP1_PROVER=cuda timeout "$TIMEOUT" provework/target/release/zk-judge "$JOBDIR" "$CYCLES" provework/elf/sp1-guest-emu "/root/receipt-$NAME.bin" 2>&1 | tail -2
  local RC=$?
  kill $MON 2>/dev/null
  echo "[$NAME] exit=$RC wall=$(( $(date +%s) - T0 ))s"
  echo "[$NAME] peak VRAM:"; sort -t, -k1 -rn "$VLOG" | head -2
}

echo "=== 4. benchmark 1: V2 native (~1.8M cycles) ==="
mkdir -p /tmp/v2j
cp provework/jobs/demo-v2/job.json provework/jobs/demo-v2/input.bin provework/jobs/demo-v2/program.elf /tmp/v2j/
bench "v2" /tmp/v2j 10000000 1800 /root/v2.log /root/vram-v2.log

echo "=== 5. benchmark 2: legacy meta-emulated (~169M cycles; OOMed a 32 GB CPU) ==="
mkdir -p /tmp/legj
cp provework/jobs/demo-hash-smoke/job.json provework/jobs/demo-hash-smoke/input.bin provework/jobs/demo-hash-smoke/program.elf /tmp/legj/
bench "legacy" /tmp/legj 10000000000 3600 /root/legacy.log /root/vram-legacy.log

echo ""
echo "================ COPY FROM HERE ================"
echo "GPU: $(nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader)"
echo "--- [v2] full verdict:"
tail -3 /root/v2.log 2>/dev/null
echo "--- [legacy] full verdict:"
tail -3 /root/legacy.log 2>/dev/null
echo "--- peak VRAM v2:     $(sort -t, -k1 -rn /root/vram-v2.log 2>/dev/null | head -1)"
echo "--- peak VRAM legacy: $(sort -t, -k1 -rn /root/vram-legacy.log 2>/dev/null | head -1)"
echo "================ COPY TO HERE =================="
