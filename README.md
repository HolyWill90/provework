# provework

[![CI](https://github.com/HolyWill90/provework/actions/workflows/ci.yml/badge.svg)](https://github.com/HolyWill90/provework/actions/workflows/ci.yml)

**An open-source experimental research engine and benchmark harness for
distributed verifiable compute.**

prowork is a working research instrument: a distributed network that
executes deterministic programs on untrusted machines and makes the
results verifiable at three selectable trust tiers — plus the harness
used to produce the first measured cost curves for zkVM-based
verification. It is published as a research artifact and benchmark
(v0.2.0), not as a product. Continuation of the
[p2p-compute](https://github.com/HolyWill90/p2p-compute) research
substrate (full history preserved).

## The measured numbers

Every figure below was measured on real hardware and is reproducible
from this repo — the full paper, with every claim mapped to a CI test
or logged run, is [docs/PREPRINT.md](docs/PREPRINT.md).

**Execution vs proving cost — same job, same input (demo fold over 32 KiB):**

| | zkVM cycles | execute | CPU prove (32 GB host) | GPU prove (32 GB Blackwell) |
|---|---|---|---|---|
| Legacy — emulator-in-guest | 168,881,446 | 2.5 s | **OOM** (> 32 GB) | **34.2 s** (26.1 GB VRAM) |
| **V2 — SP1-native** | **1,789,276** | ~2 s | **80.5 s** (15.7 GB) | **2.8 s** (10.6 GB VRAM) |

Key findings:

- **The meta-emulation tax is 322–362×.** Running a legacy-ABI program
  by embedding its interpreter inside the zkVM costs 322–362× the
  native cycle count — the measured price of binary-level
  compatibility, and it converts a compute problem into a
  memory-capacity problem (proving memory grows with the shard count).
- **A source-level native ABI (V2) removes it: 94× fewer cycles** —
  byte-identical output to the legacy path, turning a job that cannot
  be proved on a 32 GB CPU host into an 80-second CPU proof or a
  3-second GPU receipt.
- **GPU proving has a hard 24 GB VRAM floor** (measured refusal on a
  6 GB card; SP1 6.8). The 26.1 GB peak measured on the legacy job
  *explains* the floor — it is the honest minimum for traces of this
  shape.
- Native interpreter throughput: up to **57.7M instructions/s**
  (full sweep in `docs/sweep-data/`).

## What it is

- A distributed verification network over real TCP/TLS: a coordinator
  dispatches deterministic jobs to untrusted workers; every execution
  reduces to a **journal** (`u64_le instruction count ‖ output`),
  committed as `SHA-256(journal)`, verified at one of three tiers:
  1. **Quorum** (N=3→5) with bonded slashing and fraud detection,
  2. **Optimistic + dispute** — a judge (rvcore replay or zkVM)
     re-executes and reproduces the identical journal bytes; verdicts
     carry the judge's own output, never a worker's claim,
  3. **zk receipts** (SP1) — a proof replaces consensus entirely,
     produced by a content-keyed proving queue with deduplication and
     verifiable offline by anyone (`jobkit verify`).
- Two execution formats: **legacy** bare-metal RISC-V ABI (executed
  through the pinned emulator as the zkVM guest — zero-migration for
  existing ELFs) and **V2** SP1-native guests (compiled against
  `io::read`/`commit`, executed directly by the zkVM).
- A **benchmark harness** (the `jobkit` CLI) for the envelopes above,
  plus differential-determinism and conformance drivers (QEMU
  differential; official riscv-tests 67/67).

Network validation: demonstrated across three physical machines (two
different owners) and the open internet over TLS — including the
fraud case: a worker that fabricated a result was convicted by the
judge and slashed in the ledger (`docs/overview.html`).

## What it is not (honest status)

- **Not a product, and no commercial claim is made.** The repo is
  frozen as a research artifact at v0.2.0; the market search that
  preceded the freeze is recorded in `docs/DESIGN.md`.
- The coordinator is a single (trusted) party; no NAT traversal; peer
  discovery is coordinator-based.
- Jobs are deterministic integer-only programs — no floats, no I/O,
  no clocks — by design: the price of hashable execution.
- Receipts bind the exact SP1 toolchain version; upgrading re-keys
  verification. Multi-shard CPU proving is an open infrastructure gap.

## Reproducing the results

```bash
# 0. one-time setup: Rust (rustup), the RISC-V target, and this repo
curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable
source "$HOME/.cargo/env"
rustup target add riscv64imac-unknown-none-elf
git clone https://github.com/HolyWill90/provework && cd provework

# 1. run the unit + network test suite (quorum, fraud, receipts)
cargo test --workspace

# 2. benchmark: legacy vs V2 execution and proving (the numbers above)
cargo run --release -p jobkit -- new my-job            # legacy job
cargo run --release -p jobkit -- build my-job
cargo run --release -p jobkit -- new my-v2-job --v2    # SP1-native job
cargo run --release -p jobkit -- build my-v2-job       # auto-routes
#    through a pinned Docker toolchain when cargo-prove is absent

# 3. the two-party network: coordinator (terminal 1, blocks),
#    workers (terminal 2+), submission (terminal 3). First run
#    compiles for a few minutes.
./scripts/party-a.sh            # coordinator (TLS + admission PoW)
cp ./provework-demo/store/coordinator-cert.der .
./scripts/party-b.sh <coordinator-addr> worker-1 coordinator-cert.der
cargo run --release -p jobkit -- submit my-job \
    --server <coordinator-addr> --store ./p2pc-store \
    --identity submitter.key --server-cert coordinator-cert.der

# 4. evidence bundle + offline receipt verification
cargo run --release -p jobkit -- evidence \
    --results <results-dir> --job-id my-job-0001 --out evidence-bundle
cargo run --release -p jobkit -- verify --bundle evidence-bundle \
    --zk-verify sp1-host/target/release/zk-verify \
    --guest-elf elf/sp1-guest-emu --desc my-job/descriptor.json

# 5. high-assurance mode: receipt-backed outcome, no worker consensus
cargo run --release -p jobkit -- submit my-job --require-zk \
    --server <coordinator-addr> --store ./p2pc-store \
    --identity submitter.key --server-cert coordinator-cert.der
```

## Verification tiers

Every execution emits the journal described above; one journal, three
selectable tiers:

| Tier | Mechanism | Trust removed | Cost |
|---|---|---|---|
| Budget | Quorum, bond slashing, dispute judge | Workers agreeing on a fake result | ~N× |
| Standard | Optimistic acceptance + replay judgment | Same, at 1× unless challenged | ~1× |
| Strong | SP1 zkVM receipt over the emulator itself executing the actual job | Everything: no trust in any worker | prover tax |

**Execution engine.** Legacy (`rv-abi`) jobs run inside SP1's zkVM
through the pinned-emulator guest (`elf/sp1-guest-emu`, embedded at
build time): the job ELF keeps its sandbox ABI, the guest commits a
BLAKE3 binding of `(manifest, elf, input)` before executing, and
Windows dev builds run the same emulator natively. **V2
(`format: "sp1-v2"`) jobs are SP1-native guests** — executed directly
by the zkVM with no emulator in the loop; V2 output is byte-identical
to the legacy path's for the same input, and the rvcore replay judge
refuses V2 jobs (they are the zk judge's jurisdiction).

See `docs/PREPRINT.md` for the paper, `docs/DESIGN.md` for the
decision log (including the market-search record), `docs/INTEGRATION.md`
for the builder-facing interfaces, `docs/LICENSE-STRATEGY.md` for
licensing, and `docs/overview.html` for a visual briefing.

## Substrate

The verification engine is a pinned deterministic RISC-V (RV64IMC)
emulator: the entire architectural state is 32 registers + pc + machine
CSRs + memory, hashed after every fixed chunk of instructions. The
determinism contract and the job ABI are documented below — unchanged
from the research substrate.

<details>
<summary>Substrate details (determinism contract, job ABI, layout)</summary>

### Layout

```
crates/abi           job ABI: memory map, halt convention, pinned ISA string
crates/rvcore        the emulator: RV64IMC interpreter + chunk-hash chain (BLAKE3)
crates/jobfmt        job manifest/result formats, signing-message encoding
crates/jobkit        the harness CLI: scaffold / build / submit / evidence / verify
crates/worker        worker daemon + local runner (a "peer")
crates/coordinator   quorum/dispute/ledger logic + network server (the job client)
crates/wire          transport: length-prefixed JSON frames, TLS, admission PoW
crates/contentstore  BLAKE3-addressed blob store (the "torrent" layer, seeded)
crates/difftest      differential determinism harness
crates/conformance   conformance driver: QEMU differential + riscv-tests tally
arch-tests/          the official riscv-tests ELFs (rv64ui/um/uc, 67 tests)
jobs/demo-hash       the demo job: no_std Rust, compiled to a RISC-V ELF
jobs/demo-hash-smoke same program, 32 KiB input — powers the fast network tests
jobs/demo-hash-nano  1 KiB input — the same-ELF zk receipt's workload
jobs/demo-v2         the V2 (SP1-native) demo job — the 94x benchmark workload
jobs/conformance     ISA corner-case suite (explicit inline asm, both impls)
jobs/agent-task      the agent-work pilot job (see docs/PILOT.md)
sp1-guest/           zkVM guests: the algorithm (fnv) and the emulator (emu)
sp1-host/            prover + zk-verify oracle + receipt artifacts
elf/                 the SP1 guest ELF embedded into production workers
scripts/             packaging + validation + two-party pilot scripts
docs/                PREPRINT.md, DESIGN.md (decision log), INTEGRATION.md,
                     QUALIFYING.md, LICENSE-STRATEGY.md, overview.html
```

### The determinism contract

A job is a pure function `(program.elf, input.bin) -> (result, chunk
hashes)`. The emulator guarantees:

- entire architectural state = 32 registers + pc + machine CSRs +
  memory (nothing hidden);
- reads of unallocated pages are zero; writes allocate; 4 GiB flat
  space;
- misaligned loads/stores are supported (deterministic byte-level
  split, matching spike/QEMU); invalid encodings and out-of-range
  accesses trap;
- `ecall` traps (QEMU-compatible syscall mode for the conformance
  differential); `ebreak` → clean halt; `mret` → return to `mepc`;
- hash chain: `BLAKE3(prev_hash ‖ registers ‖ pc ‖ mtvec ‖ mepc ‖
  mcause ‖ mstatus ‖ memory_root)` emitted every `chunk_size`
  instructions and at exit — every architectural field is bound.

Any two machines that run the same job and disagree on a single chunk
hash have found a bug — the CI differential test exists to make that
never happen silently.

### Job ABI (see `crates/abi`)

```
0x1000_0000  u64 input length, bytes follow
0x2000_0000  u64 output length (written by the job), bytes follow
0x8000_0000  ELF image base (jobs link here)
0x83F0_0000  initial stack pointer
halt: execute `ebreak`   |   ISA pin: rv64imc (no atomics, no FP)
```

</details>

## License

Dual-licensed under MIT or Apache-2.0, at your option (see
LICENSE-MIT and LICENSE-APACHE). Job code you scaffold and write is
yours to license however you want — the templates impose nothing.
Licensing decisions and the recorded revisit triggers:
`docs/LICENSE-STRATEGY.md`.
