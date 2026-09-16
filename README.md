# provework

[![CI](https://github.com/HolyWill90/provework/actions/workflows/ci.yml/badge.svg)](https://github.com/HolyWill90/provework/actions/workflows/ci.yml)

**Verifiable serverless for deterministic Rust.** Write an integer-only
Rust function, delegate it to machines you don't trust, and get the
result back with a cryptographic receipt — plus automatic fraud
detection: if a worker lies, the judge convicts it and slashes its bond.

Forked from the [p2p-compute](https://github.com/HolyWill90/p2p-compute)
research substrate (full history preserved); this repo is the product
layer built on top of it.

## The two-party story

```
Party A (job owner)                 Party B (untrusted executor)
  has a computation                   offers machines
          │                                   │
          ├── delegate ──────────────────────→│  runs it in the sandbox
          │                                   │
          │←──── signed result + receipt ─────│
          │                                   │
  verify the receipt                 (if they cheated:)
  accept the result                  dispute judge convicts
                                     + bond slashed in the ledger
```

Real run: [three machines, two owners](docs/overview.html) — one worker
submitted a fabricated result; the judge convicted it and the ledger
shows `wB +10, wC −100`.

## Quickstart

```bash
# 0. toolchain (rustup) + the RISC-V target
rustup target add riscv64imac-unknown-none-elf

# 1. scaffold a job crate with your computation
cargo run --release -p jobkit -- new my-job
#    edit my-job/src/main.rs and my-job/input.bin

# 1b. or scaffold a V2 (SP1-native) job: ~100x cheaper to prove, and
#     verified by zk receipt without re-execution — but executable
#     only by SP1 fleets. Build auto-routes through a pinned Docker
#     toolchain when cargo-prove is not installed locally (one-time
#     image build, then ~20s rebuilds from the mounted host caches).
cargo run --release -p jobkit -- new my-v2-job --v2
#    edit my-v2-job/guest/src/main.rs and my-v2-job/input.bin
cargo run --release -p jobkit -- build my-v2-job

# 2. compile for the sandbox + validate the ELF
cargo run --release -p jobkit -- build my-job

# 3a. run as Party B — join a coordinator's fleet as an untrusted executor
./scripts/party-b.sh <coordinator-addr>

# 3b. run as Party A — start the coordinator (TLS + admission PoW)
./scripts/party-a.sh

# 4. Party A publishes + submits the job; Party B's fleet executes it.
#    jobkit submit does both in one step from the job owner's machine:
cargo run --release -p jobkit -- submit my-job \
    --server <coordinator-addr> --store ./p2pc-store --identity submitter.key

# 5. evidence: assemble the verifier-ready bundle for the finished job
cargo run --release -p jobkit -- evidence \
    --results <results-dir> --job-id my-job-0001 --out evidence-bundle

#    zk-proved jobs ship a receipt; verify it offline — no coordinator,
#    no prover (build the verifier once on any Linux machine:
#    cargo build --release -p sp1-host --bins)
cargo run --release -p jobkit -- verify --bundle evidence-bundle \
    --zk-verify sp1-host/target/release/zk-verify \
    --guest-elf elf/sp1-guest-emu --desc my-job/descriptor.json

# 6. high-assurance mode: the coordinator proves the job in its zkVM
#    and the outcome is receipt-backed — no worker consensus at all
cargo run --release -p jobkit -- submit my-job --require-zk \
    --server <coordinator-addr> --store ./p2pc-store --identity submitter.key
```

## Verification tiers

Every execution emits a **journal** — the 8-byte little-endian
instruction count followed by the job's output bytes — and workers
commit to `SHA-256(journal)`. The coordinator's dispute judge
re-executes the job and reproduces the identical bytes, so a verdict is
never a worker's claim about the output; it is the judge's own output.
One journal, three selectable verification tiers:

| Tier | Mechanism | Trust removed | Cost | Status |
|---|---|---|---|---|
| Budget | Quorum, bond slashing, dispute judge | Workers agreeing on a fake result | ~N× | live |
| Standard | Optimistic acceptance + replay judgment | Same, at 1× unless challenged | ~1× | implemented |
| Strong | SP1 zkVM receipt **over the emulator itself executing your actual job** | Everything: no trust in any worker | prover tax | receipt verified and accepted by the network (nano envelope) |

**Execution engine.** Jobs come in two formats. Legacy (`rv-abi`)
jobs run inside SP1's zkVM through the pinned-emulator guest
(`elf/sp1-guest-emu`, embedded at build time): the job ELF keeps its
sandbox ABI, the guest commits a BLAKE3 binding of
`(manifest, elf, input)` before executing, and Windows dev builds run
the same emulator natively. **V2 (`format: "sp1-v2"`) jobs are
SP1-native guests** — compiled against `io::read`/`commit`, executed
directly by the zkVM with no emulator in the loop: the measured cost
of the same 32 KiB job drops from 168.9M to 1.79M VM cycles (~94x),
turning an unprovable job into an 80-second CPU proof. V2 output is
byte-identical to the legacy path's for the same input; the rvcore
replay judge refuses V2 jobs (they are the zk judge's jurisdiction).

See `docs/DESIGN.md` for the decision log, `docs/QUALIFYING.md` for
whether your workload fits, `docs/PREPRINT.md` for the measured
account of the architecture (meta-emulation tax, V2 economics, GPU
gate), and `docs/overview.html` for a visual briefing.

## What is verified, and what is not

- **Fraud detection over real networks**: demonstrated across three
  physical machines (two different owners) and the open internet — a
  worker that fabricated a result was convicted by the judge and
  slashed in the ledger.
- **Independent correctness evidence**: the official riscv-tests
  suites (67/67) and a QEMU differential — sampled evidence, not proof.
- **Same-ELF zk receipts**: the pinned emulator itself is proven inside
  the zkVM; CI re-verifies the committed receipt every run. The
  demonstrated envelope is ~16K instructions (nano); multi-shard
  proving is an open infrastructure gap.

## The substrate

The verification engine is a pinned deterministic RISC-V (RV64IMC)
emulator: the entire architectural state is 32 registers + pc + machine
CSRs + memory, hashed after every fixed chunk of instructions. The
determinism contract, the job ABI, and the CI gates are documented in
the sections below — unchanged from the research substrate this fork
preserves.

<details>
<summary>Substrate details (determinism contract, job ABI, layout)</summary>

### Layout

```
crates/abi           job ABI: memory map, halt convention, pinned ISA string
crates/rvcore        the emulator: RV64IMC interpreter + chunk-hash chain (BLAKE3)
crates/jobfmt        job manifest/result formats, signing-message encoding
crates/jobkit        the product layer: scaffold / build / submit / evidence
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
jobs/conformance     ISA corner-case suite (explicit inline asm, both impls)
jobs/agent-task      the agent-work pilot job (see docs/PILOT.md)
sp1-guest/           zkVM guests: the algorithm (fnv) and the emulator (emu)
sp1-host/            prover + zk-verify oracle + receipt artifacts
elf/                 the SP1 guest ELF embedded into production workers
scripts/             packaging + validation + two-party pilot scripts
docs/                DESIGN.md (decision log), QUALIFYING.md, PILOT.md, overview.html
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
LICENSE-MIT and LICENSE-APACHE).
