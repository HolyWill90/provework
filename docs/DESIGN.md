# Design: deterministic verification substrate for P2P compute

This workspace implements the foundation layer of a torrent-style peer-to-peer
compute network. The insight driving every decision here: **verification is the
hard part of P2P compute, and every verification mechanism is a consumer of one
artifact — a deterministic VM that emits a hash of its state after every fixed
chunk of instructions.** Quorum compares final hashes. Dispute games binary-search
the chain to the first divergent chunk. zkVMs attach a proof to the same execution.
Build the substrate first; the tiers plug into it.

## Decision log

### 1. Substrate: a pinned deterministic RISC-V VM (RV64IMC)

- **RISC-V over WASM**: the leading zkVMs (SP1, RISC Zero, Jolt) all prove
  RISC-V execution, so the same ELF workers run today can carry a zk proof
  tomorrow with zero porting. RISC-V also has no spec ambiguity like WASM's
  NaN bit-pattern nondeterminism.
- **The pin is RV64IMC**: integer + mul/div + compressed. Atomics (`lr/sc`) and
  floating point are outside the contract; jobs compile with
  `-C target-feature=-a`. Compressed instructions are *accepted* — we tried to
  exclude them (`-c`) and the toolchain fights back (lld's relax pass compresses
  anyway because the object attributes claim C; `-relax` is unstable on stable
  rustc). Accepting C matches what every real RISC-V toolchain produces.
- **Determinism contract**, enforced by construction:
  - the entire architectural state is 32 registers + pc + memory — there is no
    hidden state to diverge (no flags, no clock, no ambient RNG);
  - reads of unallocated pages are defined as zero; writes allocate;
  - misaligned loads/stores are supported (the byte-level access splits
    across pages, which is fully deterministic) — matching the
    spike/QEMU platform behavior the conformance differentials validate
    against; instruction fetch still requires canonical 2-byte
    alignment (RVC); address space is a flat 4 GiB;
  - `ecall` traps (or is a QEMU-compatible syscall in conformance mode),
    `ebreak` halts cleanly, `mret` returns to `mepc`, invalid encodings
    trap;
  - traps and the instruction limit are themselves part of the canonical
    chain (a trapped job has a well-defined identity too).
- **Chunk hash chain**: after every `chunk_size` instructions and at exit,
  emit `h_i = BLAKE3(h_{i-1} || x0..x31 || pc || mtvec || mepc || mcause
  || mstatus || memory_root)` where `memory_root` is BLAKE3 over each
  allocated 4 KiB page in sorted index order. The chain is what every
  verification tier consumes. The machine CSRs are architectural (trap
  routing affects execution), so they are hashed: a snapshot carrying
  different CSR state cannot pass the chain check.
- **SECURITY AUDIT (external, 2026-09-14) — all findings fixed**:
  - *Quorum vote stuffing*: results were appended without checking that
    the worker was dispatched, and duplicates were counted — one
    authenticated worker could fabricate a majority. The network layer
    now drops results from non-dispatched workers and enforces one vote
    per worker per job; `decide()` deduplicates defensively too.
  - *Incomplete signatures*: only `result_hash` was signed. Workers now
    sign `jobfmt::signing_message` — a length-prefixed encoding of job
    id, status, instruction count, full chain, output, and trap detail
    — so no field can be swapped post-signing. Output consistency is
    covered by the chain (the output region is hashed into state).
  - *Dispute-state omission*: `state_hash` omitted the machine CSRs
    while snapshots carried them, so a forged snapshot could redirect
    trap handling and still verify. CSRs are now hashed.
  - *Arbitrary host-file writes*: manifest file fields were joined into
    the output directory unconstrained during materialization. They are
    now confined to a single plain file name (write and read side).
  - *Unchecked arithmetic*: `addr + len` in the memory model and ELF
    loader could overflow (debug panic / release wrap past the bounds
    check). All guest-controlled range checks use `checked_add`; ELF
    segment ranges must fit the pinned 4 GiB space.
  - *Pre-authentication panic*: nonce/pubkey hex decoding sliced
    attacker-controlled strings at byte offsets — a short or multi-byte
    string panicked the coordinator before authentication. All wire
    hex now decodes through a panic-free `jobfmt::from_hex`.
  - *CI cross-verify gap*: the smoke differential overwrote the full
    job's staged artifact, so cross-platform comparison only covered
    the one-chunk smoke run. difftest takes `--out-prefix` and both
    jobs are staged and compared per job across all platforms.
- **zk verifier process boundary hardened (external review round 3)**:
  receipt claims are size-capped before decode (64 MB), the verifier
  runs under a 30 s wall-clock limit with kill-on-exceed (a stalled or
  pathological verification can no longer wedge the coordinator loop),
  and the receipt temp file is unique and exclusively created per
  verification (the shared predictable path was a race and
  symlink-replacement hazard between concurrent claims). CI
  reproducibility pinned: nightly date, cargo-fuzz, cargo-audit
  versions fixed; the coverage job now builds the job ELFs (the
  network tests were skipping without them, gutting measured coverage)
  and the floor is raised from 25% to 55% of measured 61%.
- **zk tier, same-ELF — RECEIPT VERIFIED (2026-09-14)**: the earlier
  zk claim was same-ALGORITHM only (an SP1 guest reimplementing
  demo-hash's FNV streams). The guest is now the actual emulator:
  `sp1-guest-emu` compiles rvcore itself into the zkVM and executes
  the actual job ELF with the actual input, committing status,
  instruction count, the full chunk chain, and output. On the
  demo-hash-nano job the compressed receipt was cryptographically
  verified (`SP1 EMU PROVE PASS`) AND its committed values equal the
  local rvcore run byte-for-byte. What that buys: a job can be
  accepted on one cryptographic proof over the pinned emulator binary
  instead of worker consensus — the trust anchor collapses to
  rvcore's source (QEMU-differential + official riscv-tests
  validated) plus zkVM soundness. Envelope, stated plainly: the nano
  job (~16K emulated instructions) proves in ~20 minutes at ~24GB
  prover RAM. Two proving-infra limits remain (SP1 6.8's native
  fast-executor crashes on shard boundaries above ~100K emulated
  instructions — and the CPU prover errors on multi-shard programs
  ("artifact not found") in both compressed and core modes): receipts
  beyond one shard need a newer SP1 or the GPU prover — the already-
  listed operationalization gap. Wiring a verified receipt into the
  coordinator as an accepted verification tier is DONE (2026-09-15):
  the guest commits a job binding - BLAKE3 of (manifest, elf, input),
  i.e. the descriptor's content ids - and authenticated workers submit
  a signed ReceiptClaim over the wire; the coordinator verifies it via
  an external verifier binary (sp1-host's zk-verify, keeping the
  coordinator SDK-free) and accepts the job on the proof alone
  (Decision::Accept { zk: true } - no quorum threshold applies).
  Demonstrated by the zk_receipt_claim_accepts_job network test and
  re-verified in CI against the committed receipt on every run.
- **Identity cost — admission proof-of-work**: keypairs are free, so
  "slashing" could not bite: a banned identity returned with a fresh
  key. Authentication now requires mining
  `BLAKE3(nonce || counter)` to `--identity-pow-bits` leading zero
  bits, where `nonce` is the coordinator's fresh per-connection
  challenge — the work cannot be precomputed or reused, so every
  connection (and therefore every identity after a ban) pays
  approximately `2^bits` hashes. The difficulty is the economic dial;
  20 bits is ~0.1s per connection, and a production deployment raises
  it to whatever a return-after-ban should cost. This makes the
  sampling argument (collusion probability f^N) bind against real
  cost instead of free keypairs; it is still not stake.

### 2. Verification tiers (routing by job value)

| Tier | Mechanism | Overhead | Status |
|---|---|---|---|
| Budget | Quorum N=3 → 5, bond slashing | ~3× | implemented (coordinator) |
| Standard | Optimistic + dispute game (first-divergence + one-chunk judge from a verified snapshot, or full replay) | ~1× | implemented |
| Strong | zkVM proof attached to the same ELF | 1× + prover tax | **VERIFIED**: same digest inside SP1 v6.8 as the emulator, receipt cryptographically verified |

Quorum is *not* verification — it is bounded-risk economics: workers sampled
independently at random, P(all N collude) = f^N, bonds make detected fraud
unprofitable. It never proves a result correct; it makes wrong answers
improbable and unprofitable. High-value jobs skip it for zk once the prover
tax fits.

### 3. Coordinator = the client (deliberately centralized)

Verification protects the *client* from workers; it never required
decentralizing the coordinator. For the substrate, the client runs its own
coordinator and workers are untrusted processes. Decentralizing coordination
(DHT job discovery, token escrow, watcher bounties) is a product decision for
later, independent of verification correctness.

### 4. What is deliberately NOT built

- GPU / nondeterministic workloads: no bitwise story exists; they would route
  to TEE attestation — a different tier, out of scope until the substrate is
  proven.
- Networking beyond process spawning: workers communicate only through result
  JSON, which is exactly the real protocol surface.
- Token, chain, consensus: nothing here needs them.

## The two tests that matter

1. **Differential determinism** (`difftest`): the same job through debug and
   release builds locally, a Linux container, and — in CI — three operating
   systems on two CPU architectures. All chunk hash chains must be
   byte-identical. This is the deterministic contract, continuously proven.
2. **Independent reference check**: the demo job's digest was verified against
   an independent Python implementation of the same algorithm. Determinism
   without correctness is worthless — both builds could agree on the wrong
   answer.

## Verified milestones

- RV64IMC interpreter passes 35 unit tests: division/M-extension edges,
  compressed-encoding register-field regressions, snapshot round-trips,
  and one-chunk judge equivalence with full replay.
- Demo job: 2 MiB input, 33.5M instructions, 33 chunks — digest matches an
  independent Python reference byte-for-byte.
- Differential determinism passes locally (debug vs release), in a Linux
  container, and in CI across three operating systems and two architectures.
- **Conformance differential vs QEMU**: the same static ELF executed by our
  emulator and by `qemu-riscv64` produces byte-identical output over an
  ISA corner-case suite (integer ALU, M-extension edges, all W-forms,
  compressed instructions, branches/jumps, syscall ABI). This caught two
  real bugs: an MULH/MULHSU sign-cast error and a write-syscall that did
  not advance pc.
- Dispute game: first divergence located, judged by one-chunk
  re-execution from a hash-verified snapshot (fast path) or full replay —
  both paths agree; forged snapshots fail the hash check by construction.
- Optimistic acceptance: window/challenge state machine with a live demo
  (unchallenged → accepted; challenged in window → dispute verdict).
- Worker identities (Ed25519-signed results) and a persistent bond ledger
  with balance accumulation across jobs and history.
- Agent-task pilot job (`jobs/agent-task`): deterministic agent-shaped
  batch transform, verified against an independent reference. Positioning
  in `docs/PILOT.md`.
- **zk tier demonstrated (SP1 v6.8)**: the demo algorithm compiled as an
  SP1 guest, executed inside the zkVM, proved on CPU, receipt verified —
  and the zkVM digest equals the host reference for the same input. Scope
  note: this validates the ALGORITHM as a zk guest, not yet the exact
  emulator ELF binary; full same-ELF proving is future work, and SP1 is
  not yet wired into CI (the toolchain download is ~2 GB).

## Content-addressed store (the torrent layer, seeded)

`crates/contentstore`: blobs addressed by BLAKE3, verified on every read;
`publish` turns a job directory into a `JobDescriptor` (manifest + ELF +
input hashes — the torrent-file analog); `materialize` reconstructs the job
anywhere from the descriptor, byte-verified. Re-executing a materialized
job produces the identical chunk-hash chain, so any third party can audit
an execution without trusting the original client. CLI:
`coordinator publish | fetch | verify`.

## Adversarial hardening (demonstrated limits and defenses)

Stated as tests (`crates/coordinator/tests/collusion.rs`), not prose claims:

- **The collusion limit is real and documented**: two of three colluding
  workers with an identical wrong answer BEAT the quorum tier — the test
  asserts the wrong answer is accepted. Quorum is bounded-risk economics,
  not truth. The defense is layered, not louder: any single honest
  challenger escalates to the dispute game, which re-executes and wins —
  demonstrated with a coherent mid-chain forger (divergence at chunk 5,
  consistent fabrication thereafter): pinpointed at exactly chunk 5,
  honest side vindicated, judged by re-execution truth.
- **Disagreement-DoS is bounded and fail-closed**: a persistent attacker
  forces at most 5 executions + 1 judge replay per attacked job, then the
  job fails closed (Reject) — never an unbounded loop. Slashing makes the
  attacker's ledger strictly worse (-100/job): 3 attacked jobs → -300,
  client cost bounded at 15 executions.
- **RESOLVED — reserve escalation flake**: two distinct causes.
  First, the between-jobs worker drop and the escalation-empty-reserves
  race were both caused by dispatch firing before the full pool
  authenticated — fixed by gating dispatch on the full pool (not just
  the named round-1 workers). Second, even with that fixed, the
  network tests stayed marginal on 2-core CI runners: the 2 MiB
  demo-hash job costs ~33.5M debug-build instructions per execution,
  so a full round-1 + escalation run could outgrow the test's 110s
  receive timeout on windows-latest. The network tests now run
  `jobs/demo-hash-smoke` (same program, 32 KiB input → 524K
  instructions, seconds per execution; honest hash ends in '2', so
  the corruption hook still diverges), and the test receive bound was
  raised to 300s — the coordinator's own worst case is two full
  90s deadline windows, so anything past that is a genuine hang.
- **Security hardening (post-audit)**: submitted results are bound to
  the authenticated connection — worker id, Ed25519 public key, and a
  signature over the result hash are all checked server-side before a
  result can touch quorum. Round-1 worker selection is randomized
  (Fisher-Yates over the OS CSPRNG) with held-back escalation reserves,
  and late-authenticating workers join the reserve list of an in-flight
  untargeted job (escalation can no longer deadlock when a reserve
  connects after dispatch).
- **ISA conformance regressions (external audit)**: four M-extension and
  compressed-decode bugs found and fixed — DIVU/DIVUW by zero returned
  the dividend instead of all-ones, REMUW/REMW by zero returned the full
  register instead of the sign-extended 32-bit dividend, and the Q1
  f3=100 group ignored bit12, decoding C.SUBW/C.ADDW as C.SUB/C.XOR.
  Each has a dedicated regression test. The official riscv-tests suite
  (rv64ui/um/uc-p-*) now runs in full: **67/67 pass** through the
  emulator (`conformance arch`, wired into CI on all platforms and in
  the QEMU conformance job). Reaching that surfaced three real
  emulator bugs the project's own tests had missed:
  - the ELF loader's `.tohost` section parser silently returned None
    on every real ELF (an unbounded slice read that only converts when
    exactly 8 bytes remain), so tohost exits never fired — the earlier
    "linker alignment gaps" theory was wrong;
  - the tohost device only detected 8-byte stores, while
    riscv-test-env posts its exit code with a 32-bit store;
  - `mret` was not implemented (every test's machine-mode init ends
    with `csrw mepc; mret`, which illegally trapped into the handler).
- **Platform policy change — misaligned accesses**: the emulator used
  to trap on misaligned loads/stores. Both independent references the
  project validates against (qemu-riscv64, and spike via the official
  riscv-tests `ma_data`) support them, and the byte-level split across
  pages is exactly as deterministic as trapping. The memory model now
  supports misaligned accesses; instruction fetch keeps the canonical
  2-byte alignment. The former `misaligned_load_traps` regression test
  now asserts the split read returns the correct composed value.
- **Honest scope notes**: bond "slashing" is JSON ledger bookkeeping, not
  on-chain escrow; random sampling is unbiased but the reserve pool is
  only as Sybil-resistant as worker identities (keypairs, not stake).
- **Benchmarks** (24-core x86-64 host, release build, single-threaded
  interpreter): 22M instructions/sec; 33.5M-instruction job in 1.53s;
  snapshots cost 2.11 MB per chunk (69.6 MB for the 2 MiB-input demo —
  proportional to the job's memory footprint, an honest scaling limit for
  large-working-set jobs).
- **UPDATE (2026-09-15) — page-table memory, 5× throughput**: the
  sparse memory's page map was a BTreeMap — every instruction paid
  1-2 O(log n) pointer-chasing lookups (fetch + load/store), making
  the interpreter memory-latency-bound. The page map is now a flat
  lazily-grown index (page number -> slot), O(1) per access, with the
  canonical page iteration order preserved byte-for-byte (the Merkle
  root, snapshots and every pinned hash are unchanged — the
  differentials, the 67/67 suite and all hash pins verify it). Result:
  the 33.5M-instruction demo job runs in ~0.29s end-to-end
  (~115M instructions/sec, ~5×), and the zk guest inherits the same
  improvement (fewer zkVM cycles per emulated instruction).
- **Known untested adversaries** (for the networked phase): result-copying
  between workers (mitigation: per-worker input nonces with commit-reveal),
  Sybil identity farming (mitigation: stake-weighted identity), and
  economic attacks on the bond market itself.

## Multi-job sessions and peer-to-peer blob exchange

`coordinator serve --jobs-dir <dir>` is now a persistent session: it
watches the directory for `*.desc.json` descriptors (produced by
`coordinator publish`), dispatches each to connected workers, collects
results, decides, updates the ledger, and broadcasts BetweenJobs — one
job after another, with workers staying connected across all of them. A
filename `name@w1,w2.desc.json` targets specific workers; round-1
membership by id removes connection-order races. `--max-jobs` bounds a
session (used by tests).

**Peer-to-peer blob exchange is implemented and measured**: daemons with
`--listen-port` serve blobs to peers over the `PeerToPeer` protocol;
every JobAssignment carries peer hints; a worker fetches from peers
first, coordinator as fallback, verifying every byte against the
requested hash either way. The integration test proves the path with
byte accounting: a fresh worker's three blobs all arrived from a seeded
peer (`from_peers: 3, from_server: 0, served_to_peers: 3`), and its
re-execution matched the original run's hash exactly.

## The network layer: serve + daemon

`crates/wire` (length-prefixed JSON frames) + `coordinator serve` +
`worker daemon`: the coordinator accepts Ed25519-authenticated worker
connections (nonce challenge-response at hello), dispatches jobs as
content-store blobs **over the wire** (hash-verified on arrival by each
worker), collects signed results from a pool, and runs the standard
quorum/escalation — escalation included — across real sockets.

Demonstrated by `crates/coordinator/tests/network.rs` over localhost TCP:
a multi-job session with peer-to-peer blob exchange, the same flow over
TLS with fingerprint pinning, and reserve escalation — round 1 names an
honest worker and a liar, no majority forms, the coordinator escalates
to the held-back honest reserve, and its result joins round 1's honest
vote for a 2/3 accept while the liar's bond burns. A subtlety worth
keeping: a corruption whose flipped byte lands on the honest value is
indistinguishable from honesty. This was eliminated rather than
managed: `--corrupt-byte` now selects a journal byte to *bump*
(±1 mod 256), and a bump can never round-trip to the original — no
coincidence window exists at any byte.

Deterministic round-1 membership: the coordinator names the round-1
workers by id (`--round1-ids w1,w2,w5`), removing connection-order races
from the dispatch decision.

## Execution engine rebase, step 1: SP1 zkVM is the production executor

The worker daemon gained a second execution path behind the `sp1`
feature (Linux/production; the feature is not compiled on Windows dev
machines because SP1's JIT backend is Linux-only). The design points
that make the two paths interchangeable:

- **The guest is the emulator.** SP1 cannot run the job ELF directly:
  jobs use a bare-metal ABI (input/output at fixed addresses, `ebreak`
  halt) that SP1's VM does not honor. Instead the pinned emulator
  itself is the zkVM guest (`sp1-guest`, built to `elf/sp1-guest-emu`
  and embedded into the worker binary at compile time). The job ELF
  keeps its ABI; SP1 executes rvcore-on-the-job.
- **The guest binds the job before executing.** It commits
  `BLAKE3(manifest) ‖ BLAKE3(elf) ‖ BLAKE3(input)` first; the worker
  re-derives the same triple from the materialized blobs and rejects
  any mismatch. A wrong guest artifact or wrong job cannot be silently
  executed.
- **One journal format, one digest.** Both paths produce
  `journal = u64 LE instruction count ‖ output` and commit to
  `SHA-256(journal)`. The instruction count is the *guest's committed
  rvcore count* — not SP1's VM cycle count, which is executor overhead
  — so an SP1 worker and an rvcore worker produce comparable results.
- **Honest status.** The guest commits an exit status (halted /
  instruction-limit / trap) and the worker propagates it; the rvcore
  path maps `ExitStatus` the same way. Trapped jobs are reported as
  trapped.
- **The judge reproduces the journal.** The network dispute judge
  (`replay_journal`) re-executes from genesis with the same rvcore and
  constructs the identical journal bytes — its verdict output is its
  own replay's output, never a worker's claim. The judge must be
  recompiled with the rvcore that the fleet executes; the zkVM guest
  has the same constraint (a rebuilt `elf/sp1-guest-emu` must follow
  any rvcore semantics change — rvcore is pinned, so this is a release
  event, not a routine drift).
- **Prover client sharing.** The SP1 CPU prover is constructed once
  per process (`OnceLock`), not once per job — construction spins up
  the whole worker machinery.

What step 1 does NOT change: receipts. The Strong tier still verifies
the committed nano receipt against the pinned
`sp1-artifacts/sp1-guest-emu.elf`; refreshing that artifact with a
fresh prover run is the receipt-tier rebase (a later step). Steps 2-3
of the rebase (SP1 `prove()` as the dispute judge; direct receipts for
high-value jobs) remain open.

**Deployment constraint (SP1 executor):** SP1's JIT executor runs the
guest in a child process backed by `/dev/shm`; if that tmpfs is too
small for the workload's arena the child dies with SIGBUS — SP1's own
runner logs "SIGBUS … there is a chance /dev/shm is full!". Docker's
default `/dev/shm` is 64 MB, which executes the nano envelope fine but
kills a ~524K-instruction job. Fleets running the `sp1` path must
start their containers with `--shm-size` sized for the largest job
(8 GB covers the current envelope with headroom); bare-metal hosts
have no such limit. Documented here because the failure mode is a
silent crash in a child process, invisible in the worker's own logs
beyond the error string.

## Step 2: SP1 prove() as the dispute judge

When a job ends with no worker majority and no reserves, the
coordinator can escalate to an external `zk-judge` process (built from
`sp1-host`) instead of relying on its own rvcore replay. The judge
re-executes the disputed job inside the zkVM — the same
emulator-as-guest as the worker path — and returns a **receipt**: the
verdict becomes third-party checkable, not just coordinator-asserted.

- **Fail fast before proving.** The judge executes first (cheap) and
  refuses to prove when the VM cycle count exceeds
  `--zk-judge-max-vm-cycles` (default 10M). An emulator inside a zkVM
  multiplies job instructions ~300x, so the cycle bound — not the job
  size — is the resource dial.
- **The verdict is never trusted on faith.** The coordinator
  recomputes the journal digest from the verdict's own (instruction
  count, output) pair, cross-checks the guest's committed
  (manifest, elf, input) binding against the descriptor's content
  ids, and the judge binary itself cross-checks the zkVM execution
  against its locally linked rvcore (catching a guest artifact that
  drifted from the pinned semantics).
- **Vindication, not blanket conviction.** A receipt-backed accept
  pays the responders whose result matches the receipt and burns the
  rest — the same ledger semantics as the replay judge.
- **Fail-open to replay.** Judge absent, oversized, cycle-bound, or
  timed out (`--zk-judge-timeout-secs`, default 1800) — the replay
  judge arbitrates. Both are the coordinator's own computation; zk
  adds verifiability, not correctness.

**Measured envelope (8 CPU cores, 32 GB RAM, SP1 6.8 CPU prover,
`core` proof mode):**

| Job | rvcore instructions | VM cycles | execute | prove | peak RAM |
|---|---|---|---|---|---|
| nano | 16,410 | 5.94M | 0.1 s | **140 s** | **23.8 GB** |
| smoke | 524,314 | 168.9M | 2.5 s | killed at 70 s | 31.8 GB (OOM) |

Proving memory grows with the shard count (nano ≈ 3 shards, smoke ≈
84), so the CPU-provable envelope on a 32 GB host ends near ~10M VM
cycles (~28–31K emulated instructions). **GPU proving is now
measured**: on an RTX PRO 4500 Blackwell (32 GB VRAM, driver 595.71,
rented on vast.ai for under a dollar), SP1 6.8's CUDA prover runs
correctly on the Blackwell architecture (sm_120) and proves the
legacy 168.9M-cycle job in **34.2 s at 26.1 GB peak VRAM** (the job
that OOM-killed the 32 GB CPU host), and the V2 1.79M-cycle job in
**2.8 s at 10.6 GB peak VRAM** — a 29× proving speedup over CPU. The
26.1 GB peak explains the 24 GB VRAM floor as the honest minimum for
traces of this shape. Receipts verified against the CPU-produced
outputs; full logs in the benchmark session (2026-09-17). The meta-emulation
multiplier is the structural cost of the ABI-preserving guest;
replacing the guest emulator with an ABI trampoline (jobs compiled
directly for SP1's I/O convention) would remove the ~300x factor for
NEW jobs but abandons zero-migration compatibility — parked.

CI runs the full judge state machine under `SP1_PROVER=mock` (no
real cryptography, seconds); real-prover integration runs in the
Linux proving container. The proving envelope numbers above are why
the mock/real split exists.

**GPU proving: measured, gated by hardware.** The CUDA path is fully
wired and was verified to the gate on a real GPU host (GTX 1660
SUPER, 6 GB): the `cuda` feature builds, SP1's `sp1-gpu-server`
downloads and launches, driver passthrough works — and then the
server refuses outright: `Unsupported GPU memory: 10, must be at
least 24GB`. SP1 6.8's GPU prover has a hard 24 GB VRAM floor; this
is a gate, not a tuning knob. The proving envelope therefore remains
CPU-bound until a ≥24 GB GPU is available, at which point the same
binaries switch over with `SP1_PROVER=cuda` — no code change. Two
operational notes from the attempt, both now documented by this
entry: the gpu-server needs `libcudart.so.12` (install
`cuda-cudart-12-6`; the driver passthrough provides libcuda but not
cudart), and the zk-judge binary must use the async SDK — SP1 6.8's
blocking wrapper cannot construct the CUDA prover (no Tokio reactor
at builder time).

## Step 3: direct zk receipts as a product tier (high-assurance jobs)

A submitter can now ask for a **receipt-backed result** outright
(`jobkit submit --require-zk`): the coordinator skips worker consensus
entirely — one cryptographic proof replaces the quorum, the same
semantics as a verified receipt claim — and proves the job in its own
zkVM through the same external zk-judge process the dispute path uses.

- **Proving is decoupled from the request path.** The submission ack
  returns immediately (`proving: true`); the job sits in a FIFO
  proving queue serviced by a dedicated thread; the `JobOutcome`
  arrives when the proof lands. A client connection is never blocked
  by proving time (nano ≈ 2.5 min on CPU).
- **Receipt deduplication.** Execution is deterministic, so the same
  (manifest, elf, input) always proves to the same receipt. Receipts
  are cached under `{results_dir}/zk-cache/` keyed by
  `BLAKE3(manifest_id ‖ elf_id ‖ input_id)` — content ids, not job
  ids, so a second requester with the same content pays nothing for a
  receipt someone already paid for. A cache hit is NEVER trusted on
  faith: it is re-verified through the standalone zk-verify binary
  against the requesting job's binding; without a verifier configured,
  cache hits are refused and the job re-proves (fail-closed).
- **Client-side verification.** `jobkit evidence` bundles the receipt
  alongside the outcome; `jobkit verify --zk-verify <bin> --guest-elf
  <elf> [--desc <descriptor>]` checks the proof offline — the
  coordinator's word is not needed. With the descriptor it also pins
  the receipt to the submitter's exact content ids ("this receipt is
  for MY job", not merely "a valid receipt"). The verifier re-derives
  the verifying key from the committed guest ELF (~1 s) — an
  uninvolved third party with the bundle needs no prover and no
  coordinator.
- **Refusal is explicit.** A `require_zk` submission to a coordinator
  without a prover is refused with a clear reason, not silently
  downgraded to consensus.

## V2 guest format: SP1-native jobs (the ABI trampoline, honestly scoped)

The ~300x meta-emulation tax of the emulator-in-a-zkVM bootstrap was
the system's structural cost floor. V2 removes it for NEW jobs: a job
crate compiled against an SP1-native ABI stub (reads input via
`sp1_zkvm::io::read`, commits `blake3(input)` then the output) runs
DIRECTLY on the zkVM — the emulator is out of the loop entirely.

Honest scoping: the trampoline is source-level, not binary-level. A
legacy ELF's stores to fixed addresses cannot be intercepted under
SP1 (no trap-and-emulate hook for guest stores), so legacy jobs keep
the emulator path indefinitely; V2 is the format new jobs opt into
via the manifest's `format: "sp1-v2"` field.

**Measured, same job and input (demo fold over 32 KiB):**

| | VM cycles | CPU prove | peak RAM |
|---|---|---|---|
| legacy (emulator-in-guest) | 168,881,446 | OOM-killed at 32 GB | — |
| **V2 (SP1-native)** | **1,789,276** | **80.5 s** | **15.7 GB** |

94x fewer cycles; the job that could not be proven at all now proves
on an ordinary 32 GB host in 80 seconds. The V2 output is
byte-identical to the legacy rvcore result for the same input — the
differential the network test asserts.

Design consequences, all deliberate:

- **The V2 journal binds the output only** (`journal(0, output)`):
  SP1 cycle counts are a compiler/SDK-version artifact, not
  architectural state, and pinning them into the consensus digest
  would make receipts version-fragile.
- **The rvcore replay judge REFUSES V2 jobs** rather than mis-parsing
  them as rv-abi ELFs (a "replay" would fabricate garbage truth).
  V2 disputes and V2 high-assurance proving are the zk judge's
  exclusive jurisdiction; workers without the sp1 feature refuse V2
  assignments with an explicit error.
- **V2 receipts bind the input id** (committed by the guest; the elf
  is bound by the verifying key; the manifest is not executed), and
  the verifier checks exactly that — the "this receipt is for MY
  job" property survives the format change.

## Positioning decision (2026-09): frozen as a research artifact

A structured market search was run against every plausible application
for the base, each hypothesis eliminated on evidence: government
benefit calculators (US EITC; AU HELP/JobSeeker/FTB — verified pain,
but the computation is trusted and cheap to recompute: no trust
boundary for verification to span), agent tool-call verification
(sandboxing is solved by Firecracker/Modal/E2B, audit trails by signed
logs, and enterprise agents run on the enterprise's own trusted
infra), a Web3 ZK coprocessor (real fit and a paying market, but the
missing 70% is the on-chain/decentralization stack plus funded
incumbents — out of solo scope), and self-hosted prover orchestration
(in the zkVM world verification is mathematically free — a proof
verifies itself in milliseconds, so the quorum tier is vestigial
post-SP1-rebase, the dedup cache is a feature not a moat, and the TAM
analysis collapses to existing K8s/Slurm/Ray users).

The pattern across the search: the base's verification machinery is
valuable exactly where verification is expensive and the executor is
untrusted — and both conditions fail everywhere except inside the
zkVM ecosystem, where SP1 makes verification free. The honest
conclusion: **no near-term commercial market exists at solo scale.**

Decision: the code is FROZEN at v0.2.0 (no application layer, no MCP
wrapper, no HTTP API) and the repository is repositioned as what it
actually is — an open-source experimental research engine and
benchmark harness for distributed verifiable compute, with the
measured envelopes (docs/PREPRINT.md) as the front door. The base
remains available for future work to build on; the one bounded
question that could reopen the search is recorded under Known gaps.

## Known gaps (next milestones)

1. Official `riscv-arch-test` suite (the full official riscv-tests
   rv64ui/um/uc suites pass 67/67; riscv-arch-test is the more
   exhaustive, differently-generated form).
2. zk tier scale-out: the same-ELF receipt is verified at the
   nano-job envelope (~16K emulated instructions, one shard).
   Multi-shard CPU proving fails in SP1 6.8 ("artifact not found")
   and per-shard cycles make bigger receipts a compute-budget
   question — newer SP1, GPU proving, or a prover market is the
   production step.
3. Bisection dispute protocol for on-chain adjudication where full chains
   are not exchanged (the local judge can compare chains directly).
4. Networking: NAT traversal and peer discovery beyond the
   coordinator's hints. (TLS on the wire is DONE: serve --tls
   generates a self-signed coordinator cert, workers pin its
   BLAKE3 fingerprint via --server-cert, sessions run on
   rustls/TLS 1.3; worker identity stays the Ed25519 nonce
   handshake, and admission proof-of-work is the identity-cost
   dial.)
   shared per-job temp directory (`temp/p2pc-worker-{job_id}`) — two
   workers materializing the same job concurrently raced on
   program.elf, and one executed a partially-written ELF (hanging the
   emulator). Fixed with per-worker materialization directories;
   verified 4/4 clean runs plus a 25-job stress pass.
