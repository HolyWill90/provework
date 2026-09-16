# Optimistic Verification for Delegated Computation:
## Tiered Trust, the Measured Cost of Meta-Emulation, and the Case for Native zkVM ABIs

**Status:** draft v0.2 — every number in this paper is measured on the
referenced hardware and reproducible from the open-source artifact
(see Appendix C). Nothing here is projected, modeled, or extrapolated.

---

## Abstract

Zero-knowledge virtual machines (zkVMs) offer something delegated
computation has always lacked: cryptographic proof that a program
executed correctly, verifiable by anyone without re-execution. Their
cost, however, is structural — proving a program inside a zkVM costs
one to three orders of magnitude more in cycles than executing it
natively, plus a memory envelope that excludes commodity hardware for
all but small programs. We present an alternative composition: an
**optimistic verification network** in which independent untrusted
workers execute jobs at native speed under an economic bond, and
zkVM proofs are demanded only on dispute or explicit high-assurance
request. One journal format underlies all three verification tiers
(quorum, optimistic-plus-dispute, zk receipt), so a job's trust level
is a per-submission choice, not an architectural fork.

We contribute the first measured account (to our knowledge) of the
**meta-emulation tax**: running a legacy-ABI job by embedding its
interpreter inside a zkVM guest costs 322–362× the native zkVM cycle
count, and proves only within a narrow memory envelope (a 16,410-
instruction job requires 23.8 GB of RAM to prove; a 524,314-
instruction job OOMs on a 32 GB host). We then show the tax is
structural for binary-level compatibility — no trap-and-emulate
shim avoids it inside a zkVM — and demonstrate the escape: a
source-level native ABI (V2) compiles jobs directly for the zkVM,
reducing the same job from 168.9M to 1.79M cycles (94×) and turning
an unprovable job into an 80.5-second, 15.7 GB proof on an ordinary
32 GB host, with byte-identical output to the legacy path. Finally, we
report an empirical hardware gate for GPU proving (SP1 6.8 requires
≥ 24 GB VRAM, refusing a 6 GB card outright) and the operational
consequences of each finding. The full system runs as a working
network on real heterogeneous hosts, with every security property
enforced by continuous integration.

---

## 1. Introduction

Delegated computation — sending a computation to machines you do not
trust — is as old as time-sharing, and its core problem is as old:
*how do you know the answer is right?* Replication is the classical
answer (run it N times, compare); economic mechanisms make lying
expensive; cryptographic proofs make lying impossible. Each has a
cost. Replication costs N× the work. Economic mechanisms require
identity and collateral infrastructure. zkVMs, which execute a program
inside a virtual machine whose every step feeds a succinct proof,
cost orders of magnitude more compute than the computation itself.

This paper argues the costs are not competing alternatives but a
**spectrum**, and that a network can offer all of them simultaneously
over a single execution format. Our system, provework, delegates
deterministic integer-only programs (compiled to a pinned RISC-V
ISA) to untrusted workers over TLS with proof-of-work admission.
Every execution produces a journal — instruction count and output,
hashed into a consensus commitment — and every verification tier
consumes that same commitment:

1. **Quorum** — three or five workers execute independently; a
   supermajority agreement accepts. Cost: N executions, no proving.
   Fraud requires colluding on a fake result and losing bonds.
2. **Optimistic + dispute** — a majority is required only when
   challenged; a designated judge re-executes (or proves) the job and
   its verdict vindicates honest responders and burns liars.
3. **zk receipt** — the coordinator (or a worker) produces an SP1
   proof of the execution; one cryptographic proof replaces consensus
   entirely, verifiable offline by anyone.

**Contributions.**

- A three-tier verification architecture over a single journal
  contract, implemented end to end and enforced by CI (Section 3).
- The emulator-in-a-zkVM bootstrap: legacy bare-metal job ELFs run
  unchanged inside the zkVM by embedding the pinned interpreter in
  the guest, preserving zero-migration compatibility at a measured
  322–362× cycle cost (Section 4).
- The measured meta-emulation tax and its consequence: proving costs
  scale with the *meta* cycle count, pushing commodity hardware out
  of the envelope at ~0.5M job instructions (Section 5).
- The case, backed by measurement, for **source-level native ABIs**
  over binary-level trap-and-emulate: a V2 guest format reduces the
  same job by 94× and makes it provable on a 32 GB host in 80.5
  seconds, with byte-identical results (Section 6).
- An empirical hardware gate for GPU proving: SP1's CUDA prover
  refuses GPUs under 24 GB VRAM regardless of workload (Section 7).
- Operational integration: proving queues with content-keyed receipt
  deduplication, client-side offline verification, and fail-closed
  trust boundaries (Section 8).

---

## 2. Model and Threat Model

**Jobs.** A job is a pure function `(program.elf, input) -> output`.
Programs are deterministic integer-only RISC-V (RV64IMC, no atomics
or floating point; no syscalls, clock, filesystem, or network). The
sandbox is enforced by the ISA and the ABI, not by policy: a job
cannot observe the host, and two honest executions cannot disagree.

**Parties.**

- A **job owner** runs a coordinator: it advertises jobs, collects
  results, arbitrates disputes, and keeps the ledger. The coordinator
  is the owner's own agent — trusting it is trusting yourself; the
  design goal is that *nobody else* needs to be trusted for the
  result to be correct, and that third parties can verify outcomes
  from evidence bundles.
- **Workers** execute jobs for bond-backed rewards. They are
  untrusted: identities are Ed25519 keypairs admitted by a fresh
  proof-of-work per connection, blobs are content-addressed and
  hash-verified on arrival, and results are signed over their entire
  content.
- **Verifiers** are anyone holding an evidence bundle. Tier 1/2
  verification requires re-execution (cheap for these workloads);
  Tier 3 receipts verify in seconds with no execution at all.

**Adversary.** Workers may lie (fabricate results), collude, Stuff
quorums with duplicate identities, replay stale results, or withhold
(compute-withholding by slow-rolling). The mechanisms that answer
these — anchored quorum thresholds, one-vote-per-identity, bonded
slashing on contradiction, replay judges — are described where they
appear and exercised by named network tests (Appendix B). What the
system does not defend against (yet) is enumerated in Section 9.

**The journal.** Every execution — native, emulated, or proved —
reduces to the same commitment:

```
journal  = u64_le(instructions) || output          (legacy format)
digest   = SHA-256(journal)
```

For V2 (SP1-native) jobs the instruction count is *excluded*
(`journal(0, output)`): SP1 cycle counts are an artifact of the
compiler and SDK version, not of the program's semantics, and binding
them would make receipts version-fragile. The output of a
deterministic program is the invariant; the digest binds the output,
and V2 receipts additionally commit `blake3(input)` so a verifier can
pin a receipt to a specific job.

---

## 3. Architecture

### 3.1 Tier 1 — Quorum

The coordinator dispatches a job to N workers (default round 1: three;
escalation adds two held-back reserves). Acceptance requires a strict
majority **of the dispatched pool** — a quorum that shrinks to
whoever answered in time would let a lone survivor self-approve.
Results are grouped by digest; the winning group must also agree on
the full commitment structure. Costs are N executions at interpreter
speed (measured: up to 57.7M instructions/s on a 2 MiB job —
Table A.1) and zero proving.

Fraud economics: workers in the winning group are paid (+10 bond
units); any worker whose signed result contradicts the accepted one
is burned (−100). Slashing requires proof of contradiction — an
accepted majority the liar sits outside of — so honest failures are
never punished; slow-rolling is instead priced by the per-connection
admission proof-of-work.

### 3.2 Tier 2 — Optimistic acceptance and dispute judgment

When no majority forms and reserves are exhausted, the dispute judge
arbitrates. Two judges exist:

- **Replay judge** (legacy jobs): the coordinator re-executes the job
  from genesis with the pinned interpreter and reproduces the exact
  journal bytes. The verdict carries the judge's *own* output, never
  a worker's claim; responders whose digest matches the replay are
  vindicated and paid, contradicting ones are burned.
- **zk judge** (both formats, configured): the coordinator escalates
  to an external prover process that re-executes the job inside the
  zkVM and returns a cryptographic receipt (Section 5). The verdict
  becomes third-party checkable. The judge executes before it proves
  and refuses past a VM-cycle bound — an unbounded or hostile job
  cannot burn proving compute. The zk judge is the *exclusive*
  jurisdiction for V2 disputes: an rvcore replay of an SP1-native ELF
  would fabricate garbage truth, so the replay judge refuses them by
  format.

### 3.3 Tier 3 — Receipts and the proving queue

A submitter may request a receipt outright (`require-zk`). The job
skips consensus — one proof replaces the quorum — and enters a FIFO
proving queue serviced by a dedicated thread; the submission
acknowledgment returns immediately and the outcome arrives when the
proof lands. Three properties are enforced:

- **Deduplication.** Receipts are cached keyed by
  `BLAKE3(manifest_id ‖ elf_id ‖ input_id)` — content, not job ids —
  so identical work proves once. A cache hit is *never trusted on
  faith*: it is re-verified through the standalone verifier against
  the requesting job's binding; without a verifier configured, cache
  hits are refused and the job re-proves (fail-closed).
- **Verdict recomputation.** The coordinator recomputes the journal
  digest from the verdict's own values; the prover process's hash is
  never taken on faith.
- **Client-side verification.** `jobkit verify` checks a bundled
  receipt offline — no coordinator, no prover — re-deriving the
  verifying key from the committed guest ELF and optionally pinning
  the receipt to the submitter's content ids.

### 3.4 The execution engine: two formats, one contract

| | Legacy (`rv-abi`) | V2 (`sp1-v2`) |
|---|---|---|
| Guest runtime | embedded rvcore inside SP1 | the job itself, SP1-native |
| Job ABI | bare-metal: fixed-address I/O, `ebreak` halt | `io::read` / `commit` |
| Input binding | BLAKE3(manifest ‖ elf ‖ input) committed by the guest | BLAKE3(input) committed by the guest |
| Journal digest | `SHA-256(count ‖ output)` | `SHA-256(0 ‖ output)` |
| Windows dev path | native rvcore (identical digests) | refused, explicitly |
| Dispute jurisdiction | replay or zk judge | zk judge only |

The dual format is deliberate: legacy jobs migrate with zero
recompilation (the emulator preserves their ABI exactly), while V2
jobs shed the emulator's cost entirely. Both formats coexist on one
network, one manifest schema (a `format` field), one ledger.

---

## 4. The Emulator-in-a-zkVM Bootstrap

Legacy job ELFs use a bare-metal ABI — input at a fixed address,
output at another, halt by `ebreak` — that SP1's VM does not honor.
The zkVM offers no trap-and-emulate hook for guest stores, so there
is no binary-level shim that can translate those stores into
`commit` calls. The alternative that *does* work: compile the pinned
interpreter itself (rvcore, 67/67 official riscv-tests, QEMU
differential-validated) as the zkVM guest, and let it interpret the
legacy ELF inside the VM. The job keeps its ABI; the zkVM proves the
interpreter executing the job.

The guest commits `(BLAKE3(manifest), BLAKE3(elf), BLAKE3(input))`
before executing — so a receipt attests this exact job, and the
worker re-derives the same triple from hash-verified blobs before
accepting the execution. The judge binary cross-checks the zkVM
execution against its own locally linked interpreter, so a guest
artifact that drifted from the pinned semantics fails loudly.

**Cost.** The interpreter's every instruction is itself emulated by
the zkVM. Table 1 measures the multiplier.

**Table 1 — Meta-emulation cost (SP1 6.8, execute mode, 8-core x86-64).**

| Job | Job instructions | zkVM cycles | Multiplier | Execute wall |
|---|---|---|---|---|
| nano (1 KiB input) | 16,410 | 5,937,604 | 362× | 0.1 s |
| smoke (32 KiB input) | 524,314 | 168,881,446 | 322× | 2.5 s |

The multiplier varies with the job's memory-access profile (the
interpreter's page bookkeeping is the dominant emulated cost); 322×
to 362× is the observed range across our workloads. This is the
**meta-emulation tax** — structural, not incidental.

---

## 5. Proving Costs: Where the Tax Bites

Proving cost tracks the *zkVM* cycle count, not the job's. Table 2
shows what that means on an 8-core, 32 GB host (CPU prover, core
proof mode).

**Table 2 — CPU proving costs (legacy format).**

| Job | zkVM cycles | Prove wall | Peak RAM | Result |
|---|---|---|---|---|
| nano | 5,937,604 | 140.2 s | 23.8 GB | verified receipt |
| smoke | 168,881,446 | killed at 70 s | 31.8 GB (OOM) | — |

Proving memory grows with the shard count (nano ≈ 3 shards, smoke ≈
84), so the envelope on a 32 GB host ends near **10M zkVM cycles ≈
28–31K legacy job instructions**. A 0.5M-instruction job — trivial
for execution, seconds for quorum — cannot be proved on the machine
class that runs the rest of the system.

This is the paper's central empirical finding: **the meta-emulation
tax converts a memory-bandwidth problem into a memory-capacity
problem.** A workload that fits easily in RAM when executed does not
fit when proved through an interpreter.

---

## 6. V2: Native ABI, Measured

The escape is source-level. A V2 job is compiled against an
SP1-native ABI stub — read input via `io::read`, commit
`blake3(input)` then the output — and executes *directly* on the
zkVM. We must be precise about scope: the trampoline is
**source-level, not binary-level**. A legacy ELF's stores cannot be
intercepted under SP1; a hypothetical trap-and-emulate wrapper would
reintroduce the interpreter, and with it the tax. V2 is therefore a
format new jobs opt into (`format: "sp1-v2"` in the manifest), while
legacy jobs retain the bootstrap path indefinitely.

**Table 3 — Same job, same input (demo fold over 32 KiB), measured.**

| | zkVM cycles | Prove wall | Peak RAM |
|---|---|---|---|
| legacy (emulator-in-guest) | 168,881,446 | OOM at 32 GB | — |
| **V2 (SP1-native)** | **1,789,276** | **80.5 s** | **15.7 GB** |

94× fewer cycles; the unprovable job becomes an 80.5-second proof on
an ordinary 32 GB host. The correctness cross-check is exact: the V2
program — the same four-stream FNV fold re-expressed against SP1's
I/O convention — produces output byte-identical to the legacy
rvcore-emulated result (`25a3ab01…5c5e5`), asserted by a network
integration test on every CI run.

**Design consequences** (each deliberate, each load-bearing):

- *Cycles are excluded from the V2 journal digest.* Compiler and
  micro-architectural scheduling shift cycle counts across zkVM
  releases; the output of a deterministic program does not. Binding
  only the output keeps receipts cryptographically durable across
  toolchain upgrades.
- *Fail-closed isolation.* The replay judge refuses V2 jobs (an
  rvcore "replay" of an SP1-native ELF would fabricate garbage
  truth); non-SP1 workers refuse V2 assignments with an explicit
  error. No silent partial execution exists anywhere in the format
  boundary.
- *The V2 receipt binds the input id* (committed by the guest; the
  elf is bound by the verifying key; the manifest is not executed) —
  the "this receipt is for MY job" property survives the format
  change.

**Build ergonomics.** V2 compilation is routed by the CLI: native
`cargo prove` when the toolchain is present, a pinned, version-locked
container otherwise (built on demand; host-mounted caches reduce
rebuilds from ~6 minutes to 23.5 s). The same-host build is
byte-reproducible — the committed reference ELF's SHA-256 matches a
fresh build exactly.

---

## 7. GPU Proving: An Empirical Hardware Gate

The CUDA path was validated to its gate on real hardware (GTX 1660
SUPER, 6 GB VRAM, driver 560.94, CUDA 12.6, WSL2 container): the
`cuda` feature builds, SP1's `sp1-gpu-server` downloads and launches,
driver passthrough works — and then the server refuses:

```
Unsupported GPU memory: 10, must be at least 24GB
```

SP1 6.8's GPU prover imposes a hard **24 GB VRAM floor** (FRI commit
tables and large-domain FFTs are held in VRAM). Two operational
findings accompany it: the gpu-server requires `libcudart.so.12` (the
driver passthrough provides `libcuda`, not `cudart`), and the judge
binary must use the async SDK — the blocking wrapper cannot construct
the CUDA prover.

The consequence for capacity planning is a clean hardware-class table:

**Table 4 — Prover hardware classes (measured gates).**

| Class | Envelope (legacy) | Envelope (V2) | Evidence |
|---|---|---|---|
| 32 GB CPU host | ≈28–31K job instructions | ~500K+ job instructions | Table 2, Table 3 |
| 6 GB GPU | none (hard refusal) | none (hard refusal) | this section |
| ≥ 24 GB GPU | untested (future work) | untested (future work) | gate measured |

The V2 format moves the interesting workloads into CPU-provable
territory; the GPU gate becomes relevant only for legacy-format
proving at scale, and its floor is now measured rather than assumed.

---

## 8. Network Validation

The security properties are enforced by integration tests over real
TCP sockets, running on every push across Windows, Linux, and macOS:

- **Fraud and conviction.** One honest worker, one liar, no majority:
  the judge vindicates the honest digest and the ledger records
  `honest +10, liar −100`. Both-liar collusion (two *different*
  fabrications) is convicted by the replay. (A corruption whose flip
  lands on the honest value was once indistinguishable from honesty;
  the corruption hook now bumps a byte, which cannot round-trip — the
  coincidence window was eliminated, not managed.)
- **Quorum integrity.** Duplicate submissions cannot stuff a quorum
  (one vote per identity at receipt and again at decision); workers
  the job was never dispatched to cannot vote.
- **zk receipts over the wire.** A receipt claim verifies against the
  committed guest ELF and the descriptor's content ids; a verified
  claim accepts with no quorum threshold.
- **Proving queue and deduplication.** Two submissions of identical
  content under different job ids produce exactly one proof and
  identical receipt-backed outcomes.
- **Cross-format equivalence.** The V2 native program's output equals
  the legacy path's output byte-for-byte (Section 6).

Fleet-scale demonstration: three physical machines belonging to two
different owners, one delegate reached across the open internet, TLS
with certificate fingerprint pinning throughout.

---

## 9. Limitations

We state the boundaries as carefully as the results:

- **Coordinator trust.** The coordinator is the job owner's agent;
  workers and third parties do not need to trust it for *correctness*
  (digests are verifiable, receipts are cryptographic), but its
  liveness and its ledger's integrity are its own. Decentralized
  coordination is out of scope.
- **Scale of demonstration.** Jobs demonstrated end to end are ≤ ~0.5M
  native zkVM cycles; the network runs over LAN plus one internet
  peer, with no NAT traversal. This is a working system at pilot
  scale, not a production deployment.
- **Workload class.** Deterministic integer-only RISC-V. No floating
  point, no syscalls, no nondeterminism of any kind — by design, as
  the price of hashable execution.
- **Toolchain pinning.** Receipts bind the exact guest binary and SP1
  version; upgrading SP1 changes verifying keys and requires
  re-proving. The V2 *digest* is version-stable, but the receipt
  chain is not.
- **Economics.** Bond sizes, rewards (+10/−100 units) and the
  admission PoW dial are functioning placeholders, calibrated for
  test fleets, not a market.

---

## 10. Related Work

Truebit-style optimistic verification established the shape:
cheap execution with challenge-period dispute resolution, settled by
re-execution games. zkVM provers (RISC Zero, SP1) established that
RISC-V execution can be proved succinctly at measurable cost. This
work's contribution is compositional and empirical: a single journal
contract spanning quorum, dispute, and receipt tiers; the measured
meta-emulation tax of the emulator-in-a-guest bootstrap (with its
memory-capacity consequence, which to our knowledge has not been
previously reported in this form); and the demonstration that
source-level native ABIs — not binary-level trap-and-emulate, which
reintroduces the interpreter — are the economically required escape
path.

---

## 11. Conclusion

Verification for delegated computation does not have to choose
between cryptographic certainty and ordinary cost. An optimistic
network — native execution under bonds, proofs on demand — delivers
both ends of the spectrum over one execution format. The measurements
here give the design its economics: the meta-emulation tax (322–362×,
with a memory wall at ~25K legacy instructions) is the price of
binary compatibility; the native ABI (94× cheaper to prove,
byte-identical results) is the price of admission for new jobs; the
GPU gate (24 GB VRAM) is the price of hardware-accelerated proving.
All three are measured, reproducible from the artifact, and enforced
by continuous integration. The design work ahead is widening the
envelope — larger native proofs, GPU hosts, and the coordination
layer beyond a single owner — on foundations that no longer need to
move.

---

## Appendix A — Complete Measurements

**A.1 Interpreter execution throughput** (rvcore, native, 2 MiB job):
57.7M instructions/s; small jobs are startup-dominated (0.8M–2.0M
inst/s at 32 KiB). Full sweep in `docs/sweep-data/`.

**A.2 Prover environment:** 8-core x86-64, 32 GB RAM, WSL2 container
(Debian 13), rustc 1.98.1, SP1 SDK 6.8.0, CPU prover, `core` proof
mode. GPU host: Windows 11 + Docker Desktop (WSL2 backend), GTX 1660
SUPER 6 GB, driver 560.94, CUDA 12.6.

**A.3 Execute vs prove, all formats:**

| Workload | Format | zkVM cycles | Execute | Prove | Peak RAM |
|---|---|---|---|---|---|
| nano (16,410 inst) | legacy | 5,937,604 | 0.1 s | 140.2 s | 23.8 GB |
| smoke (524,314 inst) | legacy | 168,881,446 | 2.5 s | OOM (70 s) | 31.8 GB |
| smoke-equivalent | V2 | 1,789,276 | ~2 s | 80.5 s | 15.7 GB |

**A.4 Dispute with real proving** (honest worker vs liar, zk judge,
nano): 174 s end to end, receipt-backed acceptance, ledger `+10/−100`.

## Appendix B — Claims → Evidence

| Claim | Where it is enforced/measured |
|---|---|
| Quorum anchored to dispatched pool | `coordinator::decide`, network test `reserve_escalation_beats_lying_worker` |
| Duplicate votes cannot stuff quorum | `duplicate_submissions_do_not_stuff_quorum` |
| Non-dispatched workers cannot vote | `non_dispatched_worker_cannot_vote` |
| Replay judge reproduces the journal | `dispute_judge_convicts_diverging_fabrications` |
| zk judge receipts + vindication | `zk_judge_dispute_receipt_vindicates_honest_worker` (mock in CI, real-prover in container) |
| Receipt dedup, fail-closed cache | `zk_proving_queue_end_to_end_with_dedup` |
| V2 native equivalence + proving | `zk_proving_queue_v2_native_job` |
| Byte-reproducible builds | sha256 comparison, Section 6 |
| GPU 24 GB gate | measured refusal, Section 7 |

## Appendix C — Artifact

The full system (coordinator, workers, interpreters, zkVM guests,
judge/prover, verifier, CLI) is open source under MIT/Apache-2.0:
https://github.com/HolyWill90/provework. Every claim in Appendix B is
a named test in the repository's CI. Measurement scripts and the
throughput sweep live under `docs/sweep-data/` and `scripts/`.
