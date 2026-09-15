# Qualifying a workload for provework

Not every computation benefits from provable execution. This page is
the filter: a workload that passes all four fits below is a genuine
candidate; one failed fit means the system offers you nothing over
just running the code.

Read the costs first, because they are the honest headline:

> **The sandbox runs integer code at roughly 1/100th to 1/1000th of
> native speed.** A computation that takes 1 second natively takes
> ~2 to 20 minutes per machine here. Verification (quorum) requires
> N machines to run it independently. If that trade does not buy you
> something you currently pay for, stop here.

## Fit 1 — Sandbox-fit (can it run at all?)

The job is a self-contained Rust program compiled for RV64IMC and
executed in a flat 4 GiB address space. It must be:

- **Integer-only.** No floating point, no atomics. Financial math in
  integer cents qualifies; scientific simulation with floats does not.
- **Deterministic.** Same input → same receipt chain on every machine.
  No ambient randomness, no clocks, no hashing of uninitialized memory.
- **Self-contained.** No network, no filesystem (input arrives in
  memory; results are written to memory), no dynamic linking.
- **Bounded.** ≤ 4 GiB working set, and the instruction count fits
  your patience: at ~84M instructions/sec, 1 billion instructions ≈
  12 s; 100 billion ≈ 20 min.

**Fails here?** Floating-point-heavy simulation, anything needing a
database or an API, latency-sensitive work. (Some near-misses can be
restructured: replace floats with fixed-point integer math, pass the
data in memory instead of fetching it.)

## Fit 2 — Trust-fit (is there a live trust problem?)

The system pays off only when the executor cannot simply be trusted.
Ask: **who runs this computation today, and why would I doubt them?**

- A vendor or partner computes something you depend on, and you
  currently accept their result on faith or re-run it yourself.
- Two parties who distrust each other need one agreed number
  (settlements, scoring, shared-data computations).
- The result will be audited or disputed later, and you need
  instruction-level evidence of what was computed.
- The executor is cheap/untrusted infrastructure (spot capacity,
  volunteers, strangers' machines) on purpose.

**No trust problem?** A computation you run yourself on your own
hardware needs no receipt — the sandbox offers you nothing over
`cargo run`.

## Fit 3 — Economic-fit (does verification beat the alternative?)

Compare against **the assurance mechanism the parties use today** —
not against raw execution cost:

| Today's mechanism | provework's alternative |
|---|---|
| Re-run everything yourself | Verify the receipt: quorum = read N signed chains; dispute = judge re-executes one slice |
| Trust the vendor's word | Cryptographic receipt bound to the exact binary and input |
| TEE attestation | No hardware trust anchor: the proof is over open, auditable code |
| Legal contract / escrow | Automatic slashing in the ledger on detected fraud |

The honest comparison: if today's assurance is a signed contract and
a shrug, provework is *more* work but *more* evidence. If today's
assurance is re-running everything N times yourself, provework's
dispute tier is *cheaper* (the judge re-executes one disputed slice,
not the whole job).

## Fit 4 — Scale-fit (is the envelope tolerable?)

Current demonstrated envelope (be honest with yourself):

- Execution: ~84M instructions/sec per machine (release build).
- zk receipts: verified at the nano envelope (~16K instructions,
  1 shard); multi-shard receipts await newer SP1/GPU proving.
- Quorum: N independent executions (N = 3 typical) — the budget tier
  does not prove correctness, it makes fraud detectable and bounded.
- Dispute judgment: the coordinator re-executes the disputed slice
  (bounded by the job's own instruction budget).

**Fails here?** Jobs whose honest execution takes hours of emulation,
or where you need zk receipts at scale today.

## Workloads that have already qualified

- **Deterministic hash pipelines** (the demo: FNV streams over a
  2 MiB input) — ran live across three machines, fraud convicted.
- **Compliance transformations in integer cents** — the archetype:
  simple logic, high audit value, every input field is a plain integer.
- **Exhaustive-search negativity claims** — the one class of result
  that cannot be checked without redoing the search; the receipt
  proves the exact traversal (needs the fit-1 and fit-4 bounds).

## Workloads that will never fit

- LLM inference or training (floats, terabytes, nondeterminism).
- Anything requiring network access mid-job, wall-clock timing, or
  hardware acceleration.
- Latency-sensitive anything: the verification story is batch-shaped.

## Porting guide (short form)

1. `jobkit new my-computation` — scaffolds a crate with the ABI
   inlined and the constraints in its README.
2. Move your logic into `_start()` in `src/main.rs`: read input bytes
   from `abi::INPUT_DATA_ADDR`, write results to
   `abi::OUTPUT_DATA_ADDR`, halt with `ebreak`.
3. Integer-ify: cents instead of dollars, fixed-point instead of
   floats, seeded LCG instead of `rand::thread_rng()`.
4. `jobkit build .` — the ELF is validated against the loader
   contract before anything ships.
5. `jobkit submit . --server <coordinator>` — you receive the outcome
   notice with the vindicated workers and the result hash.

Anything your program can't express without violating the constraints
(e.g., it needs to read a file, or roll dice) must be moved outside
the job: pass the data in as input, pass the randomness in as input,
and structure the program so its output is a pure function of the two.
