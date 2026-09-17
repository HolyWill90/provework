# Building on provework — the integration guide

prowork is a **base**: a working verification substrate that other
projects build applications on. This document is for the builder who
wants to do exactly that. It maps the interfaces you touch, the
guarantees you inherit, and the limits you accept.

---

## The one-paragraph model

A **job** is a deterministic integer-only program (RISC-V, or V2:
SP1-native) plus an input blob. **Workers** execute it; a
**coordinator** dispatches, verifies, and keeps a ledger. Every
execution reduces to a journal, and every verification tier consumes
the same commitment. You write the program; you choose the trust
tier; the substrate handles dispatch, transport, verification,
fraud handling, and evidence.

## The four interfaces you touch

### 1. The job ABI (write programs against this)

- **Legacy (`rv-abi`):** bare-metal RV64IMC. Input at `0x1000_0000`
  (u64 length, then bytes), output at `0x2000_0000` (u64 length,
  then bytes), image base `0x8000_0000`, stack top `0x83F0_0000`,
  halt via `ebreak`. Pinned ISA: `rv64imc` — no atomics, no floats,
  no syscalls. Scaffold: `jobkit new`.
- **V2 (`sp1-v2`):** an SP1-native guest — read input via
  `sp1_zkvm::io::read`, commit `blake3(input)` then your output via
  `sp1_zkvm::io::commit`. Runs directly on the zkVM (no emulator,
  ~94× cheaper to prove), executable only by SP1 fleets. Scaffold:
  `jobkit new <name> --v2`.

Determinism is the contract: the same input must always produce the
same output on any host. Anything that breaks that (clocks, threads,
floats, randomness) is outside the ABI by design.

### 2. The journal contract (what consensus and receipts commit to)

- Legacy: `journal = u64_le(instructions) || output`; commitment =
  `SHA-256(journal)`. The instruction count is architectural state
  (rvcore's count) and IS bound.
- V2: `journal = u64_le(0) || output`; commitment = `SHA-256(journal)`.
  SP1 cycle counts are a compiler/SDK artifact and are deliberately
  NOT bound. V2 receipts commit `blake3(input)` as the job binding.
- Workers sign the full result (ed25519 over all fields); the
  coordinator's judge reproduces the identical journal bytes.

### 3. The wire protocol (build your own client or coordinator)

Length-prefixed JSON frames over TCP or TLS 1.3
(`crates/wire`). Client roles authenticate by Ed25519 nonce
signature plus per-connection admission proof-of-work. Messages:
`Hello` (with role worker/submitter), `Nonce`, `NonceSignature`,
`JobAssignment`, `JobResult`, `BlobRequest`/`Blob` (peer-to-peer),
`BlobUpload`/`BlobAck` (cross-machine submissions),
`JobSubmission`/`SubmissionAck`/`JobOutcome` (submitters),
`ReceiptClaim` (zk tier). TLS: the coordinator generates a
self-signed certificate; clients pin its BLAKE3 fingerprint
(`wire::tls::client_stream_pinned`).

### 4. The trust-tier dial (what you choose per submission)

| Tier | How | When |
|---|---|---|
| Quorum (N=3→5) | default dispatch | cheap jobs, fraud tolerated |
| Optimistic + dispute | escalation/reserves | 1× cost, judged on challenge |
| zk receipt | `submit --require-zk` | high assurance; proof replaces consensus |

The receipt queue deduplicates by
`BLAKE3(manifest_id ‖ elf_id ‖ input_id)` — identical content proves
once. Receipts verify offline (`jobkit verify`), no coordinator
required.

## Guaranteed vs. your responsibility

**Inherited from the substrate:** dispatch and quorum anchoring,
identity + admission PoW, TLS with fingerprint pinning,
content-addressed blob integrity, fraud detection + bonded slashing,
replay/zk judging, evidence bundles, receipt verification.

**Your responsibility:** program determinism (the ABI cannot enforce
it for arbitrary logic — pin your dependencies, avoid nondeterminism),
input and output *semantics* (the substrate verifies the execution
happened, not that your program computes what you meant), operating a
coordinator (it is the job owner's agent), and any multi-tenant or
payment layer above the ledger.

## Measured envelopes (see docs/PREPRINT.md, Tables 1–4)

- Legacy job through the emulator-in-guest: 322–362× cycle
  multiplier; CPU-provable to ≈28–31K job instructions on a 32 GB
  host; 168.9M-cycle job proves in 34.2 s on a 32 GB Blackwell GPU.
- V2 native: 1.79M cycles for the same 32 KiB job (94× fewer);
  2.8 s GPU / 80.5 s CPU; ≈1.4M job instructions CPU-provable on
  32 GB.
- Interpreter throughput: up to 57.7M instructions/s (2 MiB job).

## Declared limits (do not build on these yet)

- Single coordinator (no decentralized coordination).
- No NAT traversal — fleets over LAN or reachable addresses.
- Native V2 jobs require an SP1 fleet (Linux workers); legacy jobs
  run everywhere.
- Receipts bind the exact SP1 toolchain version; upgrades re-key the
  verifying set.
- The ledger's economics (+10/−100, PoW dial) are calibrated
  placeholders, not a market.

## License

MIT OR Apache-2.0 for the entire tree (see
docs/LICENSE-STRATEGY.md). Job code you write is yours to license
however you want — the scaffolds impose nothing.
