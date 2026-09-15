# One Hash Chain, Three Tiers: Selectable Verification for Untrusted Compute

## Preprint skeleton — v0.1 outline

Every claim below maps to a table or figure that either has data
(`docs/sweep-data/`) or names the experiment that will produce it.

---

## Abstract (draft)

We present a verification substrate for delegated computation in which
a single per-execution artifact — a BLAKE3 hash chain over the entire
architectural state of a pinned RISC-V virtual machine — supports three
selectable verification tiers with different cost/trust tradeoffs:

1. **Quorum**: N independent executions with bounded fraud (random
   sampling, admission proof-of-work, dispute-judge arbitration).
2. **Optimistic + dispute**: 1× execution with a one-slice
   re-execution judgment on challenge.
3. **zk receipt**: a STARK proof over the emulator itself executing
   the actual job binary — verification without re-execution or trust
   in any worker.

All three tiers consume the same chain, making the tier selectable per
job without changing the computation, the distribution format, or the
evidence format. We demonstrate the full stack on real hardware
(three machines, two owners, one WAN peer), close every finding from
five adversarial review rounds with regression tests, and measure the
execution/verification cost curve across job sizes and chunk
configurations.

---

## 1. Introduction

- The delegated-computation trust problem (citations: Truebit, Teutsch
  & Reitwießner; Cartesi Dave, arXiv:2405.00149; PeerReview, NSDI'04).
- Why existing systems leave the composition open (survey results —
  each system picks one verification mechanism; none tie three tiers
  to one chain).
- Contribution list:
  1. The chain-and-tiers composition.
  2. Same-ELF zk receipts (the production emulator proven inside a
     zkVM, bound to job content hashes).
  3. A security-hardened implementation: five review rounds, all
     findings fixed with regression tests.
  4. A measured cost table across tiers and job sizes.

## 2. Design

### 2.1 The pinned VM and the determinism contract

RV64IMC, flat 4 GiB, integer-only, no hidden state. The contract is
enforced by construction and verified by differential testing against
QEMU and 67/67 official riscv-tests. *(Table 1: contract → enforcement
mechanism.)*

### 2.2 The chunk-hash chain

Every architectural field is hashed (registers, pc, machine CSRs,
memory digest). The chain is a pure function of the execution — an
emulator that allocated memory differently would still produce this
exact root. *(Figure 1: chain structure; Table 2: what each tier
consumes from it.)*

### 2.3 Tier selection

Per-job `verification_class` selects the tier. The quorum tier's
threshold is anchored to the dispatched pool (not responders); the
dispute tier's judge re-executes the first divergent slice; the zk
tier verifies a receipt over the emulator binary itself, bound to job
content hashes. *(Table 3: adversary → detected by which tier, at what
cost.)*

### 2.4 The trust model

The coordinator is trusted for selection and arbitration. Workers are
untrusted. Admission proof-of-work prices identity; ledger slashing
prices fraud. These limits are stated, not hidden.

## 3. Implementation

- Substrate: ~X kLOC Rust across 9 crates.
- The sandbox: integer-only RV64IMC, ~84M inst/s measured (§6.1).
- Hardening ledger: five external review rounds; N findings, all fixed
  with regression tests (§5.3, Table 4).

## 4. Same-ELF zk receipts

The guest is the emulator itself, compiled into the SP1 zkVM. The
receipt commits a job binding (BLAKE3 over manifest, ELF and input —
the descriptor's content ids) and the full execution journal.
Verification re-derives the verifying key from the committed guest
ELF, so a receipt only verifies against the exact emulator binary it
claims. *(§6.3: measured verification cost and envelope.)*

## 5. Security evaluation

### 5.1 Adversarial model

Worker-side: result forgery, quorum stuffing, replay, collusion,
griefing. Coordinator-side: trusted for selection and arbitration
(stated). Network-side: pre-authentication attacks on the submission
and decode paths.

### 5.2 Review-ledger results

Five rounds; the classes found (quorum vote stuffing, signature
coverage, snapshot forgery, path traversal, overflow, pre-auth DoS,
verifier stall) and their fixes. *(Table 4: finding → fix → test.)*

### 5.3 The replay judge

Collusion with divergent fabrications is convicted by re-execution:
the judge's true chain matches honest workers and contradicts all
fabrications simultaneously, including 2-of-N colluding majorities…
*(bounded: the coordinator's own replay is the trust anchor at this
tier; stated.)*

## 6. Evaluation

### 6.1 Execution throughput

Native-vs-emulated ratio across job sizes; the page-table lookaside
result (4.5×). *(Figure 2: sweep data, docs/sweep-data/sweep.csv.)*

### 6.2 Verification costs per tier

Quorum: N executions + judge (only on no-majority). Dispute: one-slice
re-execution on challenge. zk: verify vs prove cost curve across job
sizes. *(Table 5 + Figure 3: the crossover.)*

### 6.3 zk receipt envelope

Measured: nano job (~16K instructions) proves in ~20 min at 31 GB;
multi-shard blocked in SP1 6.8. The honest scaling wall. *(Table 6.)*

### 6.4 End-to-end demonstrations

Three machines, two owners; a WAN peer via port-forward; fraud
detected, judged and slashed in the ledger. *(Figure 4: the flow.)*

## 7. Limitations

As stated in the repository's honest-limits section — reproduced here
verbatim, not summarized.

## 8. Related work

Truebit, Cartesi (Dave), iExec (PoCo), Bacalhau, SP1/RISC Zero,
PeerReview, Gensyn — and the composition gap each leaves open
(see the prior-art survey).

## 9. Conclusion

The chain-and-tiers composition, the same-ELF receipt, and the
hardened implementation; the honest scaling wall; the call for the
missing piece (prover compute).

---

## Tables/figures checklist

| # | Claim | Data status |
|---|---|---|
| T1 | Contract → enforcement | written |
| T2 | Tier → chain consumption | written |
| T3 | Adversary → tier → cost | written |
| T4 | Review findings → fixes → tests | data exists (repo history) |
| F2 | Execution throughput sweep | measured (sweep.csv) |
| T5/F3 | Verification cost per tier | **needs experiment**: prove/verify time per job size |
| T6 | zk envelope | measured (nano); multi-shard blocked |
| F4 | Fleet demonstration | ran; screenshots/logs exist |
