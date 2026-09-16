# Licensing Strategy

**Decision (2026-09): the entire repository remains dual-licensed
`MIT OR Apache-2.0`. No copyleft component is introduced. This
document records why, what would change the decision, and where the
real license boundaries are — so the choice is revisit-able without
being re-litigated from scratch.**

---

## 1. What exists vs. what was proposed

A component-based split was proposed: permissive (Apache/MIT) for the
"guest SDK" and "client verifier", copyleft-optional (Apache or AGPL)
for the "network core". The intent — permissive where third parties
embed code, restrictive where a hosted service might be taken — is
sound licensing practice. But a split requires **artifact boundaries
that exist as crates or linkable components**, and today they do not:

| Proposed component | What actually exists | License boundary today |
|---|---|---|
| Guest SDK & V2 ABI stubs | Scaffold templates (a few dozen lines copied into the user's own crate) + SP1's `sp1-zkvm` (already Apache-2.0, Succinct Labs) | Templates are plain files under the repo license; users license THEIR programs however they want |
| Client verifier | The `zk-verify` binary (sp1-host) + `jobkit verify` subcommand | Same repo, same license |
| Network core | worker, coordinator, wire, contentstore, ledger | Same repo, same license |

There is no separately-compiled guest SDK, no verifier library, and
no client crate — the verifier is a standalone binary and a thin CLI
wrapper. Splitting licenses across components that share one build
tree would create legal seams (file-level licensing, attribution
bookkeeping) with no corresponding technical boundary. If and when a
real embedding surface exists (e.g., a published `jobkit-verify`
crate for smart-contract use), a per-component license can be applied
at that boundary — which is exactly where it belongs.

## 2. The network core: Apache-2.0, with a stated revisit trigger

**Chosen: permissive (the current MIT OR Apache-2.0 dual).** The
AGPLv3 option for the worker/coordinator/proving queue was considered
and declined, for reasons specific to this project:

1. **Ecosystem gravity.** The entire stack sits on SP1 (Apache-2.0).
   RISC Zero, Cosmos, and the Rust infrastructure ecosystem are
   permissive; enterprise and government evaluation of AGPL network
   components is routinely blocked by policy. The project's next
   milestones are SBIR and enterprise pilots — the AGPL trade
   (protection against hosted-service competition, at the cost of
   adoption friction) buys nothing before there is a hosted service
   to protect.
2. **The moat is measured engineering, not license restrictions.**
   The defensible assets are the three-tier architecture, the
   journal contract, the measured performance envelopes, and the
   reference implementation's correctness record — plus, in an SBIR
   context, SBIR data rights over award-developed extensions.
3. **Solo-maintainer cost.** AGPL + permissive-periphery creates
   compatibility and attribution seams that one maintainer must
   police forever.

**Revisit trigger (written down so the decision is honest):** if a
hosted provework coordinator service launches as a product, AND
unhosted forks are observed operating competing hosted services from
this codebase, the network core (`worker`, `coordinator`, `wire`) is
the right boundary for a copyleft license — at that point the
copyright history is still single-owner and a relicense is legally
clean. After external contributions land, any relicense requires
contributor agreement (CLA/DCO with relicense consent) — which is
itself a reason to record this decision NOW.

## 3. SBIR / government IP

Substantively correct, worth stating precisely: open-sourcing the
platform does not forfeit SBIR data rights in data developed *under*
an award; SBIR data rights (20-year protection period) attach to
award-developed deliverables. Commercial value retained outside the
open core would live in award-developed proprietary components,
managed services, GPU proving capacity, and integrations — the
standard open-core shape. **This is not legal advice**: how open-source
publications interact with a specific award's IP terms must be
reviewed with the awarding agency's IP officer and counsel *before*
the proposal, not after — agency-specific rules (e.g., publication
timing, export control on cryptography) vary.

## 4. What this commit changes

- Every crate manifest now declares `license = "MIT OR Apache-2.0"`
  (previously undeclared — consumers and crates.io saw no license).
- `docker/sp1-toolchain.Dockerfile` and third-party note: the built
  images contain rustc/SP1 toolchains under their own licenses
  (Apache/MIT with LLVM exceptions); they are build tooling, not
  distributed products.
- No license text changes: LICENSE-MIT and LICENSE-APACHE remain the
  operative grant for the whole tree.

## 5. Summary

| Question | Decision |
|---|---|
| Single or split license? | Single dual license today; split only when a real artifact boundary exists (see §1) |
| Network core license | MIT OR Apache-2.0 (AGPL declined; revisit trigger recorded in §2) |
| User jobs / scaffolded code | User's choice — the scaffold templates impose nothing on the programs they become part of |
| Action required before SBIR submission | Counsel + agency IP officer review of award IP terms (§3) |
