pub mod dispute;
pub mod ledger;
pub mod net;
pub mod optimistic;
pub mod receipt;
pub mod zk_judge;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jobfmt::WorkerResult;

/// Quorum decision over a pool of worker results.
///
/// This is the budget tier of verification: it never proves a result
/// correct (unless `zk` is set — a verified SP1 receipt over the
/// emulator itself needs no consensus at all). It bounds the probability of accepting a wrong answer by
/// independent random sampling (P(all N sampled workers collude) =
/// f^N for a cheating fraction f) and makes detected fraud
/// economically irrational via bonds. The zk tier is what removes the
/// trust assumption entirely; this tier is what runs cheaply today.
#[derive(Debug, Clone, serde::Serialize)]
pub enum Decision {
    /// Majority hash + the output of the agreeing group + worker ids.
    /// `zk` marks an acceptance made on a verified SP1 receipt: one
    /// cryptographic proof replaces the worker consensus, and the
    /// quorum threshold does not apply.
    Accept { hash: String, output_hex: Option<String>, agreed: Vec<String>, zk: bool },
    /// Initial pool was inconclusive; add more workers (escalation).
    Escalate,
    /// No majority in the full pool, or a majority of failed runs:
    /// the job fails and bonds are burned.
    Reject { reason: String },
}

fn group_by<'a>(results: &[&'a WorkerResult]) -> Vec<(String, Vec<&'a WorkerResult>)> {
    let mut groups: Vec<(String, Vec<&WorkerResult>)> = Vec::new();
    for r in results {
        match groups.iter_mut().find(|(h, _)| *h == r.result_hash) {
            Some((_, g)) => g.push(r),
            None => groups.push((r.result_hash.clone(), vec![r])),
        }
    }
    groups
}

/// `expected_pool` is the number of workers DISPATCHED for this round
/// (3 = initial, 5 = after one escalation) — not the number of results
/// received. The threshold is a strict majority OF THE DISPATCHED
/// pool: a quorum that shrinks to whoever answered in time would let
/// one slow-network survivor self-approve a result. Responders fewer
/// than the threshold therefore escalate or reject, never accept.
pub fn decide(pool_results: &[WorkerResult], expected_pool: usize) -> Decision {
    // One vote per worker, even if a caller hands us raw duplicates:
    // quorum counts workers, not messages. (The network layer also
    // enforces this at receipt; this is the second line of defense.)
    let mut seen = std::collections::HashSet::new();
    let deduped: Vec<&WorkerResult> = pool_results
        .iter()
        .filter(|r| seen.insert(r.worker_id.clone()))
        .collect();
    // A received count above the dispatched pool is itself anomalous
    // (duplicate identities); it must never lower the bar.
    let received = deduped.len();
    let pool = expected_pool.max(received);
    let threshold = pool / 2 + 1;
    let refs: Vec<&WorkerResult> = deduped;

    let halted: Vec<&WorkerResult> = refs.iter().copied().filter(|r| r.status == "halted").collect();
    // The trapped-majority heuristic counts RECEIVED results only:
    // workers that never answered are not evidence that the job is
    // broken (the anchored `pool` below is for the accept threshold).
    let trapped = received - halted.len();

    if halted.len() >= threshold {
        let mut groups = group_by(&halted);
        groups.sort_by_key(|(_, g)| std::cmp::Reverse(g.len()));
        let (hash, group) = &groups[0];
        if group.len() >= threshold {
            // Workers that agree on the final hash must agree on the
            // full chain; a disagreement is a dispute condition. The
            // binary-search dispute game is a later milestone; for now
            // an inconsistent winning group is a rejection, never a
            // silent accept.
            let first_chain = &group[0].chunk_hashes;
            let chains_consistent =
                group.iter().all(|r| &r.chunk_hashes == first_chain);
            if chains_consistent {
                return Decision::Accept {
                    hash: hash.clone(),
                    output_hex: group[0].output_hex.clone(),
                    agreed: group.iter().map(|r| r.worker_id.clone()).collect(),
                    zk: false,
                };
            } else {
                return Decision::Reject {
                    reason: "winning group disagrees on chunk chain (dispute required)".into(),
                };
            }
        }
    }

    if trapped >= threshold {
        return Decision::Reject { reason: "majority of workers trapped: job is broken".into() };
    }

    if pool >= 5 {
        return Decision::Reject {
            reason: "no majority after escalation; bonds returned".into(),
        };
    }

    Decision::Escalate
}

/// Total bond economics placeholder: a worker caught contradicting the
/// accepted majority loses its bond; workers in the winning group get
/// paid. The numbers live with the coordinator's ledger, not here.
pub fn slashing(decision: &Decision, pool_results: &[WorkerResult]) -> Vec<(String, i64)> {
    // Slashing requires PROOF of deviation: an accepted majority that
    // the worker's result sits outside of. A rejected job (timeout,
    // exhausted escalation) proves nothing about any individual
    // responder — a lone honest worker whose peers timed out is
    // indistinguishable from a liar — so bonds are returned untouched.
    // Slow-worker griefing is instead priced by the admission
    // proof-of-work, which every reconnection re-charges.
    match decision {
        Decision::Accept { agreed, .. } => pool_results
            .iter()
            .map(|r| {
                let id = r.worker_id.clone();
                if agreed.contains(&id) {
                    (id, 10) // reward units
                } else {
                    (id, -100) // bond burn units
                }
            })
            .collect(),
        _ => pool_results.iter().map(|r| (r.worker_id.clone(), 0)).collect(),
    }
}

/// Verify a worker's Ed25519 signature over the ENTIRE result — job
/// id, status, instruction count, hash chain, and output, via
/// [`jobfmt::signing_message`]. Any field tampered after signing fails
/// verification. An unsigned result fails only when the coordinator
/// requires identities — callers decide the policy; this function is
/// the check. All decoding is panic-free: the strings are untrusted.
pub fn verify_signature(r: &WorkerResult) -> Result<(), String> {
    let (pk_hex, sig_hex) = match (&r.pubkey_hex, &r.sig_hex) {
        (Some(pk), Some(sig)) => (pk, sig),
        _ => return Err("result is unsigned".into()),
    };
    let bad = |what: &str, e: jobfmt::HexError| format!("{what}: {e}");
    let pk_bytes = jobfmt::from_hex(pk_hex, 32).map_err(|e| bad("pubkey", e))?;
    let sig_bytes = jobfmt::from_hex(sig_hex, 64).map_err(|e| bad("signature", e))?;
    let msg = jobfmt::signing_message(r);
    let vk = VerifyingKey::from_bytes(&pk_bytes.try_into().unwrap())
        .map_err(|e| format!("pubkey: {e}"))?;
    let sig = Signature::from_bytes(&sig_bytes.try_into().unwrap());
    vk.verify(&msg, &sig).map_err(|e| format!("signature: {e}"))
}
