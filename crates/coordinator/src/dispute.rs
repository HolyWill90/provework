//! The dispute game: two committed chunk-hash chains disagree, a judge
//! decides which side computed honestly.
//!
//! The judge's authority comes from re-execution against the *agreed
//! prefix*. Both parties committed to every chunk hash; they agree on
//! hashes `0..k` and diverge at `k`. The state at boundary `k-1` is
//! therefore pinned by an agreed hash preimage — impossible to fake —
//! so the judge only needs to establish the true hash at `k`:
//!
//! - **Snapshot path** (fast): take a snapshot at boundary `k-1` from
//!   either side (untrusted), verify
//!   `state_hash(chain[k-2], snap) == chain[k-1]`, execute one chunk,
//!   hash. Cost: one chunk.
//! - **Replay path** (fallback, also required when k = 0): re-run the
//!   job from genesis and read the authoritative chain. Cost: full job.
//!
//! First divergence decides the dispute; the winner is whichever side's
//! committed hash matches the judge's result.

use jobfmt::WorkerResult;
use rvcore::{execute_chunk_from, state_hash, Config, Hash, GENESIS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Chains are identical — nothing to dispute.
    Agreement,
    /// The claim side (A) matches the judge at the first divergence.
    ClaimHonest { first_divergence: usize },
    /// The counter side (B) matches the judge at the first divergence.
    CounterHonest { first_divergence: usize },
    /// Neither side matches the judge: both committed false chains.
    BothDishonest { first_divergence: usize },
    Malformed(String),
}

pub struct DisputeInput<'a> {
    pub claim: &'a WorkerResult,
    pub counter: &'a WorkerResult,
    /// Job pieces needed by the replay judge.
    pub elf: &'a [u8],
    pub entry: u64,
    pub input: &'a [u8],
    pub chunk_size: u64,
    pub max_instructions: u64,
    /// Optional snapshot directory (either worker's, untrusted).
    pub snapshot_dir: Option<&'a std::path::Path>,
}

pub fn decode_chain(hexes: &[String]) -> Result<Vec<Hash>, String> {
    hexes
        .iter()
        .map(|h| {
            let mut out = [0u8; 32];
            if h.len() != 64 {
                return Err(format!("bad hash length {}", h.len()));
            }
            for (i, b) in out.iter_mut().enumerate() {
                *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16)
                    .map_err(|_| format!("bad hex at byte {i}"))?;
            }
            Ok(out)
        })
        .collect()
}

/// First index where the chains differ, or where the shorter one ends.
/// `None` only when the chains are identical.
pub fn first_divergence(a: &[Hash], b: &[Hash]) -> Option<usize> {
    for i in 0..a.len().max(b.len()) {
        match (a.get(i), b.get(i)) {
            (Some(x), Some(y)) if x == y => {}
            _ => return Some(i),
        }
    }
    None
}

/// Apply the judge's truth at the divergence point.
pub fn verdict_with_truth(a: &[Hash], b: &[Hash], k: usize, truth: Option<Hash>) -> Verdict {
    match truth {
        None => Verdict::Malformed("judge produced no hash at the divergence".into()),
        Some(t) => match (a.get(k) == Some(&t), b.get(k) == Some(&t)) {
            (true, false) => Verdict::ClaimHonest { first_divergence: k },
            (false, true) => Verdict::CounterHonest { first_divergence: k },
            (true, true) => Verdict::Agreement, // unreachable by construction; stay safe
            (false, false) => Verdict::BothDishonest { first_divergence: k },
        },
    }
}

/// Authoritative chain from a full re-execution from genesis.
pub fn judge_by_replay(
    elf: &[u8],
    entry: u64,
    input: &[u8],
    chunk_size: u64,
    max_instructions: u64,
) -> Option<Vec<Hash>> {
    let image = rvcore::elf::parse(elf).ok()?;
    let mut mem = rvcore::Mem::new();
    rvcore::elf::load(&mut mem, &image).ok()?;
    let cfg = Config { chunk_size, max_instructions, ..Default::default() };
    Some(rvcore::interp::run(&mut mem, entry, input, &cfg).chunk_hashes)
}

/// Authoritative re-execution from genesis: returns the instruction
/// count and output bytes an honest worker would have produced, so
/// the network judge can construct the identical consensus journal.
pub fn replay_journal(
    elf: &[u8],
    entry: u64,
    input: &[u8],
    chunk_size: u64,
    max_instructions: u64,
) -> Option<(u64, Vec<u8>)> {
    let image = rvcore::elf::parse(elf).ok()?;
    let mut mem = rvcore::Mem::new();
    rvcore::elf::load(&mut mem, &image).ok()?;
    let cfg = Config { chunk_size, max_instructions, ..Default::default() };
    let outcome = rvcore::interp::run(&mut mem, entry, input, &cfg);
    Some((outcome.instructions, outcome.output.unwrap_or_default()))
}

/// Fast judge: one chunk executed from a verified snapshot. Returns
/// `None` when the snapshot path is unavailable (k = 0, missing file)
/// or the snapshot fails verification — callers fall back to replay.
pub fn judge_by_snapshot(
    dir: &std::path::Path,
    k: usize,
    agreed: &[Hash],
    chunk_size: u64,
) -> Option<Hash> {
    if k == 0 || agreed.len() < k {
        return None;
    }
    let bytes = std::fs::read(dir.join(format!("snap-{}.bin", k - 1))).ok()?;
    let (cpu, mem) = rvcore::snapshot::restore(&bytes).ok()?;
    // The snapshot claims to be the state at boundary k-1. The chain
    // hash h_i = H(h_{i-1}, state_i), so verification against the
    // agreed prefix is a preimage check: a forged snapshot fails.
    let prev_boundary = if k == 1 { GENESIS } else { agreed[k - 2] };
    if state_hash(&prev_boundary, &cpu, &mem) != agreed[k - 1] {
        return None;
    }
    let (h, _end, _n) = execute_chunk_from(&bytes, &agreed[k - 1], chunk_size).ok()?;
    let _ = _end; // boundary or exit — both are legitimate chain entries at k
    Some(h)
}

pub fn resolve(inp: &DisputeInput) -> Verdict {
    let (a, b) = match (decode_chain(&inp.claim.chunk_hashes), decode_chain(&inp.counter.chunk_hashes)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => return Verdict::Malformed(e),
    };
    if a == b {
        return Verdict::Agreement;
    }
    let k = match first_divergence(&a, &b) {
        Some(k) => k,
        None => return Verdict::Agreement,
    };

    // Snapshot fast path first; fall back to full replay.
    let truth = inp
        .snapshot_dir
        .and_then(|d| judge_by_snapshot(d, k, &a, inp.chunk_size))
        .or_else(|| {
            judge_by_replay(inp.elf, inp.entry, inp.input, inp.chunk_size, inp.max_instructions)
                .and_then(|ch| ch.get(k).copied())
        });

    verdict_with_truth(&a, &b, k, truth)
}
