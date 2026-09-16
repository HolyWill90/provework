//! zk tier: receipt verification via an external verifier process.
//!
//! The SP1 SDK does not build on every platform, and verification is a
//! distinct role from coordination, so the coordinator does NOT link
//! the SDK. Instead it spawns a verifier binary (built from
//! `sp1-host`: the `zk-verify` bin) that loads the receipt, re-derives
//! the verifying key from the committed guest ELF, and prints a JSON
//! verdict. A verified receipt attests that the pinned emulator — the
//! exact committed guest binary — executed the job's (manifest, elf,
//! input) and produced the committed chunk chain. One proof replaces
//! worker consensus: no quorum threshold applies.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ReceiptOutcome {
    pub status: u32,
    pub instructions: u64,
    pub chunk_hashes: Vec<String>,
    pub output_hex: String,
}

/// A receipt claim larger than this is dropped before any work: the
/// honest nano receipt is ~2.8 MB, and the verifier must never be
/// handed an unbounded blob (a stalled or pathological verification
/// run would otherwise freeze coordinator progress).
pub const MAX_RECEIPT_BYTES: usize = 64 * 1024 * 1024;
/// Hard wall-clock limit for one verifier invocation. The honest nano
/// verification takes ~1 s locally and up to ~60 s on slow CI
/// hardware (the verifier re-derives the verifying key from the guest
/// ELF on every invocation); anything far beyond that is killed and
/// rejected so the main loop cannot be wedged indefinitely by a
/// hostile claim.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(180);

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique, exclusively-created receipt file: the shared predictable
/// path this used to be was a race and symlink-replacement hazard
/// between concurrent claims (found by external review).
fn exclusive_receipt_file(bytes: &[u8]) -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join("p2pc-zk-verify");
    std::fs::create_dir_all(&dir).map_err(|e| format!("zk verify dir: {e}"))?;
    for _ in 0..32 {
        let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            dir.join(format!("receipt-{}-{n}.bin", std::process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                use std::io::Write;
                f.write_all(bytes)
                    .map_err(|e| format!("receipt write: {e}"))?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("receipt create: {e}")),
        }
    }
    Err("could not create a unique receipt temp file".into())
}

#[derive(Deserialize)]
struct Verdict {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    status: Option<u32>,
    #[serde(default)]
    instructions: Option<u64>,
    #[serde(default)]
    chain: Option<Vec<String>>,
    #[serde(default)]
    output_hex: Option<String>,
}

/// Verify `receipt_bytes` by spawning `cmd` (the zk-verify binary)
/// with the guest ELF and expected job binding. The receipt is passed
/// via a temp file: multi-megabyte argv would exceed OS limits.
pub fn verify_receipt(
    cmd: &str,
    receipt_bytes: &[u8],
    expected_binding: &[[u8; 32]; 3],
    guest_elf: &Path,
    v2: bool,
) -> Result<ReceiptOutcome, String> {
    if receipt_bytes.len() > MAX_RECEIPT_BYTES {
        return Err(format!(
            "receipt claim {} bytes exceeds the {} byte limit",
            receipt_bytes.len(),
            MAX_RECEIPT_BYTES
        ));
    }
    let receipt_path = exclusive_receipt_file(receipt_bytes)?;

    let binding_hex: Vec<String> =
        expected_binding.iter().map(|h| hex_upper(h)).collect();
    let mut child = match Command::new(cmd)
        .arg(guest_elf)
        .arg(&receipt_path)
        .args(v2.then_some("--v2"))
        .args(&binding_hex)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_file(&receipt_path);
            return Err(format!("zk verifier spawn ({cmd}): {e}"));
        }
    };

    // Hard wall-clock bound: a verifier that stalls (or a claim
    // engineered to be pathologically expensive) is killed after
    // VERIFY_TIMEOUT and the claim is rejected. The main loop stalls
    // for at most this long per bogus claim — bounded, not unbounded.
    let deadline = Instant::now() + VERIFY_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = std::fs::remove_file(&receipt_path);
                return Err(format!("zk verifier wait: {e}"));
            }
        }
    };
    let mut stdout_bytes = Vec::new();
    if let Some(mut out) = child.stdout.take() {
        use std::io::Read;
        let _ = out.read_to_end(&mut stdout_bytes);
    }
    let _ = std::fs::remove_file(&receipt_path);

    let Some(status) = status else {
        return Err(format!(
            "zk verifier exceeded the {:?} time limit — claim rejected",
            VERIFY_TIMEOUT
        ));
    };
    if !status.success() {
        // The verifier reports failures on stdout (the JSON verdict)
        // when it runs but rejects; stderr carries process-level errors.
        let out = String::from_utf8_lossy(&stdout_bytes);
        return Err(format!("zk verifier failed: {}", out.trim()));
    }
    let stdout = String::from_utf8_lossy(&stdout_bytes);
    let verdict: Verdict = serde_json::from_str(stdout.trim())
        .map_err(|e| format!("zk verifier output: {e}"))?;
    if !verdict.ok {
        return Err(verdict
            .error
            .unwrap_or_else(|| "receipt rejected".into()));
    }
    Ok(ReceiptOutcome {
        status: verdict.status.ok_or("verdict missing status")?,
        instructions: verdict.instructions.ok_or("verdict missing instructions")?,
        chunk_hashes: verdict.chain.ok_or("verdict missing chain")?,
        output_hex: verdict.output_hex.ok_or("verdict missing output")?,
    })
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_receipt_rejected_before_spawn() {
        let big = vec![0u8; MAX_RECEIPT_BYTES + 1];
        let binding = [[0u8; 32]; 3];
        let err = verify_receipt("definitely-not-a-real-binary", &big, &binding, Path::new("g"), false)
            .unwrap_err();
        assert!(err.contains("exceeds"), "got: {err}");
    }

    #[test]
    fn missing_verifier_is_a_clean_error() {
        let binding = [[0u8; 32]; 3];
        let err = verify_receipt(
            "definitely-not-a-real-binary-42",
            &[1, 2, 3],
            &binding,
            Path::new("guest"),
            false,
        )
        .unwrap_err();
        assert!(err.contains("spawn"), "got: {err}");
    }

    #[test]
    fn receipt_temp_files_are_unique_and_exclusive() {
        let a = exclusive_receipt_file(b"one").unwrap();
        let b = exclusive_receipt_file(b"two").unwrap();
        assert_ne!(a, b, "concurrent claims must not share a temp path");
        assert_eq!(std::fs::read(&a).unwrap(), b"one");
        assert_eq!(std::fs::read(&b).unwrap(), b"two");
        // Re-creating the same name must fail (exclusive create) — the
        // guarantee that defeats symlink/replacement races.
        assert!(std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&a)
            .is_err());
        let _ = std::fs::remove_file(a);
        let _ = std::fs::remove_file(b);
    }
}
