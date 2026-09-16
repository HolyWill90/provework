//! zk dispute judge: when a job has no worker majority, the
//! coordinator may escalate to an external SP1 prover process
//! (`sp1-host`'s `zk-judge` binary) that re-executes the disputed job
//! inside the zkVM and returns a cryptographic receipt. The
//! coordinator does NOT link the SP1 SDK: proving needs a memory and
//! time envelope a coordinator must not carry, and the SDK does not
//! build on every platform. The process protocol:
//!
//!   argv: <job-dir> <max-vm-cycles> <guest-elf> [receipt-out]
//!   stdout: one JSON verdict (see the binary's docs)
//!
//! The verdict's hash is never trusted directly: the coordinator
//! re-derives the journal digest from the verdict's own (instruction
//! count, output) pair, and cross-checks the job binding against the
//! descriptor's content ids.

use crate::Decision;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ZkJudge {
    /// Path of the zk-judge binary (built from sp1-host).
    pub cmd: String,
    /// The committed guest ELF the judge must execute.
    pub guest_elf: PathBuf,
    /// Fail fast BEFORE proving when the execution's VM cycle count
    /// exceeds this. The emulator-in-a-zkVM multiplies job
    /// instructions ~300x, so this bound is what keeps a hostile or
    /// oversized job from burning unprovable compute.
    pub max_vm_cycles: u64,
    /// Hard wall-clock limit for the whole judge invocation (execute
    /// + prove + verify). Expiry kills the process and the judge
    /// falls back to the replay judge.
    pub timeout: Duration,
    /// When set, the receipt is saved to this directory as
    /// {job_id}.receipt.bin — the evidence bundle's third-party
    /// checkable artifact. This is ALSO where the high-assurance
    /// receipt cache lives ({receipt_dir}/zk-cache/).
    pub receipt_dir: Option<PathBuf>,
    /// The standalone zk-verify binary: used to verify CACHED
    /// receipts before a cache hit is trusted. Without it, cache
    /// hits are refused and the job re-proves — a cache is never
    /// trusted on faith.
    pub verify_cmd: Option<String>,
}

/// The dedup key for high-assurance receipts: BLAKE3 over the
/// descriptor's three content ids (manifest, elf, input) in fixed
/// order. Deterministic execution means the same (program, input)
/// always proves to the same receipt — so a second requester pays
/// nothing for a receipt someone already paid for.
pub fn receipt_cache_key(descriptor: &contentstore::JobDescriptor) -> String {
    let mut material = Vec::new();
    for id in [&descriptor.manifest, &descriptor.elf, &descriptor.input] {
        let bytes =
            jobfmt::from_hex(id, 32).expect("descriptor content ids are 32-byte hex");
        material.extend_from_slice(&bytes);
    }
    let key: [u8; 32] = blake3::hash(&material).into();
    hex(&key)
}

#[derive(Debug, Clone, Deserialize)]
pub struct JudgeVerdict {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub status: Option<u32>,
    #[serde(default)]
    pub instructions: Option<u64>,
    #[serde(default)]
    pub output_hex: Option<String>,
    #[serde(default)]
    pub vm_cycles: Option<u64>,
    #[serde(default)]
    pub proving_secs: Option<f64>,
    #[serde(default)]
    pub binding: Option<Vec<String>>,
}

/// A judge process gone rogue cannot wedge the coordinator: stdout
/// reads are capped and the invocation has a hard wall-clock limit.
const MAX_VERDICT_BYTES: usize = 1024 * 1024;

pub fn run_judge(
    cfg: &ZkJudge,
    job_dir: &Path,
    receipt_out: Option<&Path>,
) -> Result<JudgeVerdict, String> {
    let mut cmd = Command::new(&cfg.cmd);
    cmd.arg(job_dir)
        .arg(cfg.max_vm_cycles.to_string())
        .arg(&cfg.guest_elf);
    if let Some(out) = receipt_out {
        if let Some(dir) = out.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("receipt dir: {e}"))?;
        }
        cmd.arg(out);
    }
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("zk judge spawn ({}): {e}", cfg.cmd))?;

    let deadline = Instant::now() + cfg.timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                let _ = child.kill();
                return Err(format!("zk judge wait: {e}"));
            }
        }
    };
    let mut stdout_bytes = Vec::new();
    if let Some(mut out) = child.stdout.take() {
        use std::io::Read;
        // Cap the read so a runaway judge cannot balloon memory.
        let mut chunk = [0u8; 8192];
        loop {
            match out.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    stdout_bytes.extend_from_slice(&chunk[..n]);
                    if stdout_bytes.len() > MAX_VERDICT_BYTES {
                        let _ = child.kill();
                        return Err("zk judge verdict exceeds size cap".into());
                    }
                }
            }
        }
    }
    let Some(status) = status else {
        return Err(format!(
            "zk judge exceeded the {:?} time limit — falling back to replay",
            cfg.timeout
        ));
    };
    let stdout = String::from_utf8_lossy(&stdout_bytes);
    let verdict: JudgeVerdict = serde_json::from_str(stdout.trim())
        .map_err(|e| format!("zk judge output: {e} (stderr: {})", {
            let mut s = String::new();
            if let Some(mut err) = child.stderr.take() {
                use std::io::Read;
                let _ = err.read_to_string(&mut s);
            }
            s
        }))?;
    // A judge that ran but rejected exits nonzero AFTER printing its
    // verdict; success plus ok:false is contradictory either way.
    if !verdict.ok {
        return Err(verdict.error.clone().unwrap_or_else(|| "judge rejected".into()));
    }
    if !status.success() {
        return Err(format!("zk judge exited with {status}"));
    }
    Ok(verdict)
}

/// The decision a verified verdict implies. Pure so tests can drive
/// it without a prover. `expected_binding` is the descriptor's
/// (manifest, elf, input) content ids: a verdict for any other job is
/// rejected outright.
pub fn judge_decision(
    verdict: &JudgeVerdict,
    expected_binding: &[[u8; 32]; 3],
    v2: bool,
) -> Result<Decision, String> {
    if !verdict.ok {
        return Err(verdict
            .error
            .clone()
            .unwrap_or_else(|| "judge rejected".into()));
    }
    let binding_hex = verdict.binding.as_ref().ok_or("verdict missing binding")?;
    if v2 {
        // V2 receipts commit the input id only; the elf is bound by
        // the verifying key and the manifest is not executed.
        if binding_hex.len() != 1 {
            return Err("v2 verdict binding malformed".into());
        }
        let bytes = jobfmt::from_hex(&binding_hex[0], 32)
            .map_err(|e| format!("binding hex: {e}"))?;
        if bytes.as_slice() != &expected_binding[2] {
            return Err("judge verdict is not for this job's input".into());
        }
    } else {
        if binding_hex.len() != 3 {
            return Err("verdict binding malformed".into());
        }
        for (hex_id, expected) in binding_hex.iter().zip(expected_binding) {
            let bytes = jobfmt::from_hex(hex_id, 32).map_err(|e| format!("binding hex: {e}"))?;
            if bytes.as_slice() != expected {
                return Err("judge verdict is not for this job's (manifest, elf, input)".into());
            }
        }
    }
    let status = verdict.status.ok_or("verdict missing status")?;
    let instructions = verdict.instructions.ok_or("verdict missing instructions")?;
    let output_hex = verdict.output_hex.clone().ok_or("verdict missing output")?;
    let output = jobfmt::from_hex(&output_hex, output_hex.len() / 2)
        .map_err(|e| format!("verdict output hex: {e}"))?;
    // The digest is RECOMPUTED here, never read from the process.
    let hash = hex(&jobfmt::journal_digest(instructions, &output));
    if status == 0 {
        Ok(Decision::Accept {
            hash,
            output_hex: Some(output_hex),
            agreed: Vec::new(),
            zk: true,
        })
    } else {
        Ok(Decision::Reject {
            reason: format!("zk judge: job does not halt cleanly (status {status})"),
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The receipt-cache layout under the configured receipt dir:
/// `{dir}/zk-cache/{key}.receipt.bin` plus a `.json` sidecar with the
/// prove metadata (proven_at, vm_cycles, proving_secs).
pub fn cache_paths(receipt_dir: &Path, key: &str) -> (PathBuf, PathBuf) {
    let dir = receipt_dir.join("zk-cache");
    (
        dir.join(format!("{key}.receipt.bin")),
        dir.join(format!("{key}.verdict.json")),
    )
}

/// Turn a cache lookup into a decision. A cache hit is only trusted
/// after the SAME external verification a worker-submitted receipt
/// claim goes through: the zk-verify binary re-derives the verifying
/// key from the guest ELF and cryptographically checks the receipt
/// against this job's binding. Anything else is treated as a miss.
pub fn verify_cached(
    zk: &ZkJudge,
    receipt_dir: &Path,
    key: &str,
    expected_binding: &[[u8; 32]; 3],
    v2: bool,
) -> Option<Decision> {
    let Some(verify_cmd) = &zk.verify_cmd else { return None };
    let (receipt_path, _) = cache_paths(receipt_dir, key);
    let receipt_bytes = std::fs::read(&receipt_path).ok()?;
    let outcome = crate::receipt::verify_receipt(
        verify_cmd,
        &receipt_bytes,
        expected_binding,
        &zk.guest_elf,
        v2,
    )
    .ok()?;
    if outcome.status != 0 {
        return None;
    }
    let output = jobfmt::from_hex(&outcome.output_hex, outcome.output_hex.len() / 2).ok()?;
    let count = if v2 { jobfmt::V2_JOURNAL_COUNT } else { outcome.instructions };
    let hash = hex(&jobfmt::journal_digest(count, &output));
    Some(Decision::Accept {
        hash,
        output_hex: Some(outcome.output_hex),
        agreed: Vec::new(),
        zk: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(ok: bool, status: u32, instructions: u64, output_hex: &str) -> JudgeVerdict {
        // Binding ids are 32-byte content hashes — hex-encoded at 64
        // chars each, first byte first (the byte order the descriptor
        // carries).
        let id = |b: u8| format!("{b:02x}{}", "0".repeat(62));
        serde_json::from_str(&format!(
            "{{\"ok\":{ok},\"status\":{status},\"instructions\":{instructions},\"output_hex\":\"{output_hex}\",\"binding\":[\"{}\",\"{}\",\"{}\"]}}",
            id(0xaa),
            id(0xbb),
            id(0xcc)
        ))
        .unwrap()
    }

    fn binding() -> [[u8; 32]; 3] {
        let mut b = [[0u8; 32]; 3];
        b[0][0] = 0xaa;
        b[1][0] = 0xbb;
        b[2][0] = 0xcc;
        b
    }

    #[test]
    fn verdict_digest_is_recomputed_not_trusted() {
        // instructions=5, output=01: journal = 05..00 || 01, digest
        // must equal SHA-256 of that — recompute independently here.
        let v = verdict(true, 0, 5, "01");
        let d = judge_decision(&v, &binding(), false).unwrap();
        let Decision::Accept { hash, zk, agreed, output_hex } = d else {
            panic!("expected accept");
        };
        assert!(zk);
        assert!(agreed.is_empty());
        assert_eq!(output_hex.as_deref(), Some("01"));
        let mut journal = 5u64.to_le_bytes().to_vec();
        journal.push(1);
        let expect: Vec<String> = {
            use sha2::{Digest as _};
            sha2::Sha256::digest(&journal)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        };
        assert_eq!(hash, expect.join(""));
    }

    #[test]
    fn verdict_for_a_different_job_is_rejected() {
        let v = verdict(true, 0, 5, "01");
        let mut wrong = binding();
        wrong[2][0] = 0xff;
        let err = judge_decision(&v, &wrong, false).unwrap_err();
        assert!(err.contains("not for this job"), "got: {err}");
    }

    #[test]
    fn trapped_job_is_a_reject_not_an_accept() {
        let v = verdict(true, 2, 5, "01");
        let d = judge_decision(&v, &binding(), false).unwrap();
        assert!(matches!(d, Decision::Reject { .. }));
    }

    #[test]
    fn failing_verdict_is_an_error() {
        let v: JudgeVerdict = serde_json::from_str("{\"ok\":false,\"error\":\"boom\"}").unwrap();
        let err = judge_decision(&v, &binding(), false).unwrap_err();
        assert!(err.contains("boom"));
    }
}
