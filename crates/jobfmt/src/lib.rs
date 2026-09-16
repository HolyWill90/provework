use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

/// A job directory is the unit of distribution:
///   job.json     — this manifest
///   program.elf  — the pinned-toolchain RISC-V image
///   input.bin    — the input blob
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobManifest {
    pub schema: u32,
    pub id: String,
    pub name: String,
    /// Pinned ISA string; must equal abi::ISA.
    pub isa: String,
    /// Toolchain description for humans; the emulator contract is the
    /// ISA, this field documents what built the ELF.
    pub toolchain: String,
    pub chunk_size: u64,
    pub max_instructions: u64,
    pub verification_class: String,
    pub elf: String,
    pub input: String,
}

#[derive(Debug, Clone)]
pub struct Job {
    pub manifest: JobManifest,
    pub dir: PathBuf,
    pub elf: Vec<u8>,
    pub input: Vec<u8>,
}

pub const SCHEMA: u32 = 1;

/// The manifest names plain files inside the job directory. A manifest
/// is untrusted data (it arrives over the wire inside a descriptor), so
/// its file fields must not escape: exactly one normal path component,
/// no separators, no `..`.
pub fn confined_name(name: &str) -> Result<(), String> {
    // Backslashes are rejected on every platform: manifests are
    // portable, and on Windows a backslash IS a separator — the
    // strictest interpretation must hold everywhere.
    if name.contains('\\') {
        return Err(format!("manifest path {name:?} is not a plain file name"));
    }
    let p = Path::new(name);
    let ok = p.is_relative()
        && p.components().collect::<Vec<_>>().len() == 1
        && matches!(
            p.components().next(),
            Some(std::path::Component::Normal(_))
        );
    if ok {
        Ok(())
    } else {
        Err(format!("manifest path {name:?} is not a plain file name"))
    }
}

pub fn load_dir(dir: &Path) -> Result<Job, String> {
    let manifest_path = dir.join("job.json");
    let raw = std::fs::read(&manifest_path)
        .map_err(|e| format!("reading {}: {e}", manifest_path.display()))?;
    let manifest: JobManifest =
        serde_json::from_slice(&raw).map_err(|e| format!("parsing job.json: {e}"))?;
    if manifest.schema != SCHEMA {
        return Err(format!("job schema {} != {SCHEMA}", manifest.schema));
    }
    if manifest.isa != abi::ISA {
        return Err(format!(
            "job targets ISA '{}' but this emulator pins '{}'",
            manifest.isa,
            abi::ISA
        ));
    }
    confined_name(&manifest.elf)?;
    confined_name(&manifest.input)?;
    let elf = std::fs::read(dir.join(&manifest.elf))
        .map_err(|e| format!("reading elf: {e}"))?;
    let input = std::fs::read(dir.join(&manifest.input))
        .map_err(|e| format!("reading input: {e}"))?;
    Ok(Job { manifest, dir: dir.to_path_buf(), elf, input })
}

pub fn save_dir(dir: &Path, manifest: &JobManifest, elf: &[u8], input: &[u8]) -> Result<(), String> {
    confined_name(&manifest.elf)?;
    confined_name(&manifest.input)?;
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir: {e}"))?;
    let json = serde_json::to_vec_pretty(manifest).unwrap();
    std::fs::write(dir.join("job.json"), json).map_err(|e| format!("{e}"))?;
    std::fs::write(dir.join(&manifest.elf), elf).map_err(|e| format!("{e}"))?;
    std::fs::write(dir.join(&manifest.input), input).map_err(|e| format!("{e}"))?;
    Ok(())
}

/// What one worker reports. This is the artifact the quorum compares.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResult {
    pub worker_id: String,
    pub job_id: String,
    /// "halted" | "instruction_limit" | "trap"
    pub status: String,
    pub instructions: u64,
    /// Final chunk hash — the identity of the execution.
    pub result_hash: String,
    /// Full chunk hash chain (hex, lowercase).
    pub chunk_hashes: Vec<String>,
    /// Output bytes (hex) if the job halted.
    pub output_hex: Option<String>,
    /// Human-readable trap detail when status == "trap".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trap: Option<String>,
    /// Ed25519 public key of the worker (hex), when it has an identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey_hex: Option<String>,
    /// Ed25519 signature over `signing_message(self)` (hex). Binds the
    /// identity to the ENTIRE result — job id, status, instruction
    /// count, hash chain, and output — not just the final hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig_hex: Option<String>,
}

/// The consensus journal format: 8-byte little-endian instruction
/// count followed by the job's output bytes. Workers commit to
/// SHA-256(journal); the coordinator's replay judge must reproduce
/// the exact same bytes, so both construct it through this function.
pub fn journal(instructions: u64, output: &[u8]) -> Vec<u8> {
    let mut j = instructions.to_le_bytes().to_vec();
    j.extend_from_slice(output);
    j
}

/// The output portion of a [`journal`]: everything after the 8-byte
/// instruction-count prefix.
pub fn journal_output(journal: &[u8]) -> &[u8] {
    journal.get(8..).unwrap_or(&[])
}

/// The consensus commitment: SHA-256 over [`journal`]. Workers submit
/// this as `result_hash`; the replay judge reproduces it for compare.
pub fn journal_digest(instructions: u64, output: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(journal(instructions, output)).into()
}

/// The exact bytes a worker signs and a coordinator verifies: a
/// length-prefixed encoding of every result field except the key and
/// signature themselves. Explicit encoding rather than JSON so the
/// binding cannot drift with serde version or field ordering.
pub fn signing_message(r: &WorkerResult) -> Vec<u8> {
    let mut m = Vec::new();
    let put = |m: &mut Vec<u8>, b: &[u8]| {
        m.extend_from_slice(&(b.len() as u32).to_le_bytes());
        m.extend_from_slice(b);
    };
    put(&mut m, r.worker_id.as_bytes());
    put(&mut m, r.job_id.as_bytes());
    put(&mut m, r.status.as_bytes());
    m.extend_from_slice(&r.instructions.to_le_bytes());
    put(&mut m, r.result_hash.as_bytes());
    for h in &r.chunk_hashes {
        put(&mut m, h.as_bytes());
    }
    match &r.output_hex {
        Some(o) => put(&mut m, o.as_bytes()),
        None => m.extend_from_slice(&0u32.to_le_bytes()),
    }
    match &r.trap {
        Some(t) => put(&mut m, t.as_bytes()),
        None => m.extend_from_slice(&0u32.to_le_bytes()),
    }
    m
}

/// The bytes a worker signs when submitting a zk receipt claim:
/// length-prefixed job id + BLAKE3 of the raw receipt bytes. Binds the
/// identity to the specific receipt and job (the receipt itself is
/// cryptographically verified separately by the coordinator).
pub fn receipt_claim_message(job_id: &str, receipt_hash: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&(job_id.len() as u32).to_le_bytes());
    m.extend_from_slice(job_id.as_bytes());
    m.extend_from_slice(receipt_hash);
    m
}

/// The bytes a job submitter signs: length-prefixed job id plus the
/// descriptor's content id. Binds the submitter's identity to the
/// exact descriptor being queued.
pub fn submission_message(job_id: &str, descriptor_id: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&(job_id.len() as u32).to_le_bytes());
    m.extend_from_slice(job_id.as_bytes());
    m.extend_from_slice(descriptor_id);
    m
}

/// Hex decode failure: which string shape was rejected and why.
#[derive(Debug)]
pub enum HexError {
    BadLength { got: usize, want: usize },
    InvalidByte(u8),
}

impl std::fmt::Display for HexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HexError::BadLength { got, want } => write!(f, "bad length {got}/{want}"),
            HexError::InvalidByte(b) => write!(f, "invalid hex byte {b:#04x}"),
        }
    }
}

/// Panic-free fixed-length hex decode: exact length required, ASCII
/// hex only. Untrusted strings (pubkeys, signatures, hashes) arrive
/// over the wire — a byte-offset slice of a multi-byte UTF-8 char
/// would panic the caller, so decoding works on bytes instead.
pub fn from_hex(s: &str, expect: usize) -> Result<Vec<u8>, HexError> {
    if s.len() != expect * 2 {
        return Err(HexError::BadLength { got: s.len(), want: expect * 2 });
    }
    let b = s.as_bytes();
    let digit = |c: u8| -> Result<u32, HexError> {
        match c {
            b'0'..=b'9' => Ok((c - b'0') as u32),
            b'a'..=b'f' => Ok((c - b'a' + 10) as u32),
            b'A'..=b'F' => Ok((c - b'A' + 10) as u32),
            other => Err(HexError::InvalidByte(other)),
        }
    };
    b.as_chunks::<2>().0.iter()
        .map(|pair| {
            let hi = digit(pair[0])?;
            let lo = digit(pair[1])?;
            Ok(((hi << 4) | lo) as u8)
        })
        .collect()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confined_name_accepts_only_plain_names() {
        assert!(confined_name("program.elf").is_ok());
        assert!(confined_name("../escape").is_err());
        assert!(confined_name("a/b").is_err());
        assert!(confined_name("a\\b").is_err());
        assert!(confined_name("..").is_err());
        assert!(confined_name("/abs").is_err());
        assert!(confined_name("C:\\temp\\x").is_err());
    }

    #[test]
    fn from_hex_is_byte_safe() {
        assert_eq!(from_hex("00ff", 2).unwrap(), vec![0x00, 0xff]);
        assert!(from_hex("00f", 2).is_err()); // short
        assert!(from_hex("00fg", 2).is_err()); // non-hex
        // 32 repetitions of a two-byte UTF-8 char: right BYTE length,
        // but a byte-offset slice would straddle a char and panic.
        assert!(from_hex(&"\u{e9}".repeat(32), 32).is_err());
    }

    #[test]
    fn signing_message_binds_every_field() {
        let base = WorkerResult {
            worker_id: "w".into(),
            job_id: "j".into(),
            status: "halted".into(),
            instructions: 7,
            result_hash: "aa".into(),
            chunk_hashes: vec!["aa".into(), "bb".into()],
            output_hex: Some("cc".into()),
            trap: None,
            pubkey_hex: Some("pk".into()),
            sig_hex: Some("sig".into()),
        };
        let m0 = signing_message(&base);
        // The key and signature are NOT part of the message (they are
        // what authenticates it) — their presence must not change it.
        let mut no_meta = base.clone();
        no_meta.pubkey_hex = None;
        no_meta.sig_hex = None;
        assert_eq!(m0, signing_message(&no_meta));

        let mut r = base.clone();
        r.output_hex = None;
        assert_ne!(m0, signing_message(&r));
        let mut r = base.clone();
        r.instructions = 8;
        assert_ne!(m0, signing_message(&r));
        let mut r = base.clone();
        r.chunk_hashes = vec!["aa".into()];
        assert_ne!(m0, signing_message(&r));
        let mut r = base.clone();
        r.trap = Some("boom".into());
        assert_ne!(m0, signing_message(&r));
    }
}
