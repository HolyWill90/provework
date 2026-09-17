//! The wire protocol: length-prefixed JSON frames over a byte stream.
//!
//! Deliberately boring: the verification surface of this project is
//! the signed result JSON and the chunk-hash chains, so the transport
//! only has to move those reliably between peers. TLS and fancier
//! framings layer on top later; nothing here changes.

use std::io::{Read, Write};
use std::time::Duration;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub mod tls;

/// Any byte stream the wire protocol can run over: plain TCP or TLS.
pub trait ByteStream: Read + Write + Send {}
impl<T: Read + Write + Send> ByteStream for T {}

/// A boxed stream for sessions that may run over either transport.
pub type BoxedStream = Box<dyn ByteStream>;

/// Hard cap on a single frame's payload — a peer claiming a 4 GB
/// message is either broken or hostile.
pub const MAX_FRAME: u32 = 64 << 20;

#[derive(Debug)]
pub enum WireError {
    Io(std::io::Error),
    Malformed(String),
    ConnectionClosed,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Io(e) => write!(f, "wire i/o: {e}"),
            WireError::Malformed(s) => write!(f, "wire: {s}"),
            WireError::ConnectionClosed => write!(f, "wire: connection closed"),
        }
    }
}

pub fn send<T: Serialize>(stream: &mut impl Write, msg: &T) -> Result<(), WireError> {
    let json = serde_json::to_vec(msg).map_err(|e| WireError::Malformed(e.to_string()))?;
    if json.len() as u64 > MAX_FRAME as u64 {
        return Err(WireError::Malformed(format!(
            "frame too large: {} bytes",
            json.len()
        )));
    }
    stream
        .write_all(&(json.len() as u32).to_le_bytes())
        .map_err(WireError::Io)?;
    stream.write_all(&json).map_err(WireError::Io)?;
    stream.flush().map_err(WireError::Io)?;
    Ok(())
}

/// Polled receive: waits up to `idle` for a frame to START, then
/// reads the rest of the frame to completion (tolerating transient
/// WouldBlocks). Returns `Ok(None)` when idle — no frame started —
/// so the caller can interleave other work (outbound sends, polling)
/// on the same stream. Required for TLS, whose streams cannot be
/// cloned for reader/writer threads.
pub fn receive_polled<T: DeserializeOwned>(
    stream: &mut impl Read,
    idle: Duration,
) -> Result<Option<T>, WireError> {
    let started_at = std::time::Instant::now();
    let mut prefix = [0u8; 4];
    let mut got = 0usize;
    while got < 4 {
        match stream.read(&mut prefix[got..]) {
            Ok(0) => return Err(WireError::ConnectionClosed),
            Ok(n) => got += n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if got == 0 && started_at.elapsed() >= idle {
                    return Ok(None); // idle: nothing pending
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(WireError::Io(e)),
        }
    }
    read_frame_body::<T>(stream, u32::from_le_bytes(prefix)).map(Some)
}

fn read_frame_body<T: DeserializeOwned>(
    stream: &mut impl Read,
    len: u32,
) -> Result<T, WireError> {
    if len > MAX_FRAME {
        return Err(WireError::Malformed(format!(
            "peer announced a {len}-byte frame; limit is {MAX_FRAME}"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    let mut got = 0usize;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while got < buf.len() {
        match stream.read(&mut buf[got..]) {
            Ok(0) => return Err(WireError::ConnectionClosed),
            Ok(n) => got += n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if std::time::Instant::now() > deadline {
                    return Err(WireError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "frame body stalled",
                    )));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(WireError::Io(e)),
        }
    }
    serde_json::from_slice(&buf).map_err(|e| WireError::Malformed(e.to_string()))
}

pub fn receive<T: DeserializeOwned>(stream: &mut impl Read) -> Result<T, WireError> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(WireError::ConnectionClosed)
        }
        Err(e) => return Err(WireError::Io(e)),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(WireError::Malformed(format!(
            "peer announced a {len}-byte frame; limit is {MAX_FRAME}"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).map_err(WireError::Io)?;
    serde_json::from_slice(&buf).map_err(|e| WireError::Malformed(e.to_string()))
}

fn default_role() -> String {
    "worker".to_string()
}

/// Messages sent by a worker (client) to the coordinator.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ClientToServer {
    /// Introduce the worker's Ed25519 public key; the server replies
    /// with Nonce to prove key possession.
    Hello {
        pubkey_hex: String,
        worker_id: String,
        /// When set, the daemon serves blobs to peers on this port.
        listen_port: Option<u16>,
        /// "worker" (default) — eligible for job dispatch; "submitter"
        /// — submits jobs and waits for the outcome, never dispatched.
        #[serde(default = "default_role")]
        role: String,
    },
    /// Signature over the nonce bytes (when the worker has an
    /// identity) plus the admission proof-of-work counter.
    NonceSignature { sig_hex: Option<String>, pow_counter: u64 },
    /// Fetch a content-store blob by hash (the torrent layer online).
    BlobRequest { id_hex: String },
    /// A completed, signed execution result.
    JobResult { result: jobfmt::WorkerResult },
    /// A job owner submits a descriptor for execution. The connection
    /// must be authenticated (same Hello/PoW/nonce flow as workers);
    /// the signature is over `jobfmt::submission_message` — the job id
    /// plus the descriptor's content id — binding the identity to the
    /// exact submitted job.
    JobSubmission {
        submitter: String,
        descriptor: contentstore::JobDescriptor,
        pubkey_hex: String,
        sig_hex: String,
        /// High-assurance mode: skip worker consensus entirely; the
        /// coordinator's prover produces an SP1 receipt for the job
        /// and the outcome is receipt-backed (`zk: true`). Proving is
        /// queued, not synchronous — the ack returns immediately and
        /// the JobOutcome arrives when the proof lands.
        #[serde(default)]
        require_zk: bool,
    },
    /// A job blob upload from an authenticated submitter whose store
    /// is not the coordinator's filesystem: the bytes are accepted
    /// only if BLAKE3(bytes) == id_hex (content-addressed trust), and
    /// land in the coordinator's store under that id.
    BlobUpload { id_hex: String, bytes_hex: String },
    /// A zk receipt claim: the worker attaches a verified SP1 receipt
    /// for the whole job (hex of the bincode-serialized receipt). The
    /// signature is over `jobfmt::receipt_claim_message`.
    ReceiptClaim {
        worker_id: String,
        job_id: String,
        pubkey_hex: String,
        sig_hex: String,
        receipt_hex: String,
    },
}

/// Messages sent by the coordinator to a worker.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ServerToClient {
    /// Random bytes: sign these to prove possession of the Hello key.
    /// `pow_bits` is the admission proof-of-work difficulty the client
    /// must meet before authentication.
    Nonce { hex: String, pow_bits: u32 },
    /// Identity verified; the server assigned this worker id.
    AuthOk { worker_id: String },
    AuthFailed { reason: String },
    /// Execute this job. The worker materializes the descriptor's
    /// blobs (peers first, coordinator as fallback) and reads the
    /// manifest for execution parameters.
    JobAssignment {
        descriptor: contentstore::JobDescriptor,
        /// Connected peers that may already hold the blobs — the
        /// p2p fetch path ahead of the coordinator fallback.
        peer_hints: Vec<String>,
    },
    /// Response to a BlobRequest; None = unknown hash.
    Blob { hex: Option<String> },
    /// A job batch ended; stay connected, more jobs may come.
    BetweenJobs,
    /// Final message: the session is over.
    ShutDown { reason: String },
    /// Sent to a job submitter when the submitted job reaches a
    /// decision: the accepted hash (or the judge's true hash), the
    /// vindicated workers, the output, and whether a zk receipt
    /// decided it.
    JobOutcome {
        job_id: String,
        hash: String,
        agreed: Vec<String>,
        output_hex: Option<String>,
        zk: bool,
        rejected_reason: Option<String>,
    },
    /// Reply to a BlobUpload: whether the blob was accepted (hash
    /// verified) and stored.
    BlobAck { id_hex: String, accepted: bool, reason: Option<String> },
    /// Immediate reply to a JobSubmission: whether the descriptor
    /// landed in the watched queue (or the zk proving queue).
    SubmissionAck {
        job_id: String,
        accepted: bool,
        reason: Option<String>,
        /// True when the job was accepted into the zk proving queue
        /// instead of worker dispatch (require_zk submissions).
        #[serde(default)]
        proving: bool,
    },
}

/// Direct worker-to-worker blob exchange (the p2p path). A daemon
/// with `listen_port` set runs a tiny server speaking this protocol.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum PeerToPeer {
    PeerBlobRequest { id_hex: String },
    PeerBlob { hex: Option<String> },
}

/// The descriptor lives with the content store conceptually, but the
/// wire needs it too — re-export to keep one definition.
pub use content_descriptor::JobDescriptor;

/// Placeholder module trick avoided: JobDescriptor is defined in
/// contentstore; wire depends on it for the protocol.
pub mod content_descriptor {
    pub use contentstore::JobDescriptor;
}


/// Admission proof-of-work: find `counter` such that
/// BLAKE3(nonce || counter_le) has at least `bits` leading zero bits.
/// This is the cost of joining: a slashed or banned identity pays it
/// again on every new connection, which is what makes identity-based
/// bookkeeping bite. Expected work is 2^bits hashes.
pub fn mine_pow(nonce: &[u8], bits: u32) -> u64 {
    let mut counter: u64 = 0;
    loop {
        if verify_pow(nonce, counter, bits) {
            return counter;
        }
        counter += 1;
    }
}

/// Verify an admission proof-of-work solution.
pub fn verify_pow(nonce: &[u8], counter: u64, bits: u32) -> bool {
    let bits = bits.min(256);
    let mut h = blake3::Hasher::new();
    h.update(nonce);
    h.update(&counter.to_le_bytes());
    let digest = h.finalize();
    leading_zero_bits(digest.as_bytes()) >= bits
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut n = 0u32;
    for &b in bytes {
        if b == 0 {
            n += 8;
        } else {
            n += b.leading_zeros();
            break;
        }
    }
    n
}


#[cfg(test)]
mod pow_tests {
    use super::*;

    #[test]
    fn mine_then_verify_roundtrips() {
        let nonce = [7u8; 32];
        let counter = mine_pow(&nonce, 12);
        assert!(verify_pow(&nonce, counter, 12));
        assert!(!verify_pow(&nonce, counter.wrapping_add(1), 12));
    }

    #[test]
    fn zero_bits_always_passes() {
        assert!(verify_pow(&[0u8; 32], 0, 0));
        assert!(mine_pow(&[1u8; 32], 0) == 0);
    }

    #[test]
    fn different_nonce_invalidates_solution() {
        let counter = mine_pow(&[2u8; 32], 8);
        assert!(!verify_pow(&[3u8; 32], counter, 8));
    }
}
