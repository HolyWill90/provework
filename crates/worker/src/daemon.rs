//! The worker daemon: connect to a coordinator, authenticate by
//! signing a nonce, then serve jobs indefinitely — fetch the job's
//! blobs from peers first (the p2p path), coordinator as fallback;
//! every byte is content-addressed and verified on arrival. Execute
//! in the deterministic emulator, sign the result, submit. The
//! session persists across many jobs; between jobs the daemon idles
//! on the wire, optionally serving blobs to peers.

use ed25519_dalek::{Signer, SigningKey};
use sha2::Digest;
#[cfg(feature = "sp1")]
use sp1_sdk::blocking::{Elf, Prover as _, ProverClient, SP1Stdin};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use wire::{ClientToServer, PeerToPeer, ServerToClient};

/// SP1's CPU prover is expensive to construct (it spins up its whole
/// worker machinery), so one instance is shared by every session and
/// job in the process.
#[cfg(feature = "sp1")]
fn sp1_prover() -> &'static sp1_sdk::blocking::CpuProver {
    static PROVER: std::sync::OnceLock<sp1_sdk::blocking::CpuProver> =
        std::sync::OnceLock::new();
    PROVER.get_or_init(|| ProverClient::builder().cpu().build())
}

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub server: String,
    pub worker_id: String,
    pub identity_path: Option<PathBuf>,
    /// Local blob cache (content-addressed; blobs dedup across jobs).
    pub store_dir: PathBuf,
    /// When set, the daemon serves blobs to peers on this port
    /// (port 0 = pick a free one; the real port is reported to the
    /// coordinator in Hello).
    pub listen_port: Option<u16>,
    /// Test hook: corrupt the result like a lying worker would.
    pub corrupt: bool,
    /// With `corrupt`: the journal byte index to bump (defaults to the
    /// last byte). Any ±1 bump guarantees divergence from the honest
    /// digest — there is no coincidental-match window.
    pub corrupt_byte: Option<u8>,
    /// Test hook: submit the result this many EXTRA times, emulating a
    /// worker trying to stuff the quorum with duplicate votes.
    pub extra_submits: u8,
    /// Path to an SP1 receipt (bincode) for the assigned job: when set
    /// and the assignment matches, the daemon submits a ReceiptClaim
    /// (the zk tier) instead of executing. The receipt is usually
    /// produced by a dedicated prover; the daemon just carries it.
    pub receipt_file: Option<PathBuf>,
    /// When set: the coordinator's certificate (DER) — the session
    /// runs over TLS pinned to this certificate's fingerprint.
    pub tls: Option<Vec<u8>>,
}

/// Counters returned when the session ends — the evidence for which
/// fetch path actually moved the bytes.
#[derive(Debug, Default, Clone)]
pub struct DaemonStats {
    pub jobs_done: usize,
    pub blobs_from_peers: usize,
    pub blobs_from_server: usize,
    pub blobs_served_to_peers: usize,
}

#[derive(Default)]
struct Counters {
    jobs: AtomicUsize,
    from_peers: AtomicUsize,
    from_server: AtomicUsize,
    served: AtomicUsize,
}

fn load_or_create_identity(path: &Path) -> SigningKey {
    if let Ok(seed) = std::fs::read(path) {
        if seed.len() == 32 {
            let arr: [u8; 32] = seed.try_into().unwrap();
            return SigningKey::from_bytes(&arr);
        }
    }
    let mut seed = [0u8; 32];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut seed);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create identity dir");
    }
    std::fs::write(path, seed).expect("write identity file");
    SigningKey::from_bytes(&seed)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    // Byte-based decoding: a char-boundary-straddling slice of a
    // multi-byte UTF-8 string would panic, so never slice by index.
    jobfmt::from_hex(s, s.len() / 2).ok()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Serve blobs to peers until the process ends. Every blob handed out
/// is counted — the p2p exchange is measured, not assumed.
fn spawn_peer_server(listener: TcpListener, store: Arc<contentstore::Store>, counters: Arc<Counters>) {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let store = store.clone();
            let counters = counters.clone();
            std::thread::spawn(move || {
                let Ok(PeerToPeer::PeerBlobRequest { id_hex }) =
                    wire::receive::<PeerToPeer>(&mut stream)
                else {
                    return;
                };
                let data = contentstore::ContentId::from_hex(&id_hex)
                    .ok()
                    .and_then(|cid| store.get(&cid).ok());
                if data.is_some() {
                    counters.served.fetch_add(1, Ordering::SeqCst);
                }
                let _ = wire::send(
                    &mut stream,
                    &PeerToPeer::PeerBlob { hex: data.as_ref().map(|d| hex(d)) },
                );
            });
        }
    });
}

/// Fetch one blob: peers first (in order), then the coordinator.
/// Every byte received is hash-verified against the requested id
/// before being stored — no trust in any serving peer.
fn fetch_blob(
    stream: &mut wire::BoxedStream,
    id_hex: &str,
    peer_hints: &[String],
    store: &contentstore::Store,
    counters: &Counters,
) -> Result<(), String> {
    let id = contentstore::ContentId::from_hex(id_hex)?;
    if store.has(&id)? {
        return Ok(()); // already cached from an earlier job
    }

    for peer in peer_hints {
        let Ok(mut peer_stream) = TcpStream::connect(peer) else { continue };
        peer_stream
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .ok();
        if wire::send(&mut peer_stream, &PeerToPeer::PeerBlobRequest { id_hex: id_hex.to_string() })
            .is_err()
        {
            continue;
        }
        if let Ok(PeerToPeer::PeerBlob { hex: Some(hex) }) =
            wire::receive::<PeerToPeer>(&mut peer_stream)
        {
            let bytes = hex_decode(&hex).ok_or("peer blob: bad hex")?;
            if contentstore::ContentId::from_data(&bytes) != id {
                return Err("peer blob: content does not match requested hash".into());
            }
            store.put(&bytes).map_err(|e| format!("store: {e}"))?;
            counters.from_peers.fetch_add(1, Ordering::SeqCst);
            println!("[p2p] fetched blob {} from peer {peer}", &id_hex[..12]);
            return Ok(());
        }
    }

    // Coordinator fallback.
    wire::send(stream, &ClientToServer::BlobRequest { id_hex: id_hex.to_string() })
        .map_err(|e| e.to_string())?;
    match wire::receive::<ServerToClient>(stream).map_err(|e| e.to_string())? {
        ServerToClient::Blob { hex: Some(hex) } => {
            let bytes = hex_decode(&hex).ok_or("blob: bad hex")?;
            if contentstore::ContentId::from_data(&bytes) != id {
                return Err("blob: content does not match requested hash".into());
            }
            store.put(&bytes).map_err(|e| format!("store: {e}"))?;
            counters.from_server.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        ServerToClient::Blob { hex: None } => Err(format!("blob {id_hex} not found on coordinator")),
        ServerToClient::BetweenJobs => {
            // The coordinator cancelled this job while we were
            // fetching (e.g. it expired). The session stays up; the
            // reconnect loop re-joins the pool for the next job.
            Err("__cancelled__".into())
        }
        other => Err(format!("expected Blob, got {other:?}")),
    }
}

/// How a single session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// The coordinator said goodbye — stop reconnecting.
    ServerShutdown,
    /// The connection dropped unexpectedly — reconnect.
    ConnectionLost,
}

/// Run the daemon across reconnects: a dropped connection is retried
/// with capped exponential backoff (a worker should be a durable
/// presence, not a fair-weather peer). Stats accumulate across
/// sessions; the loop ends only on a coordinator-initiated shutdown.
/// The per-worker directory a job materializes into. The job id comes
/// from an untrusted descriptor and lands inside a path that is then
/// `remove_dir_all`d — a crafted id with separators or `..` would
/// escape and delete or write outside the worker's scratch space.
pub fn job_materialize_dir(worker_id: &str, job_id: &str) -> Result<std::path::PathBuf, String> {
    jobfmt::confined_name(job_id)?;
    Ok(std::env::temp_dir().join(format!("p2pc-worker-{worker_id}-{job_id}")))
}

pub fn run_daemon(cfg: &DaemonConfig) -> Result<DaemonStats, String> {
    let counters = Arc::new(Counters::default());
    let mut backoff = std::time::Duration::from_secs(1);
    loop {
        eprintln!("[{}] session: connecting attempt", cfg.worker_id);
        let (end, stats) = match session_once(cfg, &counters) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[{}] session failed: {e}", cfg.worker_id);
                return Err(e);
            }
        };
        eprintln!(
            "[{}] session ended: {:?} (jobs so far: {})",
            cfg.worker_id,
            end,
            stats.jobs_done
        );
        match end {
            SessionEnd::ServerShutdown => return Ok(stats),
            SessionEnd::ConnectionLost => {
                println!(
                    "[{}] connection lost — reconnecting in {:?}",
                    cfg.worker_id, backoff
                );
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(std::time::Duration::from_secs(10));
                // Successful sessions reset the backoff.
                if counters.jobs.load(Ordering::SeqCst) > 0 {
                    backoff = std::time::Duration::from_secs(1);
                }
            }
        }
    }
}

fn stats_snapshot(counters: &Counters) -> DaemonStats {
    DaemonStats {
        jobs_done: counters.jobs.load(Ordering::SeqCst),
        blobs_from_peers: counters.from_peers.load(Ordering::SeqCst),
        blobs_from_server: counters.from_server.load(Ordering::SeqCst),
        blobs_served_to_peers: counters.served.load(Ordering::SeqCst),
    }
}

/// One connection's worth of session.
fn session_once(
    cfg: &DaemonConfig,
    counters: &Arc<Counters>,
) -> Result<(SessionEnd, DaemonStats), String> {

    // Optional peer blob server: bound before Hello so the real port
    // can be reported to the coordinator. A bind failure (port still
    // held by a dying previous session, for example) DEGRADES the
    // worker to fetch-only — it must never kill the daemon.
    let peer_server = match cfg.listen_port {
        Some(port) => match TcpListener::bind(("0.0.0.0", port)) {
            Ok(listener) => {
                let actual = listener.local_addr().map_err(|e| e.to_string())?.port();
                let store = Arc::new(
                    contentstore::Store::open(&cfg.store_dir).map_err(|e| e.to_string())?,
                );
                spawn_peer_server(listener, store, counters.clone());
                Some(actual)
            }
            Err(e) => {
                eprintln!(
                    "[{}] peer blob server unavailable ({e}) — fetch-only this session",
                    cfg.worker_id
                );
                None
            }
        },
        None => None,
    };

    let tcp = TcpStream::connect_timeout(
        &cfg.server.parse().map_err(|e| format!("server addr: {e}"))?,
        std::time::Duration::from_secs(30),
    )
    .map_err(|e| format!("connect: {e}"))?;
    let mut stream: wire::BoxedStream = match &cfg.tls {
        Some(cert_der) => {
            let client_cfg = wire::tls::client_config_pinned(cert_der)?;
            let server_name = rustls::pki_types::ServerName::try_from(
                cfg.server
                    .split(':')
                    .next()
                    .unwrap_or("localhost")
                    .to_string(),
            )
            .map_err(|e| format!("server name: {e}"))?;
            let conn = rustls::ClientConnection::new(Arc::new(client_cfg), server_name)
                .map_err(|e| format!("tls: {e}"))?;
            let mut tls = rustls::StreamOwned::new(conn, tcp);
            while tls.conn.is_handshaking() {
                if let Err(e) = tls.conn.complete_io(&mut tls.sock) {
                    eprintln!("[{}] tls handshake failed: {e}", cfg.worker_id);
                    return Err(format!("tls handshake failed: {e}"));
                }
            }
            println!(
                "[{}] TLS session established (coordinator fingerprint pinned)",
                cfg.worker_id
            );
            tls.sock
                .set_read_timeout(Some(std::time::Duration::from_secs(3600)))
                .ok();
            Box::new(tls)
        }
        None => {
            tcp.set_read_timeout(Some(std::time::Duration::from_secs(3600))).ok();
            Box::new(tcp)
        }
    };

    let signing_key = cfg.identity_path.as_ref().map(|p| load_or_create_identity(p));

    // 1. Hello + nonce challenge-response (proves key possession).
    let pubkey_hex = signing_key.as_ref().map(|k| hex(&k.verifying_key().to_bytes()));
    wire::send(
        &mut stream,
        &ClientToServer::Hello {
            pubkey_hex: pubkey_hex.clone().unwrap_or_default(),
            worker_id: cfg.worker_id.clone(),
            listen_port: peer_server,
        },
    )
    .map_err(|e| e.to_string())?;
    let (nonce, pow_bits) =
        match wire::receive::<ServerToClient>(&mut stream).map_err(|e| e.to_string())? {
            ServerToClient::Nonce { hex, pow_bits } => (hex, pow_bits),
            ServerToClient::AuthFailed { reason } => {
                return Err(format!("auth failed: {reason}"))
            }
            other => return Err(format!("expected Nonce, got {other:?}")),
        };
    let nonce_bytes = hex_decode(&nonce).ok_or("nonce: bad hex")?;
    // Admission proof-of-work: the server's fresh nonce makes this
    // cost per-connection, which is what a ban or slash re-charges.
    let pow_counter = wire::mine_pow(&nonce_bytes, pow_bits);
    if pow_bits > 0 {
        println!(
            "[{}] admission PoW mined: {pow_bits} bits",
            cfg.worker_id
        );
    }
    wire::send(
        &mut stream,
        &ClientToServer::NonceSignature {
            sig_hex: signing_key
                .as_ref()
                .map(|key| hex(&key.sign(&nonce_bytes).to_bytes())),
            pow_counter,
        },
    )
    .map_err(|e| e.to_string())?;

    // 2. Job loop — the session persists across many jobs.
    let store = contentstore::Store::open(&cfg.store_dir).map_err(|e| e.to_string())?;
    let mut submitted = false;
    loop {
        let received = wire::receive::<ServerToClient>(&mut stream);
        // A post-submit connection teardown (clean FIN or a RST — the
        // latter is what NAT/middleboxes and abrupt server closes
        // produce, e.g. across the internet) means the decision was
        // reached without a formal goodbye.
        let closed_cleanly =
            matches!(&received, Err(wire::WireError::ConnectionClosed));
        let reset_after_submit = matches!(
            &received,
            Err(wire::WireError::Io(e))
                if submitted && e.kind() == std::io::ErrorKind::ConnectionReset
        );
        if closed_cleanly || reset_after_submit {
            println!("[{}] session over: decision reached", cfg.worker_id);
            return Ok((
                SessionEnd::ServerShutdown,
                stats_snapshot(counters),
            ));
        }
        let message = received.map_err(|e| e.to_string())?;
        match message {
            ServerToClient::AuthOk { worker_id } => {
                println!("[{worker_id}] authenticated, waiting for jobs");
            }
            ServerToClient::BetweenJobs => {
                println!("[{}] between jobs — idle", cfg.worker_id);
            }
            ServerToClient::ShutDown { reason } => {
                println!("[{}] session over: {reason}", cfg.worker_id);
                return Ok((
                    SessionEnd::ServerShutdown,
                    stats_snapshot(counters),
                ));
            }
            ServerToClient::JobAssignment { descriptor, peer_hints } => {
                println!(
                    "[{}] job {} assigned — blobs: peers {:?} then coordinator",
                    cfg.worker_id, descriptor.job_id, peer_hints
                );

                for id in [&descriptor.manifest, &descriptor.elf, &descriptor.input] {
                    if let Err(e) = fetch_blob(&mut stream, id, &peer_hints, &store, counters) {
                        if e == "__cancelled__" {
                            println!(
                                "[{}] job {} cancelled by coordinator — waiting for the next one",
                                cfg.worker_id, descriptor.job_id
                            );
                            return Ok((SessionEnd::ConnectionLost, stats_snapshot(counters)));
                        }
                        eprintln!("[{}] blob fetch failed: {e} — connection lost", cfg.worker_id);
                        return Ok((SessionEnd::ConnectionLost, stats_snapshot(counters)));
                    }
                }

                // zk tier: a receipt carrier submits the proof instead
                // of executing. The claim is signed over the receipt's
                // hash, so the identity cannot be detached from it.
                if let Some(path) = &cfg.receipt_file {
                    let receipt_bytes = std::fs::read(path)
                        .map_err(|e| format!("receipt file: {e}"))?;
                    let receipt_hash: [u8; 32] =
                        blake3::hash(&receipt_bytes).into();
                    let sig = signing_key
                        .as_ref()
                        .ok_or("receipt claims require --identity")?
                        .sign(&jobfmt::receipt_claim_message(&descriptor.job_id, &receipt_hash));
                    wire::send(
                        &mut stream,
                        &ClientToServer::ReceiptClaim {
                            worker_id: cfg.worker_id.clone(),
                            job_id: descriptor.job_id.clone(),
                            pubkey_hex: hex(&signing_key.as_ref().unwrap().verifying_key().to_bytes()),
                            sig_hex: hex(&sig.to_bytes()),
                            receipt_hex: hex(&receipt_bytes),
                        },
                    )
                    .map_err(|e| format!("receipt submit: {e}"))?;
                    println!(
                        "[{}] submitted zk receipt claim for {} ({} bytes)",
                        cfg.worker_id,
                        descriptor.job_id,
                        receipt_bytes.len()
                    );
                    submitted = true;
                    continue;
                }

                // Materialize from the local (hash-verified) store.
                // Per-WORKER directory: two workers running the same
                // job concurrently must not share materialized files.
                let job_dir = job_materialize_dir(&cfg.worker_id, &descriptor.job_id)?;
                std::fs::remove_dir_all(&job_dir).ok();
                contentstore::materialize(&descriptor, &store, &job_dir)
                    .map_err(|e| format!("materialize: {e}"))?;
                eprintln!("[{}] materialized job into {}", cfg.worker_id, job_dir.display());
                let job = jobfmt::load_dir(&job_dir).map_err(|e| format!("load: {e}"))?;

                // Execute the job. SP1 path (Linux/production): the
                // guest IS the pinned emulator — the job ELF keeps its
                // rvcore ABI (memory-mapped I/O, ebreak halt) which
                // SP1 does not honor directly, so SP1 executes rvcore
                // on the job inside the zkVM. Fallback path (Windows
                // dev): the same rvcore runs natively. Both yield the
                // same journal format: 8-byte LE instruction count ||
                // output bytes — the consensus digest binds the cycle
                // count as well.
                #[cfg(feature = "sp1")]
                let (journal, cycle_count, status, trap) = {
                    const EMU_ELF: &[u8] = include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../elf/sp1-guest-emu"
                    ));
                    let manifest_bytes = std::fs::read(job_dir.join("job.json"))
                        .map_err(|e| format!("manifest: {e}"))?;
                    let mut stdin = SP1Stdin::new();
                    stdin.write(&manifest_bytes);
                    stdin.write(&job.elf);
                    stdin.write(&job.input);
                    let (mut pv, report) = sp1_prover()
                        .execute(Elf::Dynamic(EMU_ELF.into()), stdin)
                        .run()
                        .map_err(|e| format!("sp1 execute: {e}"))?;
                    // Read back the guest's committed sequence (same
                    // types, same order the guest committed them).
                    let binding: [[u8; 32]; 3] = pv.read();
                    let expected: [[u8; 32]; 3] = [
                        blake3::hash(&manifest_bytes).into(),
                        blake3::hash(&job.elf).into(),
                        blake3::hash(&job.input).into(),
                    ];
                    if binding != expected {
                        return Err("sp1 execute: guest binding does not match this job".into());
                    }
                    let status_code: u32 = pv.read();
                    let instructions: u64 = pv.read();
                    let _chain: Vec<[u8; 32]> = pv.read();
                    let output: Vec<u8> = pv.read();
                    let status = match status_code {
                        0 => "halted",
                        1 => "instruction_limit",
                        _ => "trap",
                    };
                    // SP1's VM cycle count is executor overhead, not
                    // job length; the guest's committed rvcore count
                    // is the honest instruction count.
                    eprintln!(
                        "[{}] sp1 execute: {} job instructions, {} vm cycles",
                        cfg.worker_id,
                        instructions,
                        report.total_instruction_count()
                    );
                    (
                        jobfmt::journal(instructions, &output),
                        instructions,
                        status.to_string(),
                        (status == "trap").then(|| format!("guest exit status {status_code}")),
                    )
                };
                #[cfg(not(feature = "sp1"))]
                let (journal, cycle_count, status, trap) = {
                    let image = rvcore::elf::parse(&job.elf).map_err(|e| format!("elf: {e}"))?;
                    let mut mem = rvcore::Mem::new();
                    rvcore::elf::load(&mut mem, &image).map_err(|e| format!("elf: {e}"))?;
                    let outcome = rvcore::interp::run(
                        &mut mem,
                        image.entry,
                        &job.input,
                        &rvcore::Config {
                            chunk_size: job.manifest.chunk_size,
                            max_instructions: job.manifest.max_instructions,
                            ..Default::default()
                        },
                    );
                    let cycles = outcome.instructions;
                    let output = outcome.output.unwrap_or_default();
                    let status = match &outcome.status {
                        rvcore::interp::ExitStatus::Halted
                        | rvcore::interp::ExitStatus::Tohost(_) => "halted",
                        rvcore::interp::ExitStatus::InstructionLimit => "instruction_limit",
                        rvcore::interp::ExitStatus::Trapped(_) => "trap",
                    };
                    let trap = match &outcome.status {
                        rvcore::interp::ExitStatus::Trapped(t) => Some(format!("{t:?}")),
                        _ => None,
                    };
                    (jobfmt::journal(cycles, &output), cycles, status.to_string(), trap)
                };
                eprintln!(
                    "[{}] executed {} ({} instructions, {} bytes journal)",
                    cfg.worker_id, job.manifest.name, cycle_count, journal.len()
                );

                // Corruption: bump one journal byte (last, or the
                // --corrupt-byte index) so the commitment diverges from
                // the honest journal — a ±1 bump can never round-trip.
                let mut journal_bytes = journal.clone();
                if cfg.corrupt && !journal_bytes.is_empty() {
                    let idx = cfg
                        .corrupt_byte
                        .map(|i| (i as usize) % journal_bytes.len())
                        .unwrap_or(journal_bytes.len() - 1);
                    journal_bytes[idx] = journal_bytes[idx].wrapping_add(1);
                }

                // Consensus commitment: SHA-256 of the journal. Workers
                // exchange and vote on this 32-byte digest, not the raw
                // buffer — saving bandwidth on large outputs.
                let journal_digest = sha2::Sha256::digest(&journal_bytes);
                let result_hash = hex(&journal_digest);
                let chunk_hashes = vec![result_hash.clone()];
                let output_hex = if journal.len() > 8 {
                    Some(hex(jobfmt::journal_output(&journal)))
                } else {
                    None
                };
                let instructions = cycle_count;
                let mut result = jobfmt::WorkerResult {
                    worker_id: cfg.worker_id.clone(),
                    job_id: job.manifest.id,
                    status,
                    instructions,
                    result_hash,
                    chunk_hashes,
                    output_hex,
                    trap,
                    pubkey_hex: None,
                    sig_hex: None,
                };
                // The signature binds the ENTIRE result (job id, status,
                // instruction count, chain, output) — not just the final
                // hash — so no field can be swapped post-signing.
                if let Some(key) = &signing_key {
                    let msg = jobfmt::signing_message(&result);
                    let sig = key.sign(&msg);
                    result.pubkey_hex = Some(hex(&key.verifying_key().to_bytes()));
                    result.sig_hex = Some(hex(&sig.to_bytes()));
                }
                counters.jobs.fetch_add(1, Ordering::SeqCst);
                println!(
                    "[{}] submitting result: {} after {} instructions",
                    cfg.worker_id,
                    &result.result_hash[..16.min(result.result_hash.len())],
                    result.instructions
                );
                let mut submits = 1 + cfg.extra_submits as usize;
                while submits > 0 {
                    submits -= 1;
                    if let Err(e) =
                        wire::send(&mut stream, &ClientToServer::JobResult { result: result.clone() })
                    {
                        eprintln!(
                            "[{}] result submit failed: {e} — connection lost",
                            cfg.worker_id
                        );
                        return Ok((SessionEnd::ConnectionLost, stats_snapshot(counters)));
                    }
                    if submits > 0 {
                        // Give the pump a beat so the duplicates arrive
                        // as distinct frames while the job is pending.
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    }
                }
                submitted = true;
            }
            other => return Err(format!("unexpected server message: {other:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn materialize_dir_rejects_untrusted_job_ids() {
        // REGRESSION: descriptor.job_id landed in a path that is then
        // remove_dir_all'd. A crafted id with separators or `..` must
        // be refused, not traversed.
        assert!(job_materialize_dir("wA", "demo-hash-smoke-0001").is_ok());
        assert!(job_materialize_dir("wA", "../../etc").is_err());
        assert!(job_materialize_dir("wA", "a/b").is_err());
        assert!(job_materialize_dir("wA", r"a\b").is_err());
        assert!(job_materialize_dir("wA", "..").is_err());
        // The constructed path stays inside the worker's scratch space.
        let p = job_materialize_dir("wA", "demo-hash-smoke-0001").unwrap();
        assert!(p.starts_with(std::env::temp_dir()));
        assert!(p.to_string_lossy().ends_with("p2pc-worker-wA-demo-hash-smoke-0001"));
    }
}
