//! The coordinator's persistent network session: accepts
//! Ed25519-authenticated worker connections indefinitely, watches a
//! jobs directory for descriptors, and processes each job over the
//! wire — dispatch as content-store blobs (with peer hints for the
//! p2p path), collect signed results, decide, update the ledger,
//! broadcast BetweenJobs, move to the next job.

use crate::{decide, slashing, verify_signature, Decision};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jobfmt::WorkerResult;
use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use wire::{ClientToServer, ServerToClient};

/// External zk verifier configuration: the binary (built from
/// sp1-host) and the committed guest ELF whose verifying key
/// re-derives the receipt check.
#[derive(Debug, Clone)]
pub struct ZkVerify {
    pub cmd: String,
    pub guest_elf: PathBuf,
}

pub struct ServeConfig {
    pub bind: SocketAddr,
    /// Watched for new `*.desc.json` job descriptors. A descriptor
    /// filename `name@w1,w2.desc.json` targets those workers;
    /// otherwise the job goes to every authenticated worker.
    pub jobs_dir: PathBuf,
    pub store_dir: PathBuf,
    /// Deadline for each individual job.
    pub per_job_deadline: Duration,
    pub ledger: Option<PathBuf>,
    pub require_identity: bool,
    /// zk tier: when set, authenticated workers may submit SP1 receipt
    /// claims, verified by an external verifier binary. None = receipt
    /// claims are refused.
    pub zk: Option<ZkVerify>,
    /// zk dispute judge: when set, a no-majority job escalates to an
    /// external SP1 prover process before falling back to the replay
    /// judge. The receipt makes the verdict third-party checkable.
    pub zk_judge: Option<crate::zk_judge::ZkJudge>,
    /// High-assurance proving queue: when set, submissions with
    /// `require_zk` skip worker consensus and are proven directly
    /// (queued, not synchronous). Uses the same judge config as the
    /// dispute path.
    pub zk_prover: Option<crate::zk_judge::ZkJudge>,
    /// When true, authenticated connections may submit job descriptors
    /// over the wire; each lands in the watched jobs directory.
    pub accept_submissions: bool,
    /// When set, every finished job's full outcome (decision, results,
    /// ledger deltas) is persisted here as `{job_id}.json` — the raw
    /// material for evidence bundles.
    pub results_dir: Option<PathBuf>,
    /// Admission proof-of-work difficulty in leading-zero bits (0
    /// disables). The fresh per-connection nonce forces the work to be
    /// redone on every reconnect, which is what makes bans and
    /// slashing bite: returning after a ban costs the mining again.
    pub identity_pow_bits: u32,
    /// When set, an "all workers" job waits for this many
    /// authenticated workers before dispatching.
    pub pool: Option<usize>,
    pub bound_tx: Option<Sender<SocketAddr>>,
    /// Stop after this many jobs (None = run until killed).
    pub max_jobs: Option<usize>,
    /// Each finished job is sent here (for tests and monitors).
    pub job_tx: Option<Sender<JobOutcome>>,
    /// When set, worker connections run over TLS with this server
    /// certificate + key (DER).
    pub tls: Option<(Vec<u8>, Vec<u8>)>,
    /// Random-sampling size for round-1 dispatch of untargeted jobs:
    /// pick this many workers at random, hold the rest as escalation
    /// reserves. None = dispatch to every authenticated worker.
    pub round1_size: Option<usize>,
    /// Deterministic round-1 membership by worker id (overrides
    /// random sampling; used by tests and operator-targeted runs).
    pub round1_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct JobOutcome {
    pub job_id: String,
    pub decision: Decision,
    pub results: Vec<WorkerResult>,
    pub bond_deltas: Vec<(String, i64)>,
}

pub struct ServeOutcome {
    pub jobs: Vec<JobOutcome>,
}

#[derive(Debug)]
enum Event {
    Hello {
        conn: usize,
        pubkey: String,
        worker_id: String,
        listen_port: Option<u16>,
    },
    NonceSig { conn: usize, sig: Option<String>, pow_counter: u64 },
    JobSubmission {
        conn: usize,
        submitter: String,
        descriptor: contentstore::JobDescriptor,
        pubkey_hex: String,
        sig_hex: String,
        require_zk: bool,
    },
    ReceiptClaim {
        conn: usize,
        worker_id: String,
        job_id: String,
        pubkey_hex: String,
        sig_hex: String,
        receipt_hex: String,
    },
    BlobRequest { conn: usize, id: String },
    Result { conn: usize, result: WorkerResult },
    Closed { conn: usize },
    /// A high-assurance (require_zk) job finished in the proving
    /// queue: the worker thread delivers the job with its
    /// receipt-backed (or failed) decision. Runs through the same
    /// finish path as consensus jobs.
    Proved { job: PendingJob, decision: Decision },
}

struct Conn {
    outbound: Sender<ServerToClient>,
    pubkey: Option<String>,
    nonce: Option<Vec<u8>>,
    worker_id: String,
    authed: bool,
    /// p2p blob server advertised by this worker, if any.
    peer_addr: Option<String>,
    /// The worker's IP, captured at accept time.
    peer_ip: String,
}

#[derive(Debug)]
struct PendingJob {
    descriptor: contentstore::JobDescriptor,
    /// Worker ids targeted (None = all authenticated workers).
    targets: Option<Vec<String>>,
    path: PathBuf,
    dispatched: bool,
    escalated: bool,
    dispatched_ids: Vec<String>,
    /// Workers held back from round 1 for escalation.
    reserves: Vec<String>,
    results: Vec<WorkerResult>,
    started: Instant,
    /// Set when a verified zk receipt claim arrives: the job accepts
    /// on this decision alone (no quorum threshold applies).
    zk_accept: Option<Decision>,
    /// Workers that have submitted a receipt claim, verified or not:
    /// one attempt per dispatched worker, so a rejected or slow claim
    /// cannot be repeated to stall the verifier again and again.
    receipt_claimed: Vec<String>,
    /// Connections that submitted this job remotely and wait for the
    /// outcome notice.
    subscribers: Vec<usize>,
}

pub fn serve(cfg: ServeConfig) -> Result<ServeOutcome, String> {
    let store = contentstore::Store::open(&cfg.store_dir).map_err(|e| format!("store: {e}"))?;
    let listener = TcpListener::bind(cfg.bind).map_err(|e| format!("bind: {e}"))?;
    let bound = listener.local_addr().map_err(|e| format!("local_addr: {e}"))?;
    println!("coordinator listening on {bound}");
    if let Some(tx) = &cfg.bound_tx {
        tx.send(bound).ok();
    }

    let (event_tx, event_rx) = channel::<Event>();
    let conns: Arc<Mutex<HashMap<usize, Conn>>> = Arc::new(Mutex::new(HashMap::new()));

    // High-assurance proving queue: one worker thread pops require_zk
    // submissions and delivers receipt-backed decisions as events. The
    // submitter's connection is never blocked by proving time.
    let prove_tx = if let Some(zk) = cfg.zk_prover.clone() {
        let (task_tx, task_rx) = channel::<PendingJob>();
        let ev = event_tx.clone();
        let store_dir = cfg.store_dir.clone();
        std::thread::spawn(move || proving_worker(task_rx, ev, store_dir, zk));
        Some(task_tx)
    } else {
        None
    };

    // Acceptor: each incoming connection gets a session thread that
    // owns the stream exclusively (polled receive + outbound queue) —
    // one thread per connection works for both plain TCP and TLS,
    // whose streams cannot be split for reader/writer threads.
    static NEXT_CONN: AtomicUsize = AtomicUsize::new(1);
    {
        let event_tx = event_tx.clone();
        let conns = conns.clone();
        let tls_cfg = cfg
            .tls
            .as_ref()
            .map(|(cert, key)| {
                Arc::new(wire::tls::server_config(cert, key).expect("tls server config"))
            });
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(tcp) = stream else { break };
                let id = NEXT_CONN.fetch_add(1, Ordering::SeqCst);
                let (outbound, outbound_rx) = channel::<ServerToClient>();
                let peer_ip = tcp
                    .peer_addr()
                    .map(|a| a.ip().to_string())
                    .unwrap_or_default();
                conns.lock().unwrap().insert(
                    id,
                    Conn {
                        outbound,
                        pubkey: None,
                        nonce: None,
                        worker_id: format!("w{id}"),
                        authed: false,
                        peer_addr: None,
                        peer_ip: peer_ip.clone(),
                    },
                );
                let tx = event_tx.clone();
                let conns2 = conns.clone();
                let tls_cfg = tls_cfg.clone();
                std::thread::spawn(move || {
                    let boxed: wire::BoxedStream = match &tls_cfg {
                        Some(server_cfg) => {
                            let conn = rustls::ServerConnection::new(server_cfg.clone())
                                .expect("tls connection");
                            let (mut conn, mut sock) = rustls::StreamOwned::new(conn, tcp).into_parts();
                            while conn.is_handshaking() {
                                if let Err(e) = conn.complete_io(&mut sock) {
                                    eprintln!("tls handshake failed for conn {id}: {e}");
                                    return;
                                }
                            }
                            let tls = rustls::StreamOwned::new(conn, sock);
                            // The polled receive NEEDS this timeout: it
                            // is what makes idle windows observable so
                            // the outbound queue gets pumped.
                            tls.sock
                                .set_read_timeout(Some(Duration::from_millis(100)))
                                .ok();
                            Box::new(tls)
                        }
                        None => {
                            tcp.set_read_timeout(Some(Duration::from_millis(100))).ok();
                            Box::new(tcp)
                        }
                    };
                    eprintln!("conn {id}: session started ({})", if tls_cfg.is_some() { "tls" } else { "plain" });
                    session_loop(id, boxed, outbound_rx, tx, conns2);
                });
            }
        });
    }

    let mut outcomes: Vec<JobOutcome> = Vec::new();
    let mut pending: Option<PendingJob> = None;
    let mut jobs_done = 0usize;
    // Descriptors seen failing to parse, for the write-grace window.
    let mut scan_errors: HashMap<PathBuf, Instant> = HashMap::new();

    loop {
        if let Some(max) = cfg.max_jobs {
            if jobs_done >= max {
                shutdown_all(&conns, "all queued jobs complete");
                return Ok(ServeOutcome { jobs: outcomes });
            }
        }

        // New job descriptors from the watched directory.
        if pending.is_none() {
            if let Some((descriptor, targets, path)) =
                scan_jobs_dir(&cfg.jobs_dir, &mut scan_errors)?
            {
                println!(
                    "job queued: {} (target: {})",
                    descriptor.job_id,
                    targets
                        .as_ref()
                        .map(|t| t.join(","))
                        .unwrap_or_else(|| "all".into())
                );
                pending = Some(PendingJob {
                    descriptor,
                    targets,
                    path,
                    dispatched: false,
                    escalated: false,
                    dispatched_ids: Vec::new(),
                    reserves: Vec::new(),
                    results: Vec::new(),
                    started: Instant::now(),
                    zk_accept: None,
                    receipt_claimed: Vec::new(),
                    subscribers: Vec::new(),
                });
            }
        }

        // Dispatch a queued job once its targets are all authenticated
        // (or immediately when targeting everyone).
        if let Some(job) = &mut pending {
            if !job.dispatched {
                let map = conns.lock().unwrap();
                let named = cfg.round1_ids.as_ref();
                let authed_count = map.values().filter(|c| c.authed).count();
                let targets_ready = match (&job.targets, named) {
                    (Some(ids), _) => {
                        // Named targets: wait for the targets AND the
                        // full pool so escalation reserves are populated.
                        let pool_ready = cfg
                            .pool
                            .is_none_or(|p| authed_count >= p);
                        ids.iter().all(|id| {
                            map.values().any(|c| c.authed && &c.worker_id == id)
                        }) && pool_ready
                    }
                    (_, Some(ids)) => {
                        let pool_ready = cfg
                            .pool
                            .is_none_or(|p| authed_count >= p);
                        ids.iter().all(|id| {
                            map.values().any(|c| c.authed && &c.worker_id == id)
                        }) && pool_ready
                    }
                    (None, None) => authed_count >= cfg.pool.unwrap_or(1),
                };
                if targets_ready {
                    // Pass 1 (immutable): collect eligible workers and
                    // their peer hints.
                    let mut candidates: Vec<(String, Vec<String>)> = Vec::new();
                    for c in map.values() {
                        let eligible = match &job.targets {
                            Some(ids) => ids.contains(&c.worker_id),
                            None => c.authed,
                        };
                        if eligible && c.authed {
                            let hints: Vec<String> = map
                                .values()
                                .filter(|p| {
                                    p.authed
                                        && p.peer_addr.is_some()
                                        && p.worker_id != c.worker_id
                                })
                                .filter_map(|p| p.peer_addr.clone())
                                .collect();
                            candidates.push((c.worker_id.clone(), hints));
                        }
                    }
                    drop(map);
                    // Random sampling: when more workers are eligible
                    // than the job needs, pick the round-1 set at
                    // random and hold the rest as escalation reserves.
                    // "First N authed workers" is gameable — connect
                    // first, get picked.
                    let named = cfg.round1_ids.as_ref().filter(|_| job.targets.is_none());
                    let selected: Vec<(String, Vec<String>)> = match named {
                        Some(ids) => {
                            // Named round-1 membership (deterministic).
                            ids.iter()
                                .filter_map(|id| {
                                    candidates
                                        .iter()
                                        .find(|(wid, _)| wid == id)
                                        .cloned()
                                })
                                .collect()
                        }
                        None => match cfg.round1_size {
                            Some(n) if candidates.len() > n => {
                                let mut shuffled = candidates.clone();
                                shuffle(&mut shuffled);
                                shuffled.truncate(n);
                                shuffled
                            }
                            _ => candidates.clone(),
                        },
                    };
                    // Reserves = authenticated workers outside the
                    // round-1 set (including workers the job was NOT
                    // targeted at — they are exactly who escalation
                    // needs when round 1 deadlocks). The lock is
                    // already dropped here; re-acquire to read.
                    let reserves: Vec<String> = {
                        let map = conns.lock().unwrap();
                        let selected_ids: Vec<&str> =
                            selected.iter().map(|(id, _)| id.as_str()).collect();
                        let targeted = job.targets.as_ref();
                        map.values()
                            .filter(|c| {
                                c.authed
                                    && !selected_ids.contains(&c.worker_id.as_str())
                                    && targeted
                                        .is_none_or(|ids| !ids.contains(&c.worker_id))
                            })
                            .map(|c| c.worker_id.clone())
                            .collect()
                    };
                    let mut map = conns.lock().unwrap();
                    for (wid, hints) in &selected {
                        if let Some(c) = map.values_mut().find(|c| c.worker_id == *wid) {
                            let _ = c.outbound.send(ServerToClient::JobAssignment {
                                descriptor: job.descriptor.clone(),
                                peer_hints: hints.clone(),
                            });
                            job.dispatched_ids.push(wid.clone());
                        }
                    }
                    job.reserves = reserves;
                    drop(map);
                    job.dispatched = true;
                    // The execution window starts here, not at queue
                    // time: the queue wait includes operator/handshake
                    // latency that must not eat the deadline.
                    job.started = Instant::now();
                    println!(
                        "job {} dispatched to [{}]",
                        job.descriptor.job_id,
                        job.dispatched_ids.join(", ")
                    );
                }
            }
        }

        // Per-job completion: all dispatched workers have results, the
        // deadline passed, or an escalation round is still owed.
        let mut job_finished: Option<PendingJob> = None;
        if let Some(job) = &mut pending {
            if job.dispatched {
                let all_in = job.zk_accept.is_some()
                    || job.dispatched_ids.iter().all(|id| {
                        job.results.iter().any(|r| &r.worker_id == id)
                    });
                if job.zk_accept.is_some() || all_in {
                    // No majority and reserves remain → escalate to
                    // them (dispatch the held-back workers) instead of
                    // finishing.
                    if matches!(decide(&job.results, job.dispatched_ids.len()), Decision::Escalate)
                        && !job.reserves.is_empty()
                    {
                        let reserves = std::mem::take(&mut job.reserves);
                        let mut map = conns.lock().unwrap();
                        for wid in &reserves {
                            // Hints first (immutable), then dispatch.
                            let hints: Vec<String> = map
                                .values()
                                .filter(|p| {
                                    p.authed
                                        && p.peer_addr.is_some()
                                        && &p.worker_id != wid
                                })
                                .filter_map(|p| p.peer_addr.clone())
                                .collect();
                            if let Some(c) =
                                map.values_mut().find(|c| &c.worker_id == wid && c.authed)
                            {
                                let sent = c.outbound.send(ServerToClient::JobAssignment {
                                    descriptor: job.descriptor.clone(),
                                    peer_hints: hints,
                                });
                                eprintln!("escalation dispatch to {wid}: sent={}", sent.is_ok());
                                job.dispatched_ids.push(wid.clone());
                            }
                        }
                        job.escalated = true;
                        // The escalation round gets its own execution
                        // window: the reserve workers were idle while
                        // round 1 ran, and slow runners need the full
                        // budget for the fresh execution.
                        job.started = Instant::now();
                        println!(
                            "no majority in round 1 — escalating to [{}]",
                            reserves.join(", ")
                        );
                        continue; // job stays pending for the escalation round
                    }
                    job_finished = Some(PendingJob {
                        descriptor: job.descriptor.clone(),
                        targets: job.targets.clone(),
                        path: job.path.clone(),
                        dispatched: true,
                        escalated: false,
                        dispatched_ids: job.dispatched_ids.clone(),
                        reserves: Vec::new(),
                        results: std::mem::take(&mut job.results),
                        started: job.started,
                        zk_accept: job.zk_accept.take(),
                        receipt_claimed: job.receipt_claimed.clone(),
                        subscribers: std::mem::take(&mut job.subscribers),
                    });
                } else if job.started.elapsed() > cfg.per_job_deadline {
                    job_finished = Some(PendingJob {
                        descriptor: job.descriptor.clone(),
                        targets: job.targets.clone(),
                        path: job.path.clone(),
                        dispatched: true,
                        escalated: false,
                        dispatched_ids: job.dispatched_ids.clone(),
                        reserves: Vec::new(),
                        results: std::mem::take(&mut job.results),
                        started: job.started,
                        zk_accept: job.zk_accept.take(),
                        receipt_claimed: job.receipt_claimed.clone(),
                        subscribers: std::mem::take(&mut job.subscribers),
                    });
                }
            }
        }
        if let Some(job) = job_finished {
            let decision = match job.zk_accept.clone() {
                Some(d) => d, // a verified zk receipt needs no consensus
                None => match decide(&job.results, job.dispatched_ids.len()) {
                    // No majority and nothing left to escalate to: the
                    // replay judge arbitrates. The true chain vindicates
                    // honest responders (even a lone one against a pool
                    // of no-shows) and convicts contradicting chains.
                    Decision::Escalate => {
                        // Prefer the zk judge when configured: its
                        // receipt makes the verdict third-party
                        // checkable. Any failure (absent, oversized,
                        // cycle-bound, timed out) falls back to the
                        // replay judge — both are the coordinator's
                        // own computation; zk adds verifiability.
                        match zk_judge_network(&cfg, &store, &job) {
                            Some(d) => d,
                            None => match judge_by_replay_network(&store, &job) {
                                Some(d) => d,
                                None => Decision::Reject {
                                    reason: "no majority; dispute judgment failed".into(),
                                },
                            },
                        }
                    }
                    other => other,
                },
            };
            // Shared finish path: notify, persist, ledger, count.
            finish_decided_job(&cfg, &conns, &job, &decision, &mut outcomes, &mut jobs_done);
            let mut done = job.path.clone().into_os_string();
            done.push(".done");
            std::fs::rename(&job.path, done).ok();
            broadcast_between_jobs(&conns);
            pending = None;
            continue;
        }

        // Events (bounded wait so housekeeping keeps running).
        let event = match event_rx.recv_timeout(Duration::from_millis(250)) {
            Ok(e) => e,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err("event channel closed".into())
            }
        };

        match event {
            Event::Hello { conn, pubkey, worker_id, listen_port } => {
                let nonce: [u8; 32] = rand_nonce();
                let nonce_hex = hex(&nonce);
                let pow_bits = cfg.identity_pow_bits;
                let mut map = conns.lock().unwrap();
                if let Some(c) = map.get_mut(&conn) {
                    c.pubkey = if pubkey.is_empty() { None } else { Some(pubkey) };
                    if !worker_id.is_empty() {
                        c.worker_id = worker_id;
                    }
                    c.nonce = Some(nonce.to_vec());
                    if let Some(port) = listen_port {
                        c.peer_addr = Some(format!("{}:{port}", c.peer_ip));
                    }
                    let _ = c
                        .outbound
                        .send(ServerToClient::Nonce { hex: nonce_hex, pow_bits });
                }
            }
            Event::NonceSig { conn, sig, pow_counter } => {
                let mut map = conns.lock().unwrap();
                let Some(c) = map.get_mut(&conn) else { continue };
                // Admission proof-of-work: the fresh per-connection
                // nonce forces the work to be redone every time, so a
                // slashed or banned identity cannot return for free.
                let pow_ok = match (&c.nonce, cfg.identity_pow_bits) {
                    (Some(nonce), bits) => {
                        wire::verify_pow(nonce, pow_counter, bits)
                    }
                    _ => false,
                };
                if !pow_ok {
                    eprintln!(
                        "SECURITY: connection {conn} failed admission proof-of-work ({} bits)",
                        cfg.identity_pow_bits
                    );
                }
                let auth_ok = pow_ok
                    && match (&c.pubkey, &sig, &c.nonce) {
                        (Some(pk), Some(sig), Some(nonce)) => {
                            verify_nonce(pk, nonce, sig).is_ok()
                        }
                        (None, _, Some(_)) => !cfg.require_identity,
                        _ => false,
                    };
                if auth_ok {
                    c.authed = true;
                    let wid = c.worker_id.clone();
                    let _ = c.outbound.send(ServerToClient::AuthOk { worker_id: wid.clone() });
                    // A worker authenticating after dispatch joins the
                    // in-flight job's reserve list (untargeted jobs,
                    // before escalation) — otherwise late joiners can
                    // never participate and escalation deadlocks.
                    if let Some(job) = &mut pending {
                        if job.dispatched
                            && !job.escalated
                            && job.targets.is_none()
                            && !job.dispatched_ids.contains(&wid)
                        {
                            job.reserves.push(wid.clone());
                        }
                    }
                    println!(
                        "worker authenticated: {wid}{} (pool {}/open)",
                        c.peer_addr.as_ref().map(|_| " [p2p]").unwrap_or(""),
                        map.values().filter(|c| c.authed).count()
                    );
                } else {
                    let _ = c.outbound.send(ServerToClient::AuthFailed {
                        reason: "nonce signature invalid".into(),
                    });
                    let _ = c
                        .outbound
                        .send(ServerToClient::ShutDown { reason: "auth failed".into() });
                }
            }
            Event::BlobRequest { conn, id } => {
                let mut map = conns.lock().unwrap();
                let wid = map.get(&conn).map(|c| c.worker_id.clone()).unwrap_or_default();
                if let Some(c) = map.get_mut(&conn) {
                    let data = contentstore::ContentId::from_hex(&id)
                        .ok()
                        .and_then(|cid| store.get(&cid).ok());
                    println!(
                        "blob request: {} asks {} -> {}",
                        wid,
                        &id[..12.min(id.len())],
                        if data.is_some() { "served" } else { "not found" }
                    );
                    let _ = c.outbound.send(ServerToClient::Blob {
                        hex: data.map(|d| hex(&d)),
                    });
                }
            }
            Event::Result { conn, result } => {
                // SECURITY: a result is only counted if it arrives on an
                // authenticated connection, under that connection's own
                // worker id and Ed25519 key, with a valid signature over
                // the result hash. Anything else is impersonation and is
                // dropped before it can touch quorum.
                let mut map = conns.lock().unwrap();
                let Some(c) = map.get_mut(&conn) else {
                    eprintln!("SECURITY: result from unknown conn {conn} dropped");
                    continue;
                };
                if !c.authed {
                    eprintln!("SECURITY: result from unauthenticated conn {conn} dropped");
                    continue;
                }
                if result.worker_id != c.worker_id {
                    eprintln!(
                        "SECURITY: worker id mismatch on conn {conn}: claimed {}, authenticated as {}",
                        result.worker_id, c.worker_id
                    );
                    continue;
                }
                match (&c.pubkey, &result.pubkey_hex) {
                    (Some(pk), Some(claimed)) if pk != claimed => {
                        eprintln!(
                            "SECURITY: key mismatch on conn {conn} ({wid}): result claims {claimed}",
                            wid = c.worker_id,
                        );
                        continue;
                    }
                    (None, _) if cfg.require_identity => {
                        eprintln!("SECURITY: unsigned result on conn {conn} dropped");
                        continue;
                    }
                    _ => {}
                }
                if let Err(e) = verify_signature(&result) {
                    eprintln!("SECURITY: bad signature on conn {conn}: {e}");
                    continue;
                }
                let wid = c.worker_id.clone();
                drop(map);

                if let Some(job) = &mut pending {
                    if result.job_id == job.descriptor.job_id {
                        // Quorum integrity: only workers the job was
                        // actually dispatched to may vote, and each
                        // dispatched worker gets exactly one vote. A
                        // duplicate submission could otherwise inflate
                        // its author's group into a fake majority.
                        if !job.dispatched_ids.iter().any(|id| id == &wid) {
                            eprintln!(
                                "SECURITY: result from non-dispatched worker {wid} dropped"
                            );
                            continue;
                        }
                        if job.results.iter().any(|r| r.worker_id == wid) {
                            eprintln!("SECURITY: duplicate result from {wid} dropped");
                            continue;
                        }
                        println!("result accepted: {wid} → {}", &result.result_hash[..12]);
                        job.results.push(result);
                    }
                }
            }
            Event::JobSubmission {
                conn,
                submitter,
                descriptor,
                pubkey_hex,
                sig_hex,
                require_zk,
            } => {
                handle_job_submission(
                    &cfg, &conns, &mut pending, conn, &submitter, descriptor,
                    &pubkey_hex, &sig_hex, require_zk, prove_tx.as_ref(),
                );
            }
            Event::ReceiptClaim {
                conn,
                worker_id,
                job_id,
                pubkey_hex,
                sig_hex,
                receipt_hex,
            } => {
                // zk tier: identity gate first (same rules as results).
                let mut map = conns.lock().unwrap();
                let Some(c) = map.get_mut(&conn) else {
                    eprintln!("SECURITY: receipt claim from unknown conn {conn} dropped");
                    continue;
                };
                if !c.authed {
                    eprintln!(
                        "SECURITY: receipt claim from unauthenticated conn {conn} dropped"
                    );
                    continue;
                }
                if worker_id != c.worker_id {
                    eprintln!(
                        "SECURITY: receipt claim worker id mismatch on conn {conn}: claimed {worker_id}, authenticated as {}",
                        c.worker_id
                    );
                    continue;
                }
                if let (Some(pk), claimed) = (&c.pubkey, &pubkey_hex) {
                    if pk != claimed {
                        eprintln!("SECURITY: receipt claim key mismatch on conn {conn}");
                        continue;
                    }
                }
                drop(map);
                handle_receipt_claim(
                    &cfg, &mut pending, &worker_id, &job_id, &pubkey_hex, &sig_hex,
                    &receipt_hex,
                );
            }
            Event::Proved { job, decision } => {
                // The proving queue bypasses the pending slot: the job
                // never dispatched to workers, so there is no watched
                // descriptor file to mark done — just finish it.
                finish_decided_job(&cfg, &conns, &job, &decision, &mut outcomes, &mut jobs_done);
                broadcast_between_jobs(&conns);
            }
            Event::Closed { conn } => {
                let wid = conns.lock().unwrap().get(&conn).map(|c| c.worker_id.clone());
                println!(
                    "worker disconnected: {} (conn {conn})",
                    wid.as_deref().unwrap_or("unknown")
                );
                conns.lock().unwrap().remove(&conn);
            }
        }
    }
}

/// Scan the jobs directory for the first unprocessed descriptor.
/// A queued job file: descriptor, optional explicit round-1 targets, path.
type QueuedJob = (contentstore::JobDescriptor, Option<Vec<String>>, PathBuf);

/// A descriptor still being written by its client surfaces as a
/// short-lived read or parse error. Such a file is skipped until it
/// has been failing this long — only then is it fatal, so a genuinely
/// corrupt descriptor still halts the server for operator recovery.
const DESC_WRITE_GRACE: Duration = Duration::from_secs(5);

/// Returns (descriptor, targets, path) and marks the file in use by
/// renaming to `.dispatching` — crash-safe: a renamed file is
/// recovered by the operator, not silently re-run.
fn scan_jobs_dir(
    jobs_dir: &std::path::Path,
    errors: &mut HashMap<PathBuf, Instant>,
) -> Result<Option<QueuedJob>, String> {
    for entry in std::fs::read_dir(jobs_dir).map_err(|e| format!("jobs dir: {e}"))?.flatten() {
        let path = entry.path();
        let name = path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
        if name.ends_with(".desc.json") {
            let loaded = std::fs::read(&path)
                .map_err(|e| format!("jobs dir: {e}"))
                .and_then(|bytes| {
                    serde_json::from_slice::<contentstore::JobDescriptor>(&bytes)
                        .map_err(|e| format!("descriptor {name}: {e}"))
                });
            let descriptor = match loaded {
                Ok(d) => d,
                Err(e) => {
                    match errors.entry(path.clone()) {
                        std::collections::hash_map::Entry::Occupied(seen) => {
                            if seen.get().elapsed() >= DESC_WRITE_GRACE {
                                return Err(e);
                            }
                        }
                        std::collections::hash_map::Entry::Vacant(v) => {
                            v.insert(Instant::now());
                            eprintln!(
                                "descriptor {name} unreadable ({e}) — retrying for up to {DESC_WRITE_GRACE:?}"
                            );
                        }
                    }
                    continue; // likely mid-write; retry next poll
                }
            };
            errors.remove(&path);
            let stem = name.trim_end_matches(".desc.json");
            let targets: Option<Vec<String>> = stem.split_once('@').map(|(_, ids)| {
                ids.split(',').map(|x| x.trim().to_string()).collect()
            });
            // Mark in use: rename to .dispatching so a crash cannot
            // double-run a job.
            let mut dispatching = path.clone().into_os_string();
            dispatching.push(".dispatching");
            std::fs::rename(&path, &dispatching).map_err(|e| format!("jobs dir: {e}"))?;
            return Ok(Some((descriptor, targets, PathBuf::from(dispatching))));
        }
    }
    Ok(None)
}

fn finish_ledger(
    cfg: &ServeConfig,
    job_id: &str,
    decision: &Decision,
    deltas: &[(String, i64)],
) {
    println!("decision: {decision:?}");
    if let Some(path) = &cfg.ledger {
        let mut led = crate::ledger::Ledger::load(path).unwrap_or_else(|e| {
            println!("ledger load failed ({e}); starting empty");
            Default::default()
        });
        led.apply(job_id, "network-run", deltas);
        if let Err(e) = led.save(path) {
            println!("ledger save failed: {e}");
        }
    }
}

fn broadcast_between_jobs(conns: &Mutex<HashMap<usize, Conn>>) {
    for c in conns.lock().unwrap().values() {
        let _ = c.outbound.send(ServerToClient::BetweenJobs);
    }
}

fn shutdown_all(conns: &Mutex<HashMap<usize, Conn>>, reason: &str) {
    for c in conns.lock().unwrap().values() {
        let _ = c.outbound.send(ServerToClient::ShutDown { reason: reason.into() });
    }
}

/// The dispute judge: when a job completes without a majority, the
/// coordinator re-executes it from genesis (the same thing the dispute
/// CLI does) and lets the true chain arbitrate. Every result group
/// whose full chain matches the replay is vindicated — accepted and
/// rewarded; every responder whose chain contradicts the replay is
/// proven a liar and slashed. One honest worker is rescued from a
/// pool of no-shows; two colluding liars with DIFFERENT fabrications
/// are convicted by their own disagreement.
///
/// Bounded by the job's own max_instructions budget — no unbounded
/// verifier work. Returns None when the job cannot be materialized or
/// replayed (operator intervention needed).
fn judge_by_replay_network(
    store: &contentstore::Store,
    job: &PendingJob,
) -> Option<Decision> {
    let dir = std::env::temp_dir().join(format!(
        "p2pc-judge-{}-{}",
        std::process::id(),
        job.descriptor.job_id
    ));
    let _ = std::fs::remove_dir_all(&dir);
    contentstore::materialize(&job.descriptor, store, &dir).ok()?;
    let manifest_bytes = std::fs::read(dir.join("job.json")).ok()?;
    let manifest: jobfmt::JobManifest = serde_json::from_slice(&manifest_bytes).ok()?;
    let elf = std::fs::read(dir.join(&manifest.elf)).ok()?;
    let input = std::fs::read(dir.join(&manifest.input)).ok()?;
    let image = rvcore::elf::parse(&elf).ok()?;
    let (instructions, output) = crate::dispute::replay_journal(
        &elf,
        image.entry,
        &input,
        manifest.chunk_size,
        manifest.max_instructions,
    )?;
    let _ = std::fs::remove_dir_all(&dir);
    // The consensus commitment is SHA-256 over the journal — the same
    // construction workers use, so digests are comparable as-is. The
    // verdict carries the JUDGE's own output, never a liar's claim.
    let truth_digest = hex(&jobfmt::journal_digest(instructions, &output));
    let output_hex = Some(hex(&output));

    let mut agreed: Vec<String> = Vec::new();
    for r in &job.results {
        if r.chunk_hashes.len() == 1 && r.chunk_hashes[0] == truth_digest {
            if !agreed.contains(&r.worker_id) {
                agreed.push(r.worker_id.clone());
            }
        }
    }
    Some(Decision::Accept { hash: truth_digest, output_hex, agreed, zk: false })
}

/// The zk dispute judge over the network path: materialize the job
/// (the same hash-verified blobs the workers saw), hand it to the
/// external judge process, and turn a verified verdict into a
/// decision. Returns None when no judge is configured or the judge
/// failed for any reason — the caller falls back to the replay judge.
/// The binding cross-check pins the verdict to THIS job's content
/// ids; the digest is recomputed from the verdict's own values.
fn zk_judge_network(
    cfg: &ServeConfig,
    store: &contentstore::Store,
    job: &PendingJob,
) -> Option<Decision> {
    let Some(zk) = &cfg.zk_judge else { return None };
    let dir = std::env::temp_dir().join(format!(
        "p2pc-zkjudge-{}-{}",
        std::process::id(),
        job.descriptor.job_id
    ));
    let _ = std::fs::remove_dir_all(&dir);
    contentstore::materialize(&job.descriptor, store, &dir).ok()?;
    let receipt_out = zk
        .receipt_dir
        .as_ref()
        .map(|rd| rd.join(format!("{}.receipt.bin", job.descriptor.job_id)));
    let result = crate::zk_judge::run_judge(zk, &dir, receipt_out.as_deref())
        .and_then(|verdict| {
            // The descriptor's content ids are plain hex; decode each
            // and require exactly 32 bytes (the content store's ids).
            let decode32 = |h: &str| -> Result<[u8; 32], String> {
                let bytes = jobfmt::from_hex(h, 32).map_err(|e| format!("content id: {e}"))?;
                bytes.try_into().map_err(|_| "content id length".to_string())
            };
            let expected_binding = [
                decode32(&job.descriptor.manifest)?,
                decode32(&job.descriptor.elf)?,
                decode32(&job.descriptor.input)?,
            ];
            crate::zk_judge::judge_decision(&verdict, &expected_binding)
        });
    let _ = std::fs::remove_dir_all(&dir);
    match result {
        Ok(d) => {
            // A receipt-backed accept vindicates the responders whose
            // result matches it — same semantics as the replay judge:
            // matching workers are paid, contradicting ones burned by
            // slashing (agreed stays empty only when nobody answered).
            let vindicated = match d {
                Decision::Accept { hash, output_hex, zk: true, .. } => {
                    let agreed: Vec<String> = job
                        .results
                        .iter()
                        .filter(|r| r.chunk_hashes.len() == 1 && r.chunk_hashes[0] == hash)
                        .map(|r| r.worker_id.clone())
                        .collect();
                    Decision::Accept { hash, output_hex, agreed, zk: true }
                }
                other => other,
            };
            eprintln!(
                "[net] zk judge resolved job {}: receipt-backed verdict",
                job.descriptor.job_id
            );
            Some(vindicated)
        }
        Err(e) => {
            eprintln!("[net] zk judge unavailable for {}: {e} — falling back to replay", job.descriptor.job_id);
            None
        }
    }
}

/// Decode a 32-byte hex content id (plain hex, exactly 64 chars).
fn decode_hex32(h: &str) -> Result<[u8; 32], String> {
    let bytes = jobfmt::from_hex(h, 32).map_err(|e| format!("content id: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "content id length".to_string())
}

/// The shared tail of every finished job — consensus, judged, or
/// zk-proved: notify subscribers, persist the evidence record, apply
/// ledger deltas, and hand the outcome to the caller-side collector.
fn finish_decided_job(
    cfg: &ServeConfig,
    conns: &Arc<Mutex<HashMap<usize, Conn>>>,
    job: &PendingJob,
    decision: &Decision,
    outcomes: &mut Vec<JobOutcome>,
    jobs_done: &mut usize,
) {
    let job_id = job.descriptor.job_id.clone();
    eprintln!(
        "[net] job finished: {} results, dispatched [{}], reserves [{}], decision {:?}",
        job.results.len(),
        job.dispatched_ids.join(","),
        job.reserves.join(","),
        decision
    );
    let deltas = slashing(decision, &job.results);

    // Notify remote submitters waiting on this job.
    if let Decision::Accept { hash, agreed, output_hex, zk } = decision {
        let notice = ServerToClient::JobOutcome {
            job_id: job_id.clone(),
            hash: hash.clone(),
            agreed: agreed.clone(),
            output_hex: output_hex.clone(),
            zk: *zk,
            rejected_reason: None,
        };
        for &conn in &job.subscribers {
            if let Some(c) = conns.lock().unwrap().get(&conn) {
                let _ = c.outbound.send(notice.clone());
            }
        }
    }

    // Evidence raw material: persist the full outcome for the
    // evidence-bundle assembler.
    if let Some(rd) = &cfg.results_dir {
        let _ = std::fs::create_dir_all(rd);
        let record = serde_json::json!({
            "job_id": job_id,
            "decision": decision,
            "results": job.results,
            "ledger_deltas": deltas,
        });
        let _ = std::fs::write(
            rd.join(format!("{job_id}.json")),
            serde_json::to_vec_pretty(&record).unwrap_or_default(),
        );
    }
    finish_ledger(cfg, &job_id, decision, &deltas);
    let outcome = JobOutcome {
        job_id: job_id.clone(),
        decision: decision.clone(),
        results: job.results.clone(),
        bond_deltas: deltas,
    };
    if let Some(tx) = &cfg.job_tx {
        tx.send(outcome.clone()).ok();
    }
    outcomes.push(outcome);
    *jobs_done += 1;
}

/// The high-assurance proving queue worker: pops require_zk jobs,
/// materializes them from the store, and runs the zk-judge process.
/// A fresh proof lands in the receipt cache; a cache hit (same
/// manifest+elf+input already proven) is verified through the
/// standalone verifier and served without proving again. Deterministic
/// execution makes receipts for identical jobs identical, so the
/// second requester never pays for the first one's proof.
fn proving_worker(
    rx: Receiver<PendingJob>,
    event_tx: Sender<Event>,
    store_dir: PathBuf,
    zk: crate::zk_judge::ZkJudge,
) {
    let Ok(store) = contentstore::Store::open(&store_dir) else {
        eprintln!("[net] proving queue: cannot open store — queue disabled");
        return;
    };
    while let Ok(job) = rx.recv() {
        let job_id = job.descriptor.job_id.clone();
        let decision = match prove_one(&store, &zk, &job) {
            Ok(d) => d,
            Err(e) => Decision::Reject {
                reason: format!("zk proving failed: {e}"),
            },
        };
        eprintln!("[net] proving queue finished {job_id}: {decision:?}");
        event_tx.send(Event::Proved { job, decision }).ok();
    }
}

fn prove_one(
    store: &contentstore::Store,
    zk: &crate::zk_judge::ZkJudge,
    job: &PendingJob,
) -> Result<Decision, String> {
    let dir = std::env::temp_dir().join(format!(
        "p2pc-zkprove-{}-{}",
        std::process::id(),
        job.descriptor.job_id
    ));
    let _ = std::fs::remove_dir_all(&dir);
    contentstore::materialize(&job.descriptor, store, &dir)?;
    let expected_binding = [
        decode_hex32(&job.descriptor.manifest)?,
        decode_hex32(&job.descriptor.elf)?,
        decode_hex32(&job.descriptor.input)?,
    ];
    // Dedup first: an already-proven (manifest, elf, input) is served
    // from the cache after the receipt re-verifies against THIS job's
    // binding — never trusted on faith.
    let key = crate::zk_judge::receipt_cache_key(&job.descriptor);
    if let Some(rd) = &zk.receipt_dir {
        if let Some(d) = crate::zk_judge::verify_cached(zk, rd, &key, &expected_binding) {
            eprintln!("[net] zk receipt cache hit for {} (key {key})", job.descriptor.job_id);
            let _ = std::fs::remove_dir_all(&dir);
            return Ok(d);
        }
    }
    // Fresh prove: the receipt lands in the cache keyed by content.
    let receipt_out = zk
        .receipt_dir
        .as_ref()
        .map(|rd| crate::zk_judge::cache_paths(rd, &key).0);
    let verdict = crate::zk_judge::run_judge(zk, &dir, receipt_out.as_deref())?;
    let _ = std::fs::remove_dir_all(&dir);
    // Sidecar: the prove metadata for operators and tests.
    if let (Some(rd), Some(path)) = (&zk.receipt_dir, receipt_out.as_ref()) {
        if path.exists() {
            let meta = serde_json::json!({
                "key": key,
                "job_id": job.descriptor.job_id,
                "proven_at": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                "instructions": verdict.instructions,
                "output_hex": verdict.output_hex,
                "vm_cycles": verdict.vm_cycles,
                "proving_secs": verdict.proving_secs,
            });
            let (_, meta_path) = crate::zk_judge::cache_paths(rd, &key);
            let _ = std::fs::write(meta_path, serde_json::to_vec_pretty(&meta).unwrap_or_default());
            // Per-job evidence copy: the evidence assembler picks the
            // receipt up by job id, not by cache key.
            let _ = std::fs::create_dir_all(rd);
            let _ = std::fs::copy(path, rd.join(format!("{}.receipt.bin", job.descriptor.job_id)));
        }
    }
    crate::zk_judge::judge_decision(&verdict, &expected_binding)
}

/// Validate and land a remotely submitted job descriptor. The
/// connection must be authenticated (same Hello/PoW/nonce flow as
/// workers), the signature must bind the submitter's identity to the
/// descriptor's content id, and the descriptor must pass the same
/// confinement rules the file path enforces. Accepted submissions are
/// written into the watched jobs directory — the existing scanner
/// picks them up exactly like hand-dropped files.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
fn handle_job_submission(
    cfg: &ServeConfig,
    conns: &Arc<Mutex<HashMap<usize, Conn>>>,
    pending: &mut Option<PendingJob>,
    conn: usize,
    submitter: &str,
    descriptor: contentstore::JobDescriptor,
    pubkey_hex: &str,
    sig_hex: &str,
    require_zk: bool,
    prove_tx: Option<&Sender<PendingJob>>,
) {
    if !cfg.accept_submissions {
        eprintln!("SECURITY: job submission from {submitter} dropped — submissions disabled");
        return;
    }
    let mut map = conns.lock().unwrap();
    let Some(c) = map.get_mut(&conn) else {
        eprintln!("SECURITY: job submission from unknown conn {conn} dropped");
        return;
    };
    if !c.authed {
        eprintln!("SECURITY: job submission from unauthenticated conn {conn} dropped");
        return;
    }
    if let (Some(pk), Some(claimed)) = (&c.pubkey, Some(pubkey_hex)) {
        if pk != claimed {
            eprintln!("SECURITY: job submission key mismatch on conn {conn}");
            return;
        }
    }
    drop(map);

    // The signature binds the submitter to the exact descriptor:
    // submission_message(job_id, blake3(canonical descriptor json)).
    let desc_json = match serde_json::to_vec(&descriptor) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("SECURITY: job submission {submitter}: descriptor encode failed ({e})");
            return;
        }
    };
    let desc_id: [u8; 32] = blake3::hash(&desc_json).into();
    let pk_bytes = match jobfmt::from_hex(pubkey_hex, 32) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SECURITY: job submission {submitter}: bad pubkey ({e})");
            return;
        }
    };
    let sig_bytes = match jobfmt::from_hex(sig_hex, 64) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SECURITY: job submission {submitter}: bad signature ({e})");
            return;
        }
    };
    let vk = match VerifyingKey::from_bytes(&pk_bytes.try_into().unwrap()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("SECURITY: job submission {submitter}: bad pubkey ({e})");
            return;
        }
    };
    let msg = jobfmt::submission_message(&descriptor.job_id, &desc_id);
    if let Err(e) = vk.verify(&msg, &Signature::from_bytes(&sig_bytes.try_into().unwrap())) {
        eprintln!("SECURITY: job submission {submitter}: signature invalid ({e})");
        return;
    }

    // Same confinement the file path enforces: the manifest's file
    // fields and the job id must be plain names.
    if let Err(e) = jobfmt::confined_name(&descriptor.job_id) {
        eprintln!("SECURITY: job submission {submitter}: bad job id ({e})");
        return;
    }

    // High-assurance mode: skip worker consensus entirely. The job
    // goes to the proving queue; the ack returns immediately and the
    // JobOutcome arrives when the proof (or the cache hit) lands.
    if require_zk {
        let Some(tx) = prove_tx else {
            if let Some(c) = conns.lock().unwrap().get_mut(&conn) {
                let _ = c.outbound.send(ServerToClient::SubmissionAck {
                    job_id: descriptor.job_id.clone(),
                    accepted: false,
                    reason: Some(
                        "coordinator does not run a zk prover — high-assurance submissions refused"
                            .into(),
                    ),
                    proving: false,
                });
            }
            return;
        };
        let job = PendingJob {
            descriptor: descriptor.clone(),
            targets: None,
            path: cfg.jobs_dir.join("zk-proving"),
            dispatched: true,
            escalated: false,
            dispatched_ids: Vec::new(),
            reserves: Vec::new(),
            results: Vec::new(),
            started: std::time::Instant::now(),
            zk_accept: None,
            receipt_claimed: Vec::new(),
            subscribers: vec![conn],
        };
        if tx.send(job).is_err() {
            eprintln!("SECURITY: proving queue unavailable — submission dropped");
            return;
        }
        println!("job submitted by {submitter}: {} → zk proving queue", descriptor.job_id);
        if let Some(c) = conns.lock().unwrap().get_mut(&conn) {
            let _ = c.outbound.send(ServerToClient::SubmissionAck {
                job_id: descriptor.job_id.clone(),
                accepted: true,
                reason: None,
                proving: true,
            });
        }
        return;
    }

    // Land it in the watched directory. write_new avoids clobbering a
    // concurrently-queued file with the same id.
    let path = cfg
        .jobs_dir
        .join(format!("submitted-{ }.desc.json", descriptor.job_id));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut f) => {
            use std::io::Write;
            if let Err(e) = f.write_all(&desc_json) {
                let _ = std::fs::remove_file(&path);
                eprintln!("SECURITY: job submission {submitter}: write failed ({e})");
                return;
            }
        }
        Err(e) => {
            eprintln!("SECURITY: job submission {submitter}: queue failed ({e})");
            return;
        }
    }
    println!("job submitted by {submitter}: {} → {}", descriptor.job_id, path.display());
    if let Some(c) = conns.lock().unwrap().get_mut(&conn) {
        let _ = c.outbound.send(ServerToClient::SubmissionAck {
            job_id: descriptor.job_id.clone(),
            accepted: true,
            reason: None,
            proving: false,
        });
    }
    if let Some(p) = pending.as_mut() {
        // A submitter waiting on THIS job's outcome is registered —
        // rare (resubmission of a running job) but harmless to track.
        if p.descriptor.job_id == descriptor.job_id && !p.subscribers.contains(&conn) {
            p.subscribers.push(conn);
        }
    }
}

/// The zk receipt-claim admission gate: exactly one claim attempt per/// The zk receipt-claim admission gate: exactly one claim attempt per
/// dispatched worker per job. Returns false (and consumes nothing but
/// the record of the attempt) when the worker has already claimed —
/// a rejected or slow claim cannot be replayed to re-stall the
/// verifier. Lives as a function so the regression test exercises the
/// same code the network path runs.
fn receipt_claim_gate(claimed: &mut Vec<String>, worker_id: &str) -> bool {
    if claimed.iter().any(|id| id == worker_id) {
        return false;
    }
    claimed.push(worker_id.to_string());
    true
}

/// Validate and (via the external verifier) check a zk receipt claim,
/// then mark the pending job as accepted on the proof alone.
fn handle_receipt_claim(
    cfg: &ServeConfig,
    pending: &mut Option<PendingJob>,
    worker_id: &str,
    job_id: &str,
    pubkey_hex: &str,
    sig_hex: &str,
    receipt_hex: &str,
) {
    let Some(zk) = &cfg.zk else {
        eprintln!("SECURITY: receipt claim dropped — zk tier not configured");
        return;
    };
    // Size gate BEFORE decoding: hex decode doubles the allocation,
    // so an unbounded claim must be refused on its encoded length.
    if receipt_hex.len() > 2 * crate::receipt::MAX_RECEIPT_BYTES {
        eprintln!(
            "SECURITY: receipt claim from {worker_id} dropped — {} hex chars exceeds the limit",
            receipt_hex.len()
        );
        return;
    }
    let receipt_bytes = match jobfmt::from_hex(receipt_hex, receipt_hex.len() / 2) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SECURITY: receipt claim {worker_id}: bad hex ({e})");
            return;
        }
    };
    let receipt_hash: [u8; 32] = blake3::hash(&receipt_bytes).into();
    if let Err(e) = verify_claim_sig(pubkey_hex, job_id, &receipt_hash, sig_hex) {
        eprintln!("SECURITY: receipt claim signature invalid ({worker_id}): {e}");
        return;
    }

    let Some(job) = pending.as_mut() else { return };
    if job_id != job.descriptor.job_id || job.zk_accept.is_some() {
        return;
    }
    if !job.dispatched_ids.iter().any(|id| id == worker_id) {
        eprintln!(
            "SECURITY: receipt claim from non-dispatched worker {worker_id} dropped"
        );
        return;
    }
    // One receipt-claim attempt per dispatched worker: the attempt is
    // consumed whether the verification succeeds or fails, so a
    // rejected claim cannot be replayed to re-stall the verifier.
    if !receipt_claim_gate(&mut job.receipt_claimed, worker_id) {
        eprintln!("SECURITY: repeat receipt claim from {worker_id} dropped");
        return;
    }
    let decode32 = |h: &str| -> Result<[u8; 32], String> {
        jobfmt::from_hex(h, 32)
            .map_err(|e| format!("descriptor hash: {e}"))?
            .try_into()
            .map_err(|_| "descriptor hash length".to_string())
    };
    let expected_binding = [
        match decode32(&job.descriptor.manifest) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("SECURITY: {e}");
                return;
            }
        },
        match decode32(&job.descriptor.elf) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("SECURITY: {e}");
                return;
            }
        },
        match decode32(&job.descriptor.input) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("SECURITY: {e}");
                return;
            }
        },
    ];
    match crate::receipt::verify_receipt(&zk.cmd, &receipt_bytes, &expected_binding, &zk.guest_elf)
    {
        Ok(outcome) if outcome.status == 0 => {
            let hash = outcome.chunk_hashes.last().cloned().unwrap_or_default();
            println!(
                "zk receipt verified: {worker_id} → {} ({} instructions)",
                &hash[..12.min(hash.len())],
                outcome.instructions
            );
            job.zk_accept = Some(Decision::Accept {
                hash,
                output_hex: Some(outcome.output_hex),
                agreed: vec![worker_id.to_string()],
                zk: true,
            });
        }
        Ok(outcome) => {
            eprintln!("zk receipt from {worker_id} reports failure status {}", outcome.status);
        }
        Err(e) => {
            eprintln!("SECURITY: invalid receipt claim ({worker_id}): {e}");
        }
    }
}

/// Verify a zk receipt claim's signature: the worker signs
/// `receipt_claim_message(job_id, blake3(receipt))`, binding the
/// identity to the specific receipt and job.
fn verify_claim_sig(
    pubkey_hex: &str,
    job_id: &str,
    receipt_hash: &[u8; 32],
    sig_hex: &str,
) -> Result<(), String> {
    let pk_bytes = jobfmt::from_hex(pubkey_hex, 32).map_err(|e| format!("pubkey: {e}"))?;
    let sig_bytes = jobfmt::from_hex(sig_hex, 64).map_err(|e| format!("signature: {e}"))?;
    let vk = VerifyingKey::from_bytes(&pk_bytes.try_into().unwrap())
        .map_err(|e| format!("pubkey: {e}"))?;
    let sig = Signature::from_bytes(&sig_bytes.try_into().unwrap());
    let msg = jobfmt::receipt_claim_message(job_id, receipt_hash);
    vk.verify(&msg, &sig).map_err(|e| format!("signature: {e}"))
}

fn verify_nonce(pubkey_hex: &str, nonce_hex: &[u8], sig_hex: &str) -> Result<(), String> {
    // The pubkey and signature strings arrive over the wire BEFORE the
    // sender is authenticated: decoding must never panic (no index
    // slicing of possibly-multi-byte UTF-8, exact lengths required).
    let pk_bytes =
        jobfmt::from_hex(pubkey_hex, 32).map_err(|e| format!("pubkey: {e}"))?;
    let sig_bytes = jobfmt::from_hex(sig_hex, 64).map_err(|e| format!("signature: {e}"))?;
    let pk = VerifyingKey::from_bytes(&pk_bytes.try_into().unwrap())
        .map_err(|e| format!("{e}"))?;
    let sig = Signature::from_bytes(&sig_bytes.try_into().unwrap());
    pk.verify(nonce_hex, &sig).map_err(|e| format!("{e}"))
}

/// Fisher-Yates shuffle driven by the OS CSPRNG — unbiased round-1
/// worker selection. "First N authed workers" is gameable: connect
/// first, get picked.
fn shuffle<T>(items: &mut [T]) {
    use rand_core::RngCore;
    let mut rng = rand_core::OsRng;
    for i in (1..items.len()).rev() {
        let j = (rng.next_u64() as usize) % (i + 1);
        items.swap(i, j);
    }
}

fn rand_nonce() -> [u8; 32] {
    use rand_core::RngCore;
    let mut n = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut n);
    n
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn session_loop(
    conn: usize,
    mut stream: wire::BoxedStream,
    outbound_rx: Receiver<ServerToClient>,
    tx: Sender<Event>,
    conns: Arc<Mutex<HashMap<usize, Conn>>>,
) {
    eprintln!("conn {conn}: session loop running");
    loop {
        let frame = wire::receive_polled::<ClientToServer>(&mut stream, Duration::from_millis(100));
        if frame.is_err() {
            eprintln!("conn {conn}: receive error: {:?}", frame.as_ref().err().unwrap());
        }
        match frame {
            Ok(Some(ClientToServer::Hello { pubkey_hex, worker_id, listen_port })) => {
                eprintln!("conn {conn}: Hello received");
                tx.send(Event::Hello { conn, pubkey: pubkey_hex, worker_id, listen_port })
                    .ok();
            }
            Ok(Some(ClientToServer::NonceSignature { sig_hex, pow_counter })) => {
                tx.send(Event::NonceSig { conn, sig: sig_hex, pow_counter }).ok();
            }
            Ok(Some(ClientToServer::BlobRequest { id_hex })) => {
                tx.send(Event::BlobRequest { conn, id: id_hex }).ok();
            }
            Ok(Some(ClientToServer::JobResult { result })) => {
                tx.send(Event::Result { conn, result }).ok();
            }
            Ok(Some(ClientToServer::JobSubmission {
                submitter,
                descriptor,
                pubkey_hex,
                sig_hex,
                require_zk,
            })) => {
                tx.send(Event::JobSubmission {
                    conn,
                    submitter,
                    descriptor,
                    pubkey_hex,
                    sig_hex,
                    require_zk,
                })
                .ok();
            }
            Ok(Some(ClientToServer::ReceiptClaim {
                worker_id,
                job_id,
                pubkey_hex,
                sig_hex,
                receipt_hex,
            })) => {
                tx.send(Event::ReceiptClaim {
                    conn,
                    worker_id,
                    job_id,
                    pubkey_hex,
                    sig_hex,
                    receipt_hex,
                })
                .ok();
            }
            Ok(None) => {
                // Idle window: push anything the main loop queued.
                let mut pumped = 0usize;
                while let Ok(msg) = outbound_rx.try_recv() {
                    if wire::send(&mut stream, &msg).is_err() {
                        conns.lock().unwrap().remove(&conn);
                        tx.send(Event::Closed { conn }).ok();
                        return;
                    }
                    pumped += 1;
                }
                if pumped > 0 {
                    eprintln!("conn {conn}: pumped {pumped} queued messages");
                }
            }
            Err(e) => {
                let wid = conns
                    .lock()
                    .unwrap()
                    .get(&conn)
                    .map(|c| c.worker_id.clone())
                    .unwrap_or_else(|| format!("conn{conn}"));
                if matches!(e, wire::WireError::ConnectionClosed) {
                    println!("worker {wid}: connection closed by peer");
                } else {
                    // Non-close errors are the diagnostic trail for the
                    // intermittent between-jobs drop.
                    eprintln!("worker {wid}: reader error: {e}");
                }
                conns.lock().unwrap().remove(&conn);
                tx.send(Event::Closed { conn }).ok();
                break;
            }
        }
    }
}


#[cfg(test)]
mod receipt_gate_tests {
    use super::receipt_claim_gate;

    #[test]
    fn one_attempt_per_worker_then_dropped() {
        let mut claimed: Vec<String> = Vec::new();
        assert!(receipt_claim_gate(&mut claimed, "wC"));
        assert!(!receipt_claim_gate(&mut claimed, "wC"), "repeat must be dropped");
        assert!(receipt_claim_gate(&mut claimed, "wD"), "a different worker still claims");
        assert_eq!(claimed, vec!["wC".to_string(), "wD".to_string()]);
    }
}
