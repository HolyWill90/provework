//! The full-network integration test over REAL TCP sockets, three
//! jobs in one persistent session:
//!   job 1: demo-hash-smoke → all workers (quorum accept)
//!   job 2: agent-task → all workers (a second, different job over
//!          the same session — blobs fetched from the coordinator)
//!   job 3: demo-hash-smoke again → targeted at a NEW worker wC with an
//!          empty store, whose only peer hint is wA. The blobs must
//!          arrive worker-to-worker: wA's served counter goes up,
//!          wC's from-server counter stays zero.

use coordinator::net::{self, JobOutcome, ServeConfig};
use ed25519_dalek::Signer;
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use worker::daemon::{run_daemon, DaemonConfig};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(name);
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Queue a descriptor atomically: the coordinator polls the watched
/// directory continuously, and a plain write truncates the file first
/// — the poll could read an empty or partial descriptor mid-write.
fn queue_desc(jobs_dir: &Path, name: &str, desc: &contentstore::JobDescriptor) {
    let tmp = jobs_dir.join(format!("{name}.queueing"));
    std::fs::write(&tmp, serde_json::to_vec(desc).unwrap()).unwrap();
    std::fs::rename(&tmp, jobs_dir.join(format!("{name}.desc.json"))).unwrap();
}

fn wait_job(rx: &std::sync::mpsc::Receiver<JobOutcome>) -> JobOutcome {
    // Upper bound = the coordinator's own worst case (two full per-job
    // deadline windows: round 1 + escalation) plus slow-runner
    // headroom. Smoke jobs finish in seconds; only a hang trips this.
    rx.recv_timeout(std::time::Duration::from_secs(300))
        .expect("job finished in time")
}

#[test]
fn multi_job_session_with_p2p_blob_exchange() {
    let demo_elf = std::path::Path::new("../../jobs/demo-hash-smoke/program.elf");
    let agent_elf = std::path::Path::new("../../jobs/agent-task/program.elf");
    if !demo_elf.exists() || !agent_elf.exists() {
        eprintln!("SKIP: build the demo-hash-smoke and agent-task jobs first");
        return;
    }
    let root = temp_dir("p2pc-net-multi");
    let jobs_dir = root.join("jobs");
    let store_dir = root.join("store");
    std::fs::create_dir_all(&jobs_dir).unwrap();
    let store = contentstore::Store::open(&store_dir).unwrap();

    // Publish the two distinct jobs into the server's store.
    let desc1 = contentstore::publish(&PathBuf::from("../../jobs/demo-hash-smoke"), &store).unwrap();
    let desc2 = contentstore::publish(&PathBuf::from("../../jobs/agent-task"), &store).unwrap();

    let (bound_tx, bound_rx) = channel();
    let (job_tx, job_rx) = channel::<JobOutcome>();
    let cfg = ServeConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        jobs_dir: jobs_dir.clone(),
        store_dir: store_dir.clone(),
        per_job_deadline: std::time::Duration::from_secs(90),
        ledger: Some(root.join("ledger.json")),
        require_identity: true,
        identity_pow_bits: 0,
        accept_submissions: false,
        results_dir: None,
        zk: None,
        zk_judge: None,
        round1_ids: None,
        pool: Some(2),
        round1_size: None,
        tls: None,
        bound_tx: Some(bound_tx),
        max_jobs: Some(3),
        job_tx: Some(job_tx),
    };

    std::thread::spawn(move || {
        net::serve(cfg).expect("serve");
    });

    let bound = bound_rx.recv_timeout(std::time::Duration::from_secs(15)).unwrap();
    println!("coordinator bound at {bound}");

    // Job 1 queued before any worker connects.
    queue_desc(&jobs_dir, "job1", &desc1);

    let identities = root.join("identities");
    std::fs::create_dir_all(&identities).unwrap();

    // Worker A: serves blobs to peers. Worker B: plain.
    let mut handles = Vec::new();
    {
        let server = bound.to_string();
        let identity = identities.join("wA.key");
        let store_dir = root.join("worker-store-A");
        handles.push(std::thread::spawn(move || {
            run_daemon(&DaemonConfig {
                server,
                worker_id: "wA".into(),
                identity_path: Some(identity),
                store_dir,
                listen_port: Some(0),
                tls: None,
                corrupt: false,
                corrupt_byte: None,
                extra_submits: 0,
                receipt_file: None,
            })
        }));
    }
    {
        let server = bound.to_string();
        let identity = identities.join("wB.key");
        let store_dir = root.join("worker-store-B");
        handles.push(std::thread::spawn(move || {
            run_daemon(&DaemonConfig {
                server,
                worker_id: "wB".into(),
                identity_path: Some(identity),
                store_dir,
                listen_port: None,
                tls: None,
                corrupt: false,
                corrupt_byte: None,
                extra_submits: 0,
                receipt_file: None,
            })
        }));
    }

    // --- job 1: demo-hash-smoke, both workers, quorum accept ---
    let job1 = wait_job(&job_rx);
    assert_eq!(job1.job_id, "demo-hash-smoke-0001");
    assert_eq!(job1.results.len(), 2, "both workers ran job 1");
    assert_eq!(job1.results[0].result_hash, job1.results[1].result_hash);
    let demo_digest = job1.results[0].result_hash.clone();
    let coordinator::Decision::Accept { agreed, .. } = &job1.decision else {
        panic!("job 1 should accept");
    };
    assert_eq!(agreed.len(), 2);

    // --- job 2: agent-task, same session, new blobs from the coordinator ---
    queue_desc(&jobs_dir, "job2", &desc2);
    let job2 = wait_job(&job_rx);
    let coordinator::Decision::Accept { .. } = &job2.decision else {
        panic!("job 2 should accept");
    };
    assert_eq!(job2.results.len(), 2);

    // --- job 3: demo-hash-smoke AGAIN, targeted at a fresh worker wC whose
    // only blob source is worker A (p2p exchange) ---
    let desc3 = contentstore::publish(&PathBuf::from("../../jobs/demo-hash-smoke"), &store).unwrap();
    queue_desc(&jobs_dir, "job3@wC", &desc3);
    {
        let server = bound.to_string();
        let identity = identities.join("wC.key");
        let store_dir = root.join("worker-store-C");
        handles.push(std::thread::spawn(move || {
            run_daemon(&DaemonConfig {
                server,
                worker_id: "wC".into(),
                identity_path: Some(identity),
                store_dir,
                listen_port: None,
                tls: None,
                corrupt: false,
                corrupt_byte: None,
                extra_submits: 0,
                receipt_file: None,
            })
        }));
    }
    let job3 = wait_job(&job_rx);
    assert_eq!(job3.job_id, "demo-hash-smoke-0001");
    assert_eq!(job3.results.len(), 1, "job 3 targeted at wC only");
    assert_eq!(job3.results[0].result_hash, demo_digest, "re-execution matches job 1");
    let coordinator::Decision::Accept { .. } = &job3.decision else {
        panic!("job 3 should accept");
    };

    // Server exits after 3 jobs; daemons report their stats.
    let mut stats: Vec<_> = Vec::new();
    for h in handles {
        match h.join() {
            Ok(Ok(s)) => stats.push(s),
            Ok(Err(e)) => panic!("daemon error: {e}"),
            Err(e) => std::panic::panic_any(e),
        }
    }
    let a = stats.iter().find(|s| s.jobs_done == 2).expect("worker A did 2 jobs");
    let c = stats.iter().find(|s| s.jobs_done == 1).expect("worker C did 1 job");

    // THE P2P ASSERTION: wC's three blobs arrived worker-to-worker —
    // none from the coordinator — and wA served at least those three
    // (it may also have served wB's job-1 fetches, which race wA's own
    // caching; the fallback covers that race).
    assert_eq!(c.blobs_from_peers, 3, "wC fetched all blobs from peers");
    assert_eq!(c.blobs_from_server, 0, "wC never fell back to the coordinator");
    assert!(
        a.blobs_served_to_peers >= 3,
        "wA served the blobs p2p (served: {})",
        a.blobs_served_to_peers
    );

    // Ledger: three jobs recorded.
    let ledger = coordinator::ledger::Ledger::load(&root.join("ledger.json")).unwrap();
    assert_eq!(ledger.history.len(), 3);
}

/// The same session over TLS: coordinator serves with a self-signed
/// certificate, daemons pin its fingerprint, and the full job flow —
/// auth, blob fetch, execution, signed result — runs encrypted.
#[test]
fn tls_network_session() {
    let demo_elf = std::path::Path::new("../../jobs/demo-hash-smoke/program.elf");
    if !demo_elf.exists() {
        eprintln!("SKIP: build the demo job first");
        return;
    }
    let root = temp_dir("p2pc-net-tls");
    let jobs_dir = root.join("jobs");
    let store_dir = root.join("store");
    std::fs::create_dir_all(&jobs_dir).unwrap();
    let store = contentstore::Store::open(&store_dir).unwrap();

    let desc = contentstore::publish(&PathBuf::from("../../jobs/demo-hash-smoke"), &store).unwrap();
    let cert_path = store_dir.join("coordinator-cert.der");

    let (bound_tx, bound_rx) = channel();
    let (job_tx, job_rx) = channel::<JobOutcome>();
    let cfg = ServeConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        jobs_dir: jobs_dir.clone(),
        store_dir: store_dir.clone(),
        per_job_deadline: std::time::Duration::from_secs(90),
        ledger: Some(root.join("ledger.json")),
        require_identity: true,
        identity_pow_bits: 0,
        accept_submissions: false,
        results_dir: None,
        zk: None,
        zk_judge: None,
        round1_ids: None,
        pool: Some(2),
        round1_size: None,
        tls: None,
        bound_tx: Some(bound_tx),
        max_jobs: Some(1),
        job_tx: Some(job_tx),
    };

    // Generate the coordinator certificate up front so the workers can
    // pin it (in production, serve --tls generates it on first run).
    let (cert, key) = wire::tls::generate_self_signed().unwrap();
    std::fs::write(store_dir.join("coordinator-cert.der"), cert.as_ref()).unwrap();
    std::fs::write(store_dir.join("coordinator-key.der"), key.secret_der()).unwrap();
    let cert_der = std::fs::read(&cert_path).unwrap();

    std::thread::spawn(move || {
        let cfg = ServeConfig {
            tls: Some((cert.as_ref().to_vec(), key.secret_der().to_vec())),
            ..cfg
        };
        net::serve(cfg).expect("serve");
    });
    let bound = bound_rx.recv_timeout(std::time::Duration::from_secs(15)).unwrap();

    queue_desc(&jobs_dir, "job1", &desc);

    let identities = root.join("identities");
    std::fs::create_dir_all(&identities).unwrap();
    let cert_copy = root.join("coordinator-cert.der");
    std::fs::copy(store_dir.join("coordinator-cert.der"), &cert_copy).unwrap();

    let mut handles = Vec::new();
    for id in ["wA", "wB"] {
        let server = bound.to_string();
        let identity = identities.join(format!("{id}.key"));
        let store_dir = root.join(format!("worker-store-{id}"));
        let cert_copy = cert_copy.clone();
        handles.push(std::thread::spawn(move || {
            let tls = Some(std::fs::read(&cert_copy).expect("read coordinator cert"));
            run_daemon(&DaemonConfig {
                server,
                worker_id: id.into(),
                identity_path: Some(identity),
                store_dir,
                listen_port: None,
                tls,
                corrupt: false,
                corrupt_byte: None,
                extra_submits: 0,
                receipt_file: None,
            })
        }));
    }

    let job1 = wait_job(&job_rx);
    assert_eq!(job1.job_id, "demo-hash-smoke-0001");
    assert_eq!(job1.results.len(), 2);
    assert_eq!(job1.results[0].result_hash, job1.results[1].result_hash);
    let coordinator::Decision::Accept { hash, agreed, .. } = &job1.decision else {
        panic!("job 1 should accept");
    };
    assert_eq!(agreed.len(), 2, "both TLS workers agreed");

    // Digest sanity: matches the known demo-hash-smoke result.
    assert_eq!(hash, "b4674657d1b9ac50f6d3f222c72d0c132ef03ce7ca8c417060d2492784dc80a6");

    for h in handles {
        h.join().unwrap().unwrap();
    }
    let _ = cert_der;
}

/// Reserve escalation over the wire: round 1 is named as an honest
/// worker plus a liar (round1_ids), so no majority forms; the honest
/// reserve is held back and the coordinator must escalate to it. The
/// escalated result joins round 1's honest vote for a 2/3 majority,
/// the job is accepted, and the liar's bond burns.
#[test]
fn reserve_escalation_beats_lying_worker() {
    // Regression guard: dispatch waits for full-pool authentication so
    // escalation reserves are populated (see DESIGN.md, RESOLVED entry).
    let demo_elf = std::path::Path::new("../../jobs/demo-hash-smoke/program.elf");
    if !demo_elf.exists() {
        eprintln!("SKIP: build the demo job first");
        return;
    }
    let root = temp_dir("p2pc-net-reserves");
    let jobs_dir = root.join("jobs");
    let store_dir = root.join("store");
    std::fs::create_dir_all(&jobs_dir).unwrap();
    let store = contentstore::Store::open(&store_dir).unwrap();
    let desc = contentstore::publish(&PathBuf::from("../../jobs/demo-hash-smoke"), &store).unwrap();

    let (bound_tx, bound_rx) = channel();
    let (job_tx, job_rx) = channel::<JobOutcome>();
    let cfg = ServeConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        jobs_dir: jobs_dir.clone(),
        store_dir: store_dir.clone(),
        per_job_deadline: std::time::Duration::from_secs(90),
        ledger: Some(root.join("ledger.json")),
        require_identity: true,
        identity_pow_bits: 0,
        accept_submissions: false,
        results_dir: None,
        zk: None,
        zk_judge: None,
        pool: Some(3),
        round1_size: None,
        round1_ids: Some(vec!["wA".into(), "wB".into()]),
        tls: None,
        bound_tx: Some(bound_tx),
        max_jobs: Some(1),
        job_tx: Some(job_tx),
    };
    std::thread::spawn(move || net::serve(cfg).expect("serve"));
    let bound = bound_rx.recv_timeout(std::time::Duration::from_secs(15)).unwrap();

    queue_desc(&jobs_dir, "job1", &desc);

    let identities = root.join("identities");
    std::fs::create_dir_all(&identities).unwrap();
    let mut handles = Vec::new();
    // Pool of 3, round 1 named [wA, wB]: wA honest, wB corrupts its
    // result, wC is the held-back honest reserve. One lie against one
    // honest vote leaves no majority, so the coordinator escalates to
    // wC, whose result joins wA's for the 2/3 accept.
    let spawns: Vec<(&str, bool, Option<u8>)> = vec![
        ("wA", false, None),
        ("wB", true, Some(9)), // journal byte 9 bumped — divergence is guaranteed
        ("wC", false, None),
    ];
    for (id, corrupt, byte) in spawns {
        let server = bound.to_string();
        let identity = identities.join(format!("{id}.key"));
        let store_dir = root.join(format!("worker-store-{id}"));
        handles.push(std::thread::spawn(move || {
            run_daemon(&DaemonConfig {
                server,
                worker_id: id.into(),
                identity_path: Some(identity),
                store_dir,
                listen_port: None,
                tls: None,
                corrupt,
                corrupt_byte: byte,
                extra_submits: 0,
                receipt_file: None,
            })
        }));
    }

    let job1 = wait_job(&job_rx);
    let coordinator::Decision::Accept { hash, agreed, .. } = &job1.decision else {
        panic!("escalation should end in accept, got {:?}", job1.decision);
    };
    assert_eq!(hash, "b4674657d1b9ac50f6d3f222c72d0c132ef03ce7ca8c417060d2492784dc80a6");
    assert_eq!(agreed, &vec!["wA".to_string(), "wC".to_string()]);
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// A descriptor being written while the coordinator polls the watched
/// directory must not kill the server: the poll skips the unreadable
/// file for the grace window, and the job runs once the write
/// completes. Regression for the mid-write empty-file race that
/// crashed serve ("EOF while parsing a value at line 1 column 0").
#[test]
fn partial_descriptor_write_does_not_kill_server() {
    let smoke_elf = std::path::Path::new("../../jobs/demo-hash-smoke/program.elf");
    if !smoke_elf.exists() {
        eprintln!("SKIP: build the demo-hash-smoke job first");
        return;
    }
    let root = temp_dir("p2pc-net-partial-desc");
    let jobs_dir = root.join("jobs");
    let store_dir = root.join("store");
    std::fs::create_dir_all(&jobs_dir).unwrap();
    let store = contentstore::Store::open(&store_dir).unwrap();
    let desc = contentstore::publish(&PathBuf::from("../../jobs/demo-hash-smoke"), &store).unwrap();

    let (bound_tx, bound_rx) = channel();
    let (job_tx, job_rx) = channel::<JobOutcome>();
    let cfg = ServeConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        jobs_dir: jobs_dir.clone(),
        store_dir: store_dir.clone(),
        per_job_deadline: std::time::Duration::from_secs(90),
        ledger: None,
        require_identity: true,
        identity_pow_bits: 0,
        accept_submissions: false,
        results_dir: None,
        zk: None,
        zk_judge: None,
        pool: Some(1),
        round1_size: None,
        round1_ids: None,
        tls: None,
        bound_tx: Some(bound_tx),
        max_jobs: Some(1),
        job_tx: Some(job_tx),
    };
    std::thread::spawn(move || net::serve(cfg).expect("serve"));
    let bound = bound_rx.recv_timeout(std::time::Duration::from_secs(15)).unwrap();

    // Simulate the mid-write window: an empty file sits where the
    // descriptor will land. The old scan treated this as fatal.
    std::fs::write(jobs_dir.join("job1.desc.json"), b"").unwrap();

    let identities = root.join("identities");
    std::fs::create_dir_all(&identities).unwrap();
    let server = bound.to_string();
    let identity = identities.join("wA.key");
    let store_dir = root.join("worker-store-wA");
    let worker = std::thread::spawn(move || {
        run_daemon(&DaemonConfig {
            server,
            worker_id: "wA".into(),
            identity_path: Some(identity),
            store_dir,
            listen_port: None,
            tls: None,
            corrupt: false,
            corrupt_byte: None,
            extra_submits: 0,
            receipt_file: None,
        })
    });

    // Well inside the grace window: finish the write atomically.
    std::thread::sleep(std::time::Duration::from_millis(1500));
    queue_desc(&jobs_dir, "job1", &desc);

    let job1 = wait_job(&job_rx);
    let coordinator::Decision::Accept { .. } = &job1.decision else {
        panic!("job should accept after the descriptor write completes");
    };
    worker.join().unwrap().unwrap();
}


/// A raw wire client (no daemon): authenticate with its own Ed25519 key
/// and submit one signed result. Emulates a worker that was never
/// dispatched trying to vote, outside the assignment-driven flow.
struct RawClient {
    stream: std::net::TcpStream,
    key: ed25519_dalek::SigningKey,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl RawClient {
    fn connect(server: &str, worker_id: &str) -> Self {
        use wire::{ClientToServer, ServerToClient};
        let mut stream = std::net::TcpStream::connect(server).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        wire::send(
            &mut stream,
            &ClientToServer::Hello {
                pubkey_hex: hex(&key.verifying_key().to_bytes()),
                worker_id: worker_id.into(),
                listen_port: None,
            },
        )
        .unwrap();
        loop {
            match wire::receive::<ServerToClient>(&mut stream).unwrap() {
                ServerToClient::Nonce { hex: nonce, pow_bits } => {
                    // The coordinator verifies over the RAW nonce bytes.
                    let nonce_bytes =
                        jobfmt::from_hex(&nonce, nonce.len() / 2).unwrap();
                    let sig = key.sign(&nonce_bytes);
                    wire::send(
                        &mut stream,
                        &ClientToServer::NonceSignature {
                            sig_hex: Some(hex(&sig.to_bytes())),
                            pow_counter: wire::mine_pow(&nonce_bytes, pow_bits),
                        },
                    )
                    .unwrap();
                }
                ServerToClient::AuthOk { .. } => break,
                other => panic!("unexpected during auth: {other:?}"),
            }
        }
        RawClient { stream, key }
    }

    fn submit(&mut self, result: &jobfmt::WorkerResult) {
        use wire::ClientToServer;
        wire::send(&mut self.stream, &ClientToServer::JobResult { result: result.clone() })
            .unwrap();
    }
}

fn honest_result(
    worker_id: &str,
    job_id: &str,
    key: &ed25519_dalek::SigningKey,
) -> jobfmt::WorkerResult {
    let mut r = jobfmt::WorkerResult {
        worker_id: worker_id.into(),
        job_id: job_id.into(),
        status: "halted".into(),
        instructions: 524314,
        result_hash: "67925f935808b41f326dd1f183e8e2951ac8d01f647e0d987f2cefa8944879b5".into(),
        chunk_hashes: vec![
            "67925f935808b41f326dd1f183e8e2951ac8d01f647e0d987f2cefa8944879b5".into(),
        ],
        output_hex: Some("25a3ab01".into()),
        trap: None,
        pubkey_hex: Some(hex(&key.verifying_key().to_bytes())),
        sig_hex: None,
    };
    let sig = key.sign(&jobfmt::signing_message(&r));
    r.sig_hex = Some(hex(&sig.to_bytes()));
    r
}


fn net_security_cfg(
    bind_tx: std::sync::mpsc::Sender<std::net::SocketAddr>,
    job_tx: std::sync::mpsc::Sender<JobOutcome>,
    jobs_dir: std::path::PathBuf,
    store_dir: std::path::PathBuf,
    pool: usize,
    round1: Vec<String>,
) -> net::ServeConfig {
    net::ServeConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        jobs_dir,
        store_dir,
        per_job_deadline: std::time::Duration::from_secs(90),
        ledger: None,
        require_identity: true,
        identity_pow_bits: 8,
        accept_submissions: false,
        results_dir: None,
        zk: None,
        zk_judge: None,
        pool: Some(pool),
        round1_size: None,
        round1_ids: Some(round1),
        tls: None,
        bound_tx: Some(bind_tx),
        max_jobs: Some(1),
        job_tx: Some(job_tx),
    }
}

/// SECURITY: a worker the job was never dispatched to cannot vote. Its
/// result must be dropped before quorum, even when fully authenticated
/// and correctly signed.
#[test]
fn non_dispatched_worker_cannot_vote() {
    let smoke_elf = std::path::Path::new("../../jobs/demo-hash-smoke/program.elf");
    if !smoke_elf.exists() {
        eprintln!("SKIP: build the demo-hash-smoke job first");
        return;
    }
    let root = temp_dir("p2pc-net-nondispatch");
    let jobs_dir = root.join("jobs");
    let store_dir = root.join("store");
    std::fs::create_dir_all(&jobs_dir).unwrap();
    let store = contentstore::Store::open(&store_dir).unwrap();
    let desc = contentstore::publish(&PathBuf::from("../../jobs/demo-hash-smoke"), &store).unwrap();

    let (bound_tx, bound_rx) = channel();
    let (job_tx, job_rx) = channel::<JobOutcome>();
    let cfg = net_security_cfg(bound_tx, job_tx, jobs_dir.clone(), store_dir, 3, vec![
        "wA".into(),
        "wB".into(),
    ]);
    std::thread::spawn(move || net::serve(cfg).expect("serve"));
    let bound = bound_rx.recv_timeout(std::time::Duration::from_secs(15)).unwrap();
    queue_desc(&jobs_dir, "job1", &desc);

    // Dispatch fires once the named round-1 workers authenticate.
    let identities = root.join("identities");
    std::fs::create_dir_all(&identities).unwrap();
    let mut handles = Vec::new();
    for id in ["wA", "wB"] {
        let server = bound.to_string();
        let identity = identities.join(format!("{id}.key"));
        let store_dir = root.join(format!("worker-store-{id}"));
        handles.push(std::thread::spawn(move || {
            run_daemon(&DaemonConfig {
                server,
                worker_id: id.into(),
                identity_path: Some(identity),
                store_dir,
                listen_port: None,
                tls: None,
                corrupt: false,
                corrupt_byte: None,
                extra_submits: 0,
                receipt_file: None,
            })
        }));
    }
    // Give dispatch a beat, then the raw non-dispatched client votes.
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let mut client = RawClient::connect(&bound.to_string(), "wC");
    client.submit(&honest_result("wC", "demo-hash-smoke-0001", &client.key));

    let job1 = wait_job(&job_rx);
    let coordinator::Decision::Accept { agreed, .. } = &job1.decision else {
        panic!("job should accept, got {:?}", job1.decision);
    };
    assert!(
        !agreed.contains(&"wC".to_string()),
        "non-dispatched worker's vote must be dropped, got {agreed:?}"
    );
    // agreed follows result arrival order; compare as a set.
    let mut sorted = agreed.clone();
    sorted.sort();
    assert_eq!(sorted, vec!["wA".to_string(), "wB".to_string()]);
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// SECURITY: a dispatched worker's duplicate submissions must not
/// stuff the quorum. wA submits its honest result TWICE; wB lies.
/// Counting duplicates, wA's pair would form a 2/3 "majority"; the
/// correct outcome is a reject for lack of a genuine majority.
#[test]
fn duplicate_submissions_do_not_stuff_quorum() {
    let smoke_elf = std::path::Path::new("../../jobs/demo-hash-smoke/program.elf");
    if !smoke_elf.exists() {
        eprintln!("SKIP: build the demo-hash-smoke job first");
        return;
    }
    let root = temp_dir("p2pc-net-dupe");
    let jobs_dir = root.join("jobs");
    let store_dir = root.join("store");
    std::fs::create_dir_all(&jobs_dir).unwrap();
    let store = contentstore::Store::open(&store_dir).unwrap();
    let desc = contentstore::publish(&PathBuf::from("../../jobs/demo-hash-smoke"), &store).unwrap();

    let (bound_tx, bound_rx) = channel::<std::net::SocketAddr>();
    let (job_tx, job_rx) = channel::<JobOutcome>();
    let cfg = ServeConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        jobs_dir: jobs_dir.clone(),
        store_dir: store_dir.clone(),
        per_job_deadline: std::time::Duration::from_secs(90),
        ledger: Some(root.join("ledger.json")),
        require_identity: true,
        identity_pow_bits: 8,
        accept_submissions: false,
        results_dir: None,
        zk: None,
        zk_judge: None,
        pool: Some(2),
        round1_size: None,
        round1_ids: Some(vec!["wA".into(), "wB".into()]),
        tls: None,
        bound_tx: Some(bound_tx),
        max_jobs: Some(1),
        job_tx: Some(job_tx),
    };
    std::thread::spawn(move || net::serve(cfg).expect("serve"));
    let bound = bound_rx.recv_timeout(std::time::Duration::from_secs(15)).unwrap();
    queue_desc(&jobs_dir, "job1", &desc);

    let identities = root.join("identities");
    std::fs::create_dir_all(&identities).unwrap();
    let mut handles = Vec::new();
    let spawns: Vec<(&str, bool, Option<u8>, u8)> =
        vec![("wA", false, None, 1), ("wB", true, Some(9), 0)];
    for (id, corrupt, byte, extra) in spawns {
        let server = bound.to_string();
        let identity = identities.join(format!("{id}.key"));
        let store_dir = root.join(format!("worker-store-{id}"));
        handles.push(std::thread::spawn(move || {
            run_daemon(&DaemonConfig {
                server,
                worker_id: id.into(),
                identity_path: Some(identity),
                store_dir,
                listen_port: None,
                tls: None,
                corrupt,
                corrupt_byte: byte,
                extra_submits: extra,
                receipt_file: None,
            })
        }));
    }

    let job1 = wait_job(&job_rx);
    // The duplicate was dropped (wA votes once), and with no majority
    // the replay judge arbitrates: the true chain vindicates wA and
    // convicts wB — no bare reject, the liar is proven and slashed.
    let coordinator::Decision::Accept { hash, agreed, zk, .. } = &job1.decision else {
        panic!("judge should vindicate the honest worker, got {:?}", job1.decision);
    };
    assert!(!*zk, "resolved by dispute judgment, not a zk receipt");
    assert_eq!(
        hash,
        "b4674657d1b9ac50f6d3f222c72d0c132ef03ce7ca8c417060d2492784dc80a6"
    );
    assert_eq!(agreed, &vec!["wA".to_string()]);
    let ledger = std::fs::read_to_string(root.join("ledger.json")).unwrap();
    assert!(ledger.contains("\"wB\": -100"), "liar slashed: {ledger}");
    assert!(ledger.contains("\"wA\": 10"), "honest rewarded: {ledger}");
    for h in handles {
        h.join().unwrap().unwrap();
    }
}


/// zk tier end to end: a receipt-carrier worker submits a signed SP1
/// receipt claim; the coordinator verifies it via the external
/// verifier binary and accepts the job on the proof alone. Skipped
/// unless the verifier binary, receipt and guest ELF are available
/// (CI's zk-receipt job builds and provides all three).
#[test]
fn zk_receipt_claim_accepts_job() {
    let (verify_cmd, guest_elf) = match (
        std::env::var("P2PC_ZK_VERIFY"),
        std::env::var("P2PC_ZK_GUEST_ELF"),
    ) {
        (Ok(v), Ok(g)) if std::path::Path::new(&v).exists() => (v, g),
        _ => {
            eprintln!("SKIP: zk verifier binary or guest ELF not available");
            return;
        }
    };
    let receipt_file =
        std::path::Path::new("../../sp1-artifacts/nano-receipt.bin");
    if !receipt_file.exists() {
        eprintln!("SKIP: committed nano receipt missing");
        return;
    }

    let root = temp_dir("p2pc-net-zk");
    let jobs_dir = root.join("jobs");
    let store_dir = root.join("store");
    std::fs::create_dir_all(&jobs_dir).unwrap();
    let store = contentstore::Store::open(&store_dir).unwrap();
    let desc = contentstore::publish(&PathBuf::from("../../jobs/demo-hash-nano"), &store).unwrap();

    let (bound_tx, bound_rx) = channel();
    let (job_tx, job_rx) = channel::<JobOutcome>();
    let cfg = ServeConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        jobs_dir: jobs_dir.clone(),
        store_dir: store_dir.clone(),
        per_job_deadline: std::time::Duration::from_secs(90),
        ledger: None,
        require_identity: true,
        identity_pow_bits: 8,
        accept_submissions: false,
        results_dir: None,
        zk: Some(net::ZkVerify {
            cmd: verify_cmd,
            guest_elf: PathBuf::from(guest_elf),
        }),
        zk_judge: None,
        pool: Some(1),
        round1_size: None,
        round1_ids: None,
        tls: None,
        bound_tx: Some(bound_tx),
        max_jobs: Some(1),
        job_tx: Some(job_tx),
    };
    std::thread::spawn(move || net::serve(cfg).expect("serve"));
    let bound = bound_rx.recv_timeout(std::time::Duration::from_secs(15)).unwrap();
    queue_desc(&jobs_dir, "job1", &desc);

    // The receipt carrier: never executes, just presents the proof.
    let identities = root.join("identities");
    std::fs::create_dir_all(&identities).unwrap();
    let server = bound.to_string();
    let identity = identities.join("wA.key");
    let store_dir = root.join("worker-store-wA");
    let receipt_file = receipt_file.to_path_buf();
    let handle = std::thread::spawn(move || {
        run_daemon(&DaemonConfig {
            server,
            worker_id: "wA".into(),
            identity_path: Some(identity),
            store_dir,
            listen_port: None,
            tls: None,
            corrupt: false,
            corrupt_byte: None,
            extra_submits: 0,
            receipt_file: Some(receipt_file),
        })
    });

    let job1 = wait_job(&job_rx);
    let coordinator::Decision::Accept { hash, agreed, zk, .. } = &job1.decision else {
        panic!("receipt claim should accept the job, got {:?}", job1.decision);
    };
    assert!(*zk, "acceptance must be zk-backed");
    assert_eq!(agreed, &vec!["wA".to_string()]);
    assert_eq!(
        hash,
        "00d58a79c3534d62fd37b04e9e934e412b717b70c26a851a9d2587d9f8bd2ce5"
    );
    handle.join().unwrap().unwrap();
}

/// The dispute judge against full collusion: two workers fabricate
/// DIFFERENT results (no majority, no honest vote to lean on), and the
/// coordinator's replay produces a chain matching NEITHER — both are
/// convicted by their own disagreement with the re-execution.
#[test]
fn dispute_judge_convicts_diverging_fabrications() {
    let smoke_elf = std::path::Path::new("../../jobs/demo-hash-smoke/program.elf");
    if !smoke_elf.exists() {
        eprintln!("SKIP: build the demo-hash-smoke job first");
        return;
    }
    let root = temp_dir("p2pc-net-judge");
    let jobs_dir = root.join("jobs");
    let store_dir = root.join("store");
    std::fs::create_dir_all(&jobs_dir).unwrap();
    let store = contentstore::Store::open(&store_dir).unwrap();
    let desc = contentstore::publish(&PathBuf::from("../../jobs/demo-hash-smoke"), &store).unwrap();

    let (bound_tx, bound_rx) = channel::<std::net::SocketAddr>();
    let (job_tx, job_rx) = channel::<JobOutcome>();
    let cfg = ServeConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        jobs_dir: jobs_dir.clone(),
        store_dir: store_dir.clone(),
        per_job_deadline: std::time::Duration::from_secs(90),
        ledger: Some(root.join("ledger.json")),
        require_identity: true,
        identity_pow_bits: 8,
        accept_submissions: false,
        results_dir: None,
        zk: None,
        zk_judge: None,
        pool: Some(2),
        round1_size: None,
        round1_ids: Some(vec!["wA".into(), "wB".into()]),
        tls: None,
        bound_tx: Some(bound_tx),
        max_jobs: Some(1),
        job_tx: Some(job_tx),
    };
    std::thread::spawn(move || net::serve(cfg).expect("serve"));
    let bound = bound_rx.recv_timeout(std::time::Duration::from_secs(15)).unwrap();
    queue_desc(&jobs_dir, "job1", &desc);

    let identities = root.join("identities");
    std::fs::create_dir_all(&identities).unwrap();
    let mut handles = Vec::new();
    // Both lie, with DIFFERENT fabricated tails — no majority, and the
    // replay matches neither fabrication.
    let spawns: Vec<(&str, bool, Option<u8>)> =
        vec![("wA", true, Some(3)), ("wB", true, Some(7))];
    for (id, corrupt, byte) in spawns {
        let server = bound.to_string();
        let identity = identities.join(format!("{id}.key"));
        let store_dir = root.join(format!("worker-store-{id}"));
        handles.push(std::thread::spawn(move || {
            run_daemon(&DaemonConfig {
                server,
                worker_id: id.into(),
                identity_path: Some(identity),
                store_dir,
                listen_port: None,
                tls: None,
                corrupt,
                corrupt_byte: byte,
                extra_submits: 0,
                receipt_file: None,
            })
        }));
    }

    let job1 = wait_job(&job_rx);
    let coordinator::Decision::Accept { hash, agreed, zk, .. } = &job1.decision else {
        panic!("judge should resolve the job, got {:?}", job1.decision);
    };
    assert!(!*zk);
    // The judge reports the TRUE result...
    assert_eq!(
        hash,
        "b4674657d1b9ac50f6d3f222c72d0c132ef03ce7ca8c417060d2492784dc80a6"
    );
    // ...and vindicates nobody: both fabrications contradicted it.
    assert!(agreed.is_empty(), "both liars must be convicted: {agreed:?}");
    let ledger = std::fs::read_to_string(root.join("ledger.json")).unwrap();
    assert!(ledger.contains("\"wA\": -100") && ledger.contains("\"wB\": -100"),
        "both liars slashed: {ledger}");
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// zk dispute judge end to end: one honest worker against one liar
/// (no majority, no reserves) escalates to the external zk-judge
/// process, whose SP1 receipt re-executes the job inside the zkVM.
/// Gated on P2PC_ZK_JUDGE_CMD + P2PC_ZK_JUDGE_GUEST_ELF: CI runs it
/// with SP1_PROVER=mock (fast, no real proving); the Linux proving
/// container runs it with the real CPU prover.
#[test]
fn zk_judge_dispute_receipt_vindicates_honest_worker() {
    let Ok(judge_cmd) = std::env::var("P2PC_ZK_JUDGE_CMD") else {
        eprintln!("SKIP: P2PC_ZK_JUDGE_CMD not set (build sp1-host/zk-judge)");
        return;
    };
    let Ok(guest_elf) = std::env::var("P2PC_ZK_JUDGE_GUEST_ELF") else {
        eprintln!("SKIP: P2PC_ZK_JUDGE_GUEST_ELF not set");
        return;
    };
    if !Path::new(&judge_cmd).exists() || !Path::new(&guest_elf).exists() {
        eprintln!("SKIP: zk judge binary or guest ELF missing");
        return;
    }
    // The nano job: its program.elf is a committed sealed artifact, so
    // this test needs no job build step.
    if !Path::new("../../jobs/demo-hash-nano/program.elf").exists() {
        eprintln!("SKIP: jobs/demo-hash-nano/program.elf missing");
        return;
    }
    let root = temp_dir("p2pc-net-zkjudge");
    let jobs_dir = root.join("jobs");
    let store_dir = root.join("store");
    std::fs::create_dir_all(&jobs_dir).unwrap();
    let store = contentstore::Store::open(&store_dir).unwrap();
    let desc = contentstore::publish(&PathBuf::from("../../jobs/demo-hash-nano"), &store).unwrap();

    let (bound_tx, bound_rx) = channel();
    let (job_tx, job_rx) = channel::<JobOutcome>();
    let cfg = net::ServeConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        jobs_dir: jobs_dir.clone(),
        store_dir: store_dir.clone(),
        per_job_deadline: std::time::Duration::from_secs(90),
        ledger: Some(root.join("ledger.json")),
        require_identity: true,
        identity_pow_bits: 8,
        accept_submissions: false,
        results_dir: None,
        zk: None,
        zk_judge: Some(coordinator::zk_judge::ZkJudge {
            cmd: judge_cmd,
            guest_elf: PathBuf::from(&guest_elf),
            // Mock prover: instantaneous. Real prover: the nano
            // envelope measured 140 s / 24 GB (docs/DESIGN.md) — the
            // bound and timeout leave headroom for slower hosts.
            max_vm_cycles: 10_000_000,
            timeout: std::time::Duration::from_secs(900),
            receipt_dir: None,
        }),
        pool: Some(2),
        round1_size: None,
        round1_ids: Some(vec!["wA".into(), "wB".into()]),
        tls: None,
        bound_tx: Some(bound_tx),
        max_jobs: Some(1),
        job_tx: Some(job_tx),
    };
    std::thread::spawn(move || net::serve(cfg).expect("serve"));
    let bound = bound_rx.recv_timeout(std::time::Duration::from_secs(15)).unwrap();

    queue_desc(&jobs_dir, "job1", &desc);

    let identities = root.join("identities");
    std::fs::create_dir_all(&identities).unwrap();
    // wA honest, wB corrupts its journal: 1v1 is no majority, the
    // reserves are empty, so the zk judge arbitrates.
    let spawns: Vec<(&str, bool)> = vec![("wA", false), ("wB", true)];
    let mut handles = Vec::new();
    for (id, corrupt) in spawns {
        let server = bound.to_string();
        let identity = identities.join(format!("{id}.key"));
        let store_dir = root.join(format!("worker-store-{id}"));
        handles.push(std::thread::spawn(move || {
            run_daemon(&DaemonConfig {
                server,
                worker_id: id.into(),
                identity_path: Some(identity),
                store_dir,
                listen_port: None,
                tls: None,
                corrupt,
                corrupt_byte: None,
                extra_submits: 0,
                receipt_file: None,
            })
        }));
    }

    let job1 = wait_job(&job_rx);
    let coordinator::Decision::Accept { hash, agreed, zk, .. } = &job1.decision else {
        panic!("zk judge should accept the job, got {:?}", job1.decision);
    };
    assert!(*zk, "acceptance must be receipt-backed");
    // The receipt vindicates the honest responder by digest...
    assert_eq!(agreed, &vec!["wA".to_string()], "honest worker paid, liar not: {agreed:?}");
    // ...and the hash is the honest worker's own commitment.
    let honest = job1.results.iter().find(|r| r.worker_id == "wA").unwrap();
    assert_eq!(hash, &honest.result_hash, "judge digest == honest digest");
    let ledger = std::fs::read_to_string(root.join("ledger.json")).unwrap();
    assert!(ledger.contains("\"wA\": 10"), "honest rewarded: {ledger}");
    assert!(ledger.contains("\"wB\": -100"), "liar slashed: {ledger}");
    for h in handles {
        h.join().unwrap().unwrap();
    }
}
