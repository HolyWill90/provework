use clap::Parser;
use coordinator::{decide, dispute, ledger::Ledger, net, optimistic, slashing, verify_signature, Decision};
use jobfmt::WorkerResult;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The coordinator runs as the job client: it matches jobs to workers,
/// holds escrow, compares results, escalates on mismatch, and referees
/// disputes. Workers communicate only through their result JSON — the
/// protocol surface a real network would keep.
#[derive(Parser)]
enum Cmd {
    /// Quorum run: N workers, escalation, slashing, optional ledger.
    Run(RunArgs),
    /// Referee a dispute between two committed chunk-hash chains.
    Dispute(DisputeArgs),
    /// Optimistic acceptance demo: accept after a challenge window,
    /// optionally challenged in time.
    Optimistic(OptimisticArgs),
    /// Publish a job directory into a content store: blobs by hash,
    /// descriptor as the torrent-file analog.
    Publish(PublishArgs),
    /// Reconstruct a job from a descriptor + store, hash-verified.
    Fetch(FetchArgs),
    /// Re-hash every blob in a store; first mismatch is an error.
    Verify(VerifyArgs),
    /// Run as the network coordinator: accept authenticated worker
    /// connections, dispatch the job as content-store blobs over TCP,
    /// collect signed results, decide with quorum/escalation.
    Serve(ServeArgs),
}

#[derive(Parser)]
struct RunArgs {
    job_dir: PathBuf,
    #[arg(long)]
    worker: PathBuf,
    #[arg(long)]
    out: Option<PathBuf>,
    /// Corrupt worker #2, to exercise escalation and slashing.
    #[arg(long)]
    corrupt: bool,
    /// Persist a bond ledger (balances accumulate across runs).
    #[arg(long)]
    ledger: Option<PathBuf>,
    /// Workers write per-chunk snapshots (dispute fast path).
    #[arg(long)]
    snapshots: bool,
    /// Workers sign results with per-worker Ed25519 identities
    /// (created on first use under identities/).
    #[arg(long)]
    identities: bool,
}

#[derive(Parser)]
struct DisputeArgs {
    job_dir: PathBuf,
    #[arg(long)]
    a: PathBuf,
    #[arg(long)]
    b: PathBuf,
    /// Either worker's snapshot directory for the one-chunk fast path.
    #[arg(long)]
    snapshots: Option<PathBuf>,
}

#[derive(Parser)]
struct OptimisticArgs {
    job_dir: PathBuf,
    #[arg(long)]
    worker: PathBuf,
    /// Challenge window in milliseconds (simulated clock: the demo
    /// sleeps).
    #[arg(long, default_value_t = 0)]
    window_ms: u64,
    /// Issue a bonded challenge inside the window.
    #[arg(long)]
    challenge: bool,
}

#[derive(Parser)]
struct PublishArgs {
    job_dir: PathBuf,
    #[arg(long)]
    store: PathBuf,
    /// Where to write the job descriptor JSON (the torrent-file analog).
    #[arg(long)]
    out: PathBuf,
}

#[derive(Parser)]
struct FetchArgs {
    #[arg(long)]
    desc: PathBuf,
    #[arg(long)]
    store: PathBuf,
    /// Directory to materialize the job into.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Parser)]
struct VerifyArgs {
    #[arg(long)]
    store: PathBuf,
}

fn cmd_publish(args: PublishArgs) {
    let store = contentstore::Store::open(&args.store).expect("open store");
    let desc = contentstore::publish(&args.job_dir, &store).expect("publish");
    let desc_id = contentstore::descriptor_id(&desc).expect("descriptor id");
    std::fs::write(&args.out, serde_json::to_vec_pretty(&desc).unwrap()).expect("write descriptor");
    println!(
        "published job {} — descriptor {} ({} blobs)",
        desc.job_id,
        desc_id.to_hex(),
        3
    );
}

fn cmd_fetch(args: FetchArgs) {
    let store = contentstore::Store::open(&args.store).expect("open store");
    let desc: contentstore::JobDescriptor =
        serde_json::from_slice(&std::fs::read(&args.desc).expect("read descriptor")).expect("parse descriptor");
    contentstore::materialize(&desc, &store, &args.out).expect("materialize");
    println!(
        "materialized job {} into {} (all blobs hash-verified)",
        desc.job_id,
        args.out.display()
    );
}

fn cmd_verify(args: VerifyArgs) {
    let store = contentstore::Store::open(&args.store).expect("open store");
    let count = store.verify_all().expect("verify");
    println!("store verified: {} blobs, all hashes match their content", count);
}

#[derive(Parser)]
struct ServeArgs {
    /// Watched directory for `*.desc.json` job descriptors
    /// (produce with `coordinator publish --out ...`). A filename
    /// `name@w1,w2.desc.json` targets workers w1 and w2.
    #[arg(long)]
    jobs_dir: PathBuf,
    /// Bind address for worker connections.
    #[arg(long, default_value = "0.0.0.0:7777")]
    bind: String,
    /// Expected pool size (display + open-pool option).
    #[arg(long, default_value_t = 5)]
    pool: usize,
    /// Per-job deadline in seconds.
    #[arg(long, default_value_t = 120)]
    per_job_deadline_secs: u64,
    /// Stop after this many jobs (default: run until killed).
    #[arg(long)]
    max_jobs: Option<usize>,
    /// Round-1 sample size for untargeted jobs: pick this many
    /// workers at random, hold the rest as escalation reserves.
    /// Default: all authenticated workers.
    #[arg(long)]
    sample_size: Option<usize>,
    /// Deterministic round-1 membership by worker id (comma-separated),
    /// overriding --sample-size.
    #[arg(long)]
    round1_ids: Option<String>,
    /// Admission proof-of-work difficulty (leading zero bits). Every
    /// connection must mine this before authentication, so a slashed
    /// or banned identity pays to return. 0 disables (default 20,
    /// roughly a tenth of a second of hashing per connection).
    #[arg(long, default_value_t = 20)]
    identity_pow_bits: u32,
    /// zk tier: the external receipt-verifier binary (built from
    /// sp1-host). When set together with --zk-guest-elf, authenticated
    /// workers may submit SP1 receipt claims for immediate acceptance.
    #[arg(long)]
    zk_verify_cmd: Option<String>,
    /// zk tier: the committed guest ELF the verifier re-derives the
    /// verifying key from (sp1-artifacts/sp1-guest-emu.elf).
    #[arg(long)]
    zk_guest_elf: Option<PathBuf>,
    /// Directory where each finished job's full outcome (decision,
    /// results, ledger deltas) is persisted as {job_id}.json — the raw
    /// material for evidence bundles. Required for `jobkit evidence`.
    #[arg(long)]
    results_dir: Option<PathBuf>,
    /// Accept job descriptors over the wire from authenticated
    /// submitters (enabled by default; disable for invite-only fleets).
    #[arg(long, default_value_t = true)]
    accept_submissions: bool,
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    ledger: Option<PathBuf>,
    /// Run worker connections over TLS: generates a self-signed
    /// certificate into the store dir on first run and prints its
    /// fingerprint. Workers verify the fingerprint via --server-cert.
    #[arg(long)]
    tls: bool,
}

fn cmd_serve(args: ServeArgs) {
    let bind: std::net::SocketAddr = args.bind.parse().expect("parse bind address");
    let args_tls = if args.tls {
        let cert_path = args.store.join("coordinator-cert.der");
        let key_path = args.store.join("coordinator-key.der");
        let (cert, key) = if cert_path.exists() && key_path.exists() {
            (
                std::fs::read(&cert_path).expect("read cert"),
                std::fs::read(&key_path).expect("read key"),
            )
        } else {
            let (cert, key) = wire::tls::generate_self_signed().expect("generate cert");
            std::fs::write(&cert_path, cert.as_ref()).expect("write cert");
            std::fs::write(&key_path, key.secret_der()).expect("write key");
            (cert.as_ref().to_vec(), key.secret_der().to_vec())
        };
        let fp = wire::tls::fingerprint_of_file(&cert_path).expect("fingerprint");
        println!("TLS enabled — coordinator cert fingerprint (blake3): {fp}");
        println!("copy {} to workers for --server-cert", cert_path.display());
        Some((cert, key))
    } else {
        None
    };
    let (job_tx, job_rx) = std::sync::mpsc::channel();
    let cfg = net::ServeConfig {
        bind,
        jobs_dir: args.jobs_dir.clone(),
        store_dir: args.store,
        per_job_deadline: std::time::Duration::from_secs(args.per_job_deadline_secs),
        ledger: args.ledger,
        require_identity: true,
        identity_pow_bits: args.identity_pow_bits,
        accept_submissions: args.accept_submissions,
        results_dir: args.results_dir.clone(),
        zk: match (&args.zk_verify_cmd, &args.zk_guest_elf) {
            (Some(cmd), Some(elf)) => Some(net::ZkVerify {
                cmd: cmd.clone(),
                guest_elf: elf.clone(),
            }),
            _ => None,
        },
        pool: Some(args.pool),
        round1_size: args.sample_size,
        round1_ids: args
            .round1_ids
            .map(|s| s.split(',').map(|x| x.trim().to_string()).collect()),
        tls: args_tls,
        bound_tx: None,
        max_jobs: args.max_jobs,
        job_tx: Some(job_tx),
    };
    let handle = std::thread::spawn(move || net::serve(cfg));

    // Print each finished job as it lands.
    let mut seen = 0usize;
    while let Ok(outcome) = job_rx.recv() {
        seen += 1;
        println!("--- job {}: {} results", outcome.job_id, outcome.results.len());
        for r in &outcome.results {
            println!(
                "  {}: {} {} insts, result {}",
                r.worker_id,
                r.status,
                r.instructions,
                &r.result_hash[..16.min(r.result_hash.len())],
            );
        }
        if seen == args.max_jobs.unwrap_or(usize::MAX) {
            break; // server exits on its own; stop printing
        }
    }
    let served = handle.join().expect("serve thread");
    let served = match served {
        Ok(o) => o,
        Err(e) => {
            eprintln!("serve failed: {e}");
            std::process::exit(1);
        }
    };
    for job in &served.jobs {
        match &job.decision {
            Decision::Accept { hash, agreed, .. } => {
                println!(
                    "JOB {}: ACCEPT — {} agreed on {}",
                    job.job_id,
                    agreed.join(","),
                    &hash[..16]
                );
            }
            Decision::Reject { reason } => println!("JOB {}: REJECT — {reason}", job.job_id),
            other => println!("JOB {}: {other:?}", job.job_id),
        }
    }
}

fn load_result(path: &Path) -> WorkerResult {
    let json = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&json).expect("parse worker result")
}

fn run_worker(worker: &Path, job_dir: &Path, id: &str, extra: &[String]) -> WorkerResult {
    let out = std::env::temp_dir().join(format!("p2pc-{id}.json"));
    let mut cmd = Command::new(worker);
    cmd.arg("run").arg(job_dir).arg("--out").arg(&out).arg("--id").arg(id);
    for a in extra {
        cmd.arg(a);
    }
    let st = cmd.status().expect("spawn worker");
    assert!(st.success(), "worker {id} exited {st}");
    load_result(&out)
}

fn cmd_run(args: RunArgs) {
    let mut pool: Vec<WorkerResult> = Vec::new();
    let mut spawn_extra: Vec<Vec<String>> = vec![vec![], vec![], vec![]];
    if args.corrupt {
        spawn_extra[1].push("--corrupt".into());
    }
    if args.snapshots {
        for (i, extra) in spawn_extra.iter_mut().enumerate() {
            extra.push("--snapshots".into());
            extra.push(format!("snaps-w{}", i + 1));
        }
    }
    if args.identities {
        std::fs::create_dir_all("identities").ok();
        for (i, extra) in spawn_extra.iter_mut().enumerate() {
            extra.push("--identity".into());
            extra.push(format!("identities/w{}.key", i + 1));
        }
    }

    for (i, extra) in spawn_extra.iter().enumerate() {
        let id = format!("w{}", i + 1);
        let r = run_worker(&args.worker, &args.job_dir, &id, extra);
        if args.identities {
            match verify_signature(&r) {
                Ok(()) => println!("  signature verified: {id}"),
                Err(e) => {
                    println!("  SIGNATURE FAILURE {id}: {e}");
                    let mut bad = r;
                    bad.status = "malformed".into();
                    pool.push(bad);
                    continue;
                }
            }
        }
        pool.push(r);
    }

    println!("round 1: {} workers", pool.len());
    let mut decision = decide(&pool, if pool.len() > 3 { 5 } else { 3 });
    if matches!(decision, Decision::Escalate) {
        println!("round 1 inconclusive -> escalating quorum to 5");
        for i in 4..=5 {
            let id = format!("w{i}");
            pool.push(run_worker(&args.worker, &args.job_dir, &id, &[]));
        }
        decision = decide(&pool, if pool.len() > 3 { 5 } else { 3 });
    }

    for r in &pool {
        println!(
            "  {}: {} {} insts, result {}",
            r.worker_id,
            r.status,
            r.instructions,
            &r.result_hash[..16.min(r.result_hash.len())],
        );
    }

    let (decision_str, deltas) = match &decision {
        Decision::Accept { hash, agreed, .. } => {
            println!("ACCEPT: {} agreed on {}", agreed.join(","), &hash[..16]);
            ("accept".to_string(), slashing(&decision, &pool))
        }
        Decision::Escalate => {
            println!("ESCALATE");
            ("escalate".to_string(), vec![])
        }
        Decision::Reject { reason } => {
            println!("REJECT: {reason}");
            ("reject".to_string(), slashing(&decision, &pool))
        }
    };

    let ledger_text = match &args.ledger {
        Some(path) => {
            let mut led = Ledger::load(path).expect("load ledger");
            led.apply(&pool[0].job_id, &decision_str, &deltas);
            led.save(path).expect("save ledger");
            serde_json::to_string_pretty(&led).unwrap()
        }
        None => serde_json::to_string_pretty(&serde_json::json!({
            "job_id": pool[0].job_id,
            "decision": decision_str,
            "bonds": deltas,
        }))
        .unwrap(),
    };

    match &args.out {
        Some(p) => std::fs::write(p, ledger_text).unwrap(),
        None => println!("{ledger_text}"),
    }

    if decision_str == "reject" {
        std::process::exit(1);
    }
}

fn cmd_dispute(args: DisputeArgs) {
    let job = jobfmt::load_dir(&args.job_dir).expect("load job");
    let a = load_result(&args.a);
    let b = load_result(&args.b);
    let inp = dispute::DisputeInput {
        claim: &a,
        counter: &b,
        elf: &job.elf,
        entry: rvcore::elf::parse(&job.elf).expect("parse elf").entry,
        input: &job.input,
        chunk_size: job.manifest.chunk_size,
        max_instructions: job.manifest.max_instructions,
        snapshot_dir: args.snapshots.as_deref(),
    };
    let verdict = dispute::resolve(&inp);
    println!("dispute verdict: {verdict:?}");
    match verdict {
        dispute::Verdict::ClaimHonest { .. } | dispute::Verdict::CounterHonest { .. } | dispute::Verdict::Agreement => {}
        _ => std::process::exit(1),
    }
}

fn cmd_optimistic(args: OptimisticArgs) {
    let job = jobfmt::load_dir(&args.job_dir).expect("load job");
    let prover = run_worker(&args.worker, &args.job_dir, "prover", &[]);
    let mut state = optimistic::State::Awaiting;
    println!("submitted: awaiting challenge for {} ms", args.window_ms);

    if args.challenge {
        // A bonded challenger re-executes and submits a counter-result
        // inside the window; the dispute game referees.
        let counter = run_worker(&args.worker, &args.job_dir, "challenger", &["--corrupt".into()]);
        let image = rvcore::elf::parse(&job.elf).expect("parse elf");
        let verdict = dispute::resolve(&dispute::DisputeInput {
            claim: &prover,
            counter: &counter,
            elf: &job.elf,
            entry: image.entry,
            input: &job.input,
            chunk_size: job.manifest.chunk_size,
            max_instructions: job.manifest.max_instructions,
            snapshot_dir: None,
        });
        state = optimistic::transition(&state, &optimistic::Event::Challenge(&verdict), true)
            .expect("challenge during window");
    } else {
        std::thread::sleep(std::time::Duration::from_millis(args.window_ms.max(1)));
        state = optimistic::expire(&state, &prover.result_hash).expect("expire after window");
    }

    match &state {
        optimistic::State::Accepted { hash } => {
            println!("ACCEPTED (window closed): {}", &hash[..16.min(hash.len())])
        }
        optimistic::State::Disputed { verdict } => println!("DISPUTED: {verdict}"),
        _ => unreachable!(),
    }
}

fn main() {
    match Cmd::parse() {
        Cmd::Run(a) => cmd_run(a),
        Cmd::Dispute(a) => cmd_dispute(a),
        Cmd::Optimistic(a) => cmd_optimistic(a),
        Cmd::Publish(a) => cmd_publish(a),
        Cmd::Fetch(a) => cmd_fetch(a),
        Cmd::Verify(a) => cmd_verify(a),
        Cmd::Serve(a) => cmd_serve(a),
    }
}
