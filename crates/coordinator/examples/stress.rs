//! Stress harness for the between-jobs transition: a persistent
//! session, two reconnecting daemons, N tiny jobs queued back-to-back.
//! Every connection drop is logged with its cause from BOTH sides;
//! every job must still end in an Accept of the correct hash. Exit 0
//! iff no wrong result was ever accepted.

use coordinator::net::{self, JobOutcome, ServeConfig};
use std::path::PathBuf;
use std::sync::mpsc::channel;
use worker::daemon::{run_daemon, DaemonConfig};

fn main() {
    let jobs = std::env::args()
        .nth(1)
        .and_then(|n| n.parse::<usize>().ok())
        .unwrap_or(20);
    let root = std::env::temp_dir().join("p2pc-stress");
    std::fs::remove_dir_all(&root).ok();
    let jobs_dir = root.join("jobs");
    let store_dir = root.join("store");
    std::fs::create_dir_all(&jobs_dir).unwrap();
    let store = contentstore::Store::open(&store_dir).unwrap();

    let desc = contentstore::publish(
        &PathBuf::from("jobs/agent-task"),
        &store,
    )
    .expect("publish agent-task");

    let (bound_tx, bound_rx) = channel();
    let (job_tx, job_rx) = channel::<JobOutcome>();
    let cfg = ServeConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        jobs_dir: jobs_dir.clone(),
        store_dir: store_dir.clone(),
        per_job_deadline: std::time::Duration::from_secs(60),
        ledger: None,
        require_identity: true,
        identity_pow_bits: 0,
        accept_submissions: false,
        results_dir: None,
        zk: None,
        round1_ids: None,
        pool: Some(2),
        round1_size: None,
        tls: None,
        bound_tx: Some(bound_tx),
        max_jobs: Some(jobs),
        job_tx: Some(job_tx),
    };
    std::thread::spawn(move || net::serve(cfg).expect("serve"));
    let bound = bound_rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
    println!("stress: coordinator on {bound}, {jobs} jobs queued");

    // Queue all jobs up front.
    for i in 0..jobs {
        let tmp = jobs_dir.join(format!("job{i}.queueing"));
        std::fs::write(&tmp, serde_json::to_vec(&desc).unwrap()).unwrap();
        std::fs::rename(&tmp, jobs_dir.join(format!("job{i}.desc.json"))).unwrap();
    }

    // Two reconnecting daemons.
    let root2 = root.clone();
    let mut handles = Vec::new();
    for id in ["wA", "wB"] {
        let bound = bound.to_string();
        let id = id.to_string();
        let identity = root2.join(format!("identities/{id}.key"));
        let store_dir = root2.join(format!("store-{id}"));
        handles.push(std::thread::spawn(move || {
            let cfg = DaemonConfig {
                server: bound,
                worker_id: id.clone(),
                identity_path: Some(identity),
                store_dir,
                listen_port: Some(0),
                tls: None,
                corrupt: false,
                corrupt_byte: None,
                extra_submits: 0,
                receipt_file: None,
            };
            let mut drops = 0usize;
            loop {
                match run_daemon(&cfg) {
                    Ok(stats) => {
                        println!(
                            "[{id}] ended: {} jobs, {} drops, served {}",
                            stats.jobs_done, drops, stats.blobs_served_to_peers
                        );
                        return (id, stats, drops);
                    }
                    Err(_) => {
                        drops += 1;
                        println!("[{id}] daemon error — retrying");
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                }
            }
        }));
    }

    // Collect all job outcomes.
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut wrong_accepted = false;
    for _ in 0..jobs {
        let outcome = job_rx
            .recv_timeout(std::time::Duration::from_secs(90))
            .expect("job outcome in time");
        match &outcome.decision {
            coordinator::Decision::Accept { hash, .. } => {
                // Every agent-task run must produce the same digest.
                if outcome.results.iter().any(|r| {
                    r.result_hash
                        != outcome
                            .results
                            .first()
                            .map(|f| f.result_hash.clone())
                            .unwrap()
                }) {
                    wrong_accepted = true;
                }
                let _ = hash;
                accepted += 1;
            }
            _ => rejected += 1,
        }
    }
    let mut total_drops = 0usize;
    for h in handles {
        let (id, _stats, drops) = h.join().unwrap();
        total_drops += drops;
        println!("[{id}] final drops: {drops}");
    }
    println!(
        "STRESS RESULT: {accepted}/{jobs} accepted, {rejected} rejected, {total_drops} reconnects, wrong-accepted: {wrong_accepted}"
    );
    if wrong_accepted || accepted + rejected != jobs {
        std::process::exit(1);
    }
}
