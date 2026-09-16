use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use std::path::PathBuf;

#[derive(Parser)]
enum Cmd {
    /// Execute a job locally and emit the result: final hash, chunk
    /// hash chain, output. A worker is a pure function of
    /// (job, input) -> WorkerResult; nothing about the host machine
    /// leaks into the output, which is the property the differential
    /// test enforces.
    Run(RunArgs),
    /// Run as a daemon: connect to a coordinator over TCP,
    /// authenticate with an Ed25519 nonce signature, fetch job blobs
    /// over the wire (content-verified), execute, submit signed
    /// results — until the session ends.
    Daemon(DaemonArgs),
}

#[derive(Parser)]
struct RunArgs {
    job_dir: PathBuf,
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long, default_value = "w0")]
    id: String,
    /// Simulate a malicious worker: flip the last byte of the result
    /// and chunk hashes. Used to exercise escalation end to end.
    #[arg(long)]
    corrupt: bool,
    /// Write per-chunk machine-state snapshots here (dispute fast
    /// path). Snapshot trust comes from the hash check, not the file.
    #[arg(long)]
    snapshots: Option<PathBuf>,
    /// Enable the QEMU-compatible syscall environment (write/exit) —
    /// conformance-differential mode; jobs that halt via ebreak don't
    /// need it.
    #[arg(long)]
    syscalls: bool,
    /// Ed25519 identity file (raw 32-byte seed). Created on first use.
    /// When set, the result is signed, binding the identity to the
    /// claimed result hash.
    #[arg(long)]
    identity: Option<PathBuf>,
}

#[derive(Parser)]
struct DaemonArgs {
    /// Coordinator address, e.g. 192.168.1.10:7777.
    #[arg(long)]
    server: String,
    #[arg(long, default_value = "w0")]
    id: String,
    /// Ed25519 identity file (raw 32-byte seed); created on first use.
    /// REQUIRED in practice — unsigned workers are refused by the
    /// coordinator's default policy.
    #[arg(long)]
    identity: PathBuf,
    /// Local content store: fetched blobs are hash-verified and cached
    /// here, deduplicating across jobs.
    #[arg(long, default_value = "worker-store")]
    store_dir: PathBuf,
    /// Test hook: corrupt the result like a lying worker.
    #[arg(long)]
    corrupt: bool,
    /// With --corrupt: the journal byte index to bump (defaults to
    /// the last byte) — any bump guarantees divergence.
    #[arg(long)]
    corrupt_byte: Option<u8>,
    /// zk tier: submit this SP1 receipt (bincode) as a ReceiptClaim
    /// when a matching job is assigned, instead of executing. The
    /// receipt is produced by a prover; the daemon carries it signed.
    #[arg(long)]
    receipt_file: Option<PathBuf>,
    /// Serve blobs to peers on this port (the p2p fetch path).
    #[arg(long)]
    listen_port: Option<u16>,
    /// Run the session over TLS with this coordinator certificate
    /// (raw DER, copied from the coordinator's store dir). The
    /// certificate's fingerprint is pinned: no other server will be
    /// accepted.
    #[arg(long)]
    server_cert: Option<PathBuf>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn load_or_create_identity(path: &std::path::Path) -> SigningKey {
    if let Ok(seed) = std::fs::read(path) {
        if seed.len() == 32 {
            let arr: [u8; 32] = seed.try_into().unwrap();
            return SigningKey::from_bytes(&arr);
        }
    }
    let mut seed = [0u8; 32];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut seed);
    std::fs::write(path, seed).expect("write identity file");
    SigningKey::from_bytes(&seed)
}

fn main() {
    match Cmd::parse() {
        Cmd::Run(a) => cmd_run(a),
        Cmd::Daemon(a) => {
            let tls = a.server_cert.map(|p| {
                std::fs::read(&p)
                    .expect("read coordinator certificate")
            });
            let cfg = worker::daemon::DaemonConfig {
                server: a.server,
                worker_id: a.id,
                identity_path: Some(a.identity),
                store_dir: a.store_dir,
                listen_port: a.listen_port,
                tls,
                corrupt: a.corrupt,
                corrupt_byte: a.corrupt_byte,
                extra_submits: 0,
                receipt_file: a.receipt_file,
            };
            if let Err(e) = worker::daemon::run_daemon(&cfg) {
                eprintln!("daemon error: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn cmd_run(args: RunArgs) {
    let job = jobfmt::load_dir(&args.job_dir).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(2);
    });

    let image = rvcore::elf::parse(&job.elf).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(2);
    });
    let mut mem = rvcore::Mem::new();
    rvcore::elf::load(&mut mem, &image).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(2);
    });

    let cfg = rvcore::Config {
        chunk_size: job.manifest.chunk_size,
        max_instructions: job.manifest.max_instructions,
        syscalls: args.syscalls,
        tohost_addr: None,
        snapshot_dir: args.snapshots.clone(),
    };
    let outcome = rvcore::interp::run(&mut mem, image.entry, &job.input, &cfg);

    let status = match &outcome.status {
        rvcore::ExitStatus::Halted | rvcore::ExitStatus::Tohost(_) => "halted",
        rvcore::ExitStatus::InstructionLimit => "instruction_limit",
        rvcore::ExitStatus::Trapped(_) => "trap",
    };
    let trap = match outcome.status {
        rvcore::ExitStatus::Trapped(t) => Some(format!("{t:?}")),
        _ => None,
    };

    let mut chunk_hashes: Vec<String> =
        outcome.chunk_hashes.iter().map(|h| hex(h)).collect();
    let mut result_hash = chunk_hashes.last().cloned().unwrap_or_else(|| hex(&rvcore::GENESIS));

    if args.corrupt && !chunk_hashes.is_empty() {
        // Corrupt the execution identity while keeping the same shape,
        // like a worker that "computed" something else (or nothing).
        flip_last(&mut result_hash);
        flip_last(chunk_hashes.last_mut().unwrap());
    }

    // Identity: sign the raw result-hash bytes with the worker's key.
    let (pubkey_hex, sig_hex) = match &args.identity {
        Some(path) => {
            let key = load_or_create_identity(path);
            let msg = unhex(&result_hash).expect("hash is hex");
            let sig = key.sign(&msg);
            (Some(hex(&key.verifying_key().to_bytes())), Some(hex(&sig.to_bytes())))
        }
        None => (None, None),
    };

    let result = jobfmt::WorkerResult {
        worker_id: args.id,
        job_id: job.manifest.id,
        status: status.to_string(),
        instructions: outcome.instructions,
        result_hash,
        chunk_hashes,
        output_hex: outcome.output.as_ref().map(|o| hex(o)),
        trap,
        pubkey_hex,
        sig_hex,
    };

    let json = serde_json::to_string_pretty(&result).unwrap();
    match args.out {
        Some(p) => std::fs::write(p, json).expect("write result"),
        None => println!("{json}"),
    }
}

fn flip_last(s: &mut str) {
    let bytes = unsafe { s.as_bytes_mut() };
    let n = bytes.len();
    bytes[n - 1] = if bytes[n - 1] == b'0' { b'1' } else { b'0' };
}
