//! jobkit — the product layer: everything a job owner touches.
//!
//!   jobkit new <name>        scaffold a job crate (sandbox-ready)
//!   jobkit build <dir>       compile for the sandbox + validate the ELF
//!   jobkit submit <dir>      publish + ship to a coordinator over the wire
//!   jobkit evidence          assemble / verify an auditor-ready bundle
//!
//! All subcommands are thin over the substrate crates; none of them
//! require knowing the descriptor format, the store layout, or the
//! wire protocol.

use clap::{Parser, Subcommand};
use ed25519_dalek::Signer;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "jobkit", version, about = "Verifiable serverless for deterministic Rust")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scaffold a sandbox-ready job crate.
    New { name: String },
    /// Compile the job for RISC-V and validate the ELF against the loader contract.
    Build { dir: PathBuf },
    /// Publish the job and submit it to a coordinator over the wire.
    Submit {
        dir: PathBuf,
        #[arg(long, default_value = "./p2pc-store")]
        store: PathBuf,
        #[arg(long)]
        server: String,
        /// Ed25519 identity for signing the submission (created on first use).
        #[arg(long, default_value = "submitter.key")]
        identity: PathBuf,
    },
    /// Assemble a verifier-ready evidence bundle from a finished job.
    Evidence {
        #[arg(long)]
        results: PathBuf,
        #[arg(long)]
        job_id: String,
        #[arg(long, default_value = "evidence-bundle")]
        out: PathBuf,
    },
}

fn main() {
    match Cli::parse().cmd {
        Cmd::New { name } => new_job(&name),
        Cmd::Build { dir } => build_job(&dir),
        Cmd::Submit {
            dir,
            store,
            server,
            identity,
        } => submit(&dir, &store, &server, &identity),
        Cmd::Evidence { results, job_id, out } => evidence(&results, &job_id, &out),
    }
}

// ---------- new ----------


mod scaffold;
use scaffold::*;


fn new_job(name: &str) {
    let dir = Path::new(name);
    if dir.exists() {
        eprintln!("error: {name} already exists");
        std::process::exit(1);
    }
    for sub in ["", "src", ".cargo", "abi"] {
        std::fs::create_dir_all(dir.join(sub)).expect("mkdir");
    }
    std::fs::write(
        dir.join("Cargo.toml"),
        SCAFFOLD_CARGO_TOML.replace("{{NAME}}", name),
    )
    .unwrap();
    std::fs::write(dir.join(".cargo/config.toml"), SCAFFOLD_CARGO_CONFIG).unwrap();
    std::fs::write(dir.join("link.ld"), SCAFFOLD_LINK_LD).unwrap();
    std::fs::write(
        dir.join("README.md"),
        SCAFFOLD_README.replace("{{NAME}}", name),
    )
    .unwrap();
    std::fs::write(dir.join("abi/abi.rs"), SCAFFOLD_ABI_RS).unwrap();
    std::fs::write(dir.join("abi/mod.rs"), "pub mod abi;\n").unwrap();
    std::fs::write(dir.join("src/main.rs"), SCAFFOLD_MAIN_RS).unwrap();
    // A minimal manifest so `jobkit submit` works out of the box.
    let manifest_json = scaffold::SCAFFOLD_MANIFEST
        .replace("{{NAME}}", name)
        .replace("{{ID}}", &format!("{name}-0001"));
    std::fs::write(dir.join("job.json"), manifest_json).unwrap();
    std::fs::write(dir.join("input.bin"), scaffold::SCAFFOLD_SAMPLE_INPUT).unwrap();
    println!("scaffolded job crate: {name}/");
    println!("next: write your computation in src/main.rs, put your input in input.bin, then `jobkit build {name}`");
}

// ---------- build ----------

fn build_job(dir: &Path) {
    let status = std::process::Command::new("cargo")
        .args(["build", "--release"])
        .current_dir(dir)
        .status()
        .expect("cargo build (is rustup + the riscv64imac target installed?)");
    if !status.success() {
        eprintln!("error: build failed");
        std::process::exit(1);
    }
    let elf_dir = dir.join("target/riscv64imac-unknown-none-elf/release");
    let built = std::fs::read_dir(&elf_dir)
        .expect("built ELF directory")
        .flatten()
        .find(|e| {
            e.path().extension().is_none_or(|x| x.is_empty())
                && e.metadata().is_ok_and(|m| m.len() > 4)
        })
        .map(|e| e.path())
        .unwrap_or_else(|| {
            eprintln!("error: built ELF not found in {elf_dir:?}");
            std::process::exit(1);
        });
    let bytes = std::fs::read(&built).expect("read ELF");
    match rvcore::elf::parse(&bytes) {
        Ok(image) => {
            println!(
                "ELF valid: entry {:#x}, {} segment(s), tohost {:?}",
                image.entry,
                image.segments.len(),
                image.tohost_addr
            );
        }
        Err(e) => {
            eprintln!("error: built ELF rejected by the loader contract: {e}");
            std::process::exit(1);
        }
    }
    std::fs::copy(&built, dir.join("program.elf")).expect("install program.elf");
    println!("program.elf installed into {dir:?}");
}

// ---------- submit ----------

fn load_or_create_identity(path: &Path) -> ed25519_dalek::SigningKey {
    if let Ok(seed) = std::fs::read(path) {
        let mut k = [0u8; 32];
        k.copy_from_slice(&seed[..32]);
        return ed25519_dalek::SigningKey::from_bytes(&k);
    }
    use rand_core::RngCore;
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    std::fs::write(path, seed).expect("write identity");
    key
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn submit(dir: &Path, store: &Path, server: &str, identity: &Path) {
    let manifest_bytes = std::fs::read(dir.join("job.json")).expect("job.json");
    let manifest: jobfmt::JobManifest = serde_json::from_slice(&manifest_bytes).expect("manifest");
    // Read to validate presence; the blobs themselves are served from
    // the local store (the coordinator fetches them hash-verified).
    let _elf = std::fs::read(dir.join(&manifest.elf)).expect("job ELF (run jobkit build first)");
    let _input = std::fs::read(dir.join(&manifest.input)).expect("input file");

    let key = load_or_create_identity(identity);
    println!("submitter identity: {}", hex(&key.verifying_key().to_bytes()));

    // Publish into the local store, then hand the descriptor to the
    // coordinator — every blob it fetches from us is hash-verified.
    let store = contentstore::Store::open(store).expect("store");
    let descriptor = contentstore::publish(dir, &store).expect("publish");
    let desc_id = contentstore::descriptor_id(&descriptor).unwrap();
    println!(
        "published {} — descriptor {}",
        descriptor.job_id,
        desc_id.to_hex()
    );

    let desc_id: [u8; 32] = desc_id.into();
    let msg = jobfmt::submission_message(&descriptor.job_id, &desc_id);
    let stream = std::net::TcpStream::connect(server).expect("connect coordinator");
    let mut stream: wire::BoxedStream = Box::new(stream);

    // Same admission flow as a worker: Hello, mine the PoW, prove the
    // identity, then submit.
    wire::send(
        &mut stream,
        &wire::ClientToServer::Hello {
            pubkey_hex: hex(&key.verifying_key().to_bytes()),
            worker_id: format!("submitter-{}", &hex(&key.verifying_key().to_bytes())[..8]),
            listen_port: None,
        },
    )
    .unwrap();
    let (nonce, pow_bits) =
        match wire::receive::<wire::ServerToClient>(&mut stream).expect("nonce") {
            wire::ServerToClient::Nonce { hex, pow_bits } => (hex, pow_bits),
            wire::ServerToClient::AuthFailed { reason } => {
                eprintln!("auth failed: {reason}");
                std::process::exit(1);
            }
            other => panic!("expected Nonce, got {other:?}"),
        };
    let nonce_bytes = jobfmt::from_hex(&nonce, nonce.len() / 2).expect("nonce hex");
    let counter = wire::mine_pow(&nonce_bytes, pow_bits);
    println!("admission PoW mined: {pow_bits} bits");
    wire::send(
        &mut stream,
        &wire::ClientToServer::NonceSignature {
            sig_hex: Some(hex(&key.sign(&nonce_bytes).to_bytes())),
            pow_counter: counter,
        },
    )
    .unwrap();
    // The server replies to the NonceSignature exactly once.
    match wire::receive::<wire::ServerToClient>(&mut stream).expect("auth reply") {
        wire::ServerToClient::AuthOk { worker_id } => {
            println!("authenticated as {worker_id}");
        }
        wire::ServerToClient::AuthFailed { reason } => {
            eprintln!("auth failed: {reason}");
            std::process::exit(1);
        }
        other => panic!("unexpected during auth: {other:?}"),
    }

    wire::send(
        &mut stream,
        &wire::ClientToServer::JobSubmission {
            submitter: descriptor.job_id.clone(),
            descriptor: descriptor.clone(),
            pubkey_hex: hex(&key.verifying_key().to_bytes()),
            sig_hex: hex(&key.sign(&msg).to_bytes()),
        },
    )
    .unwrap();

    loop {
        match wire::receive::<wire::ServerToClient>(&mut stream) {
            Ok(wire::ServerToClient::SubmissionAck {
                job_id, accepted, ..
            }) => {
                if accepted {
                    println!("submitted {job_id} — queued for execution");
                } else {
                    eprintln!("submission rejected");
                    std::process::exit(1);
                }
            }
            Ok(wire::ServerToClient::JobOutcome {
                job_id,
                hash,
                agreed,
                output_hex,
                zk,
                rejected_reason,
            }) => {
                println!("job {job_id} finished");
                println!("  result hash: {hash}");
                println!("  vindicated:  {}", agreed.join(", "));
                if let Some(o) = &output_hex {
                    println!("  output:      {o}");
                }
                if zk {
                    println!("  decided by:  zk receipt");
                }
                if let Some(r) = &rejected_reason {
                    println!("  note: {r}");
                }
                break;
            }
            Ok(wire::ServerToClient::ShutDown { reason }) => {
                println!("session over: {reason}");
                break;
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("connection lost while waiting for the outcome: {e}");
                std::process::exit(1);
            }
        }
    }
}

// ---------- evidence ----------

fn evidence(results: &Path, job_id: &str, out: &Path) {
    let record_path = results.join(format!("{job_id}.json"));
    std::fs::create_dir_all(out).expect("bundle dir");
    let record_path = std::fs::copy(&record_path, out.join("outcome.json"))
        .unwrap_or_else(|e| {
            panic!(
                "read {}: {e} (is --results right, and did the coordinator persist outcomes?)",
                record_path.display()
            )
        });
    println!("evidence bundle: {out:?}/outcome.json ({record_path} bytes)");
    println!("an auditor re-verifies it by re-executing the job and comparing the chain");
}
