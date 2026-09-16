//! Standalone zk dispute judge: re-executes a disputed job inside the
//! zkVM and produces a cryptographic receipt instead of a bare replay.
//! Invoked by the coordinator as an external process (the SDK does not
//! build everywhere, and proving needs a memory envelope the
//! coordinator itself must not carry). Protocol:
//!   argv: <job-dir> <max-vm-cycles> <guest-elf> [receipt-out]
//!     job-dir: materialized job (job.json, program.elf, input.bin)
//!     max-vm-cycles: fail fast BEFORE proving when the execution's VM
//!       cycle count exceeds this — an emulator-in-a-zkVM multiplies
//!       job instructions ~300x, so the bound is what keeps a hostile
//!       or oversized job from burning unprovable compute.
//!   stdout: one JSON verdict:
//!     {"ok":true,"status":0,"instructions":N,"output_hex":"..",
//!      "vm_cycles":N,"proving_secs":S,"binding":["h1","h2","h3"],
//!      "receipt_saved":"path"|null}
//!     {"ok":false,"error":"...","vm_cycles":N|null}
//! SP1_PROVER=mock switches the prover to SP1's mock (fast, no real
//! cryptography) — used by CI to exercise the full judge state machine
//! without a proving-sized memory envelope.

use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
use sp1_sdk::ProvingKey as _;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (job_dir, max_cycles, guest_elf, receipt_out) = match args.as_slice() {
        [j, m, g] => (j.clone(), m.clone(), g.clone(), None),
        [j, m, g, r] => (j.clone(), m.clone(), g.clone(), Some(r.clone())),
        _ => {
            println!(
                "{{\"ok\":false,\"error\":\"usage: zk-judge <job-dir> <max-vm-cycles> <guest-elf> [receipt-out]\"}}"
            );
            std::process::exit(1);
        }
    };
    match run(&job_dir, &max_cycles, &guest_elf, receipt_out.as_deref()) {
        Ok(v) => println!("{v}"),
        Err(e) => {
            println!("{{\"ok\":false,\"error\":{}}}", serde_json::to_string(&e).unwrap());
            std::process::exit(1);
        }
    }
}

struct Job {
    manifest_bytes: Vec<u8>,
    elf: Vec<u8>,
    input: Vec<u8>,
    chunk_size: u64,
    max_instructions: u64,
}

fn load_job(dir: &str) -> Result<Job, String> {
    let manifest_bytes =
        std::fs::read(format!("{dir}/job.json")).map_err(|e| format!("manifest: {e}"))?;
    let manifest: jobfmt::JobManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|e| format!("manifest parse: {e}"))?;
    let elf = std::fs::read(format!("{dir}/{}", manifest.elf))
        .map_err(|e| format!("job elf: {e}"))?;
    let input = std::fs::read(format!("{dir}/{}", manifest.input))
        .map_err(|e| format!("job input: {e}"))?;
    Ok(Job { manifest_bytes, elf, input, chunk_size: manifest.chunk_size, max_instructions: manifest.max_instructions })
}

/// Read back the guest's committed sequence — the same types in the
/// same order the emu guest commits them. The reads ADVANCE the
/// buffer cursor, so this is the one and only pass over the values.
fn read_committed(
    pv: &mut sp1_sdk::SP1PublicValues,
) -> ([[u8; 32]; 3], u32, u64, Vec<[u8; 32]>, Vec<u8>) {
    let binding: [[u8; 32]; 3] = pv.read();
    let status: u32 = pv.read();
    let instructions: u64 = pv.read();
    let chain: Vec<[u8; 32]> = pv.read();
    let output: Vec<u8> = pv.read();
    (binding, status, instructions, chain, output)
}

fn run(
    job_dir: &str,
    max_cycles: &str,
    guest_elf_path: &str,
    receipt_out: Option<&str>,
) -> Result<String, String> {
    let max_cycles: u64 = max_cycles.parse().map_err(|_| "max-vm-cycles parse")?;
    let job = load_job(job_dir)?;
    let guest_bytes =
        std::fs::read(guest_elf_path).map_err(|e| format!("guest ELF: {e}"))?;

    let binding: [[u8; 32]; 3] = [
        blake3::hash(&job.manifest_bytes).into(),
        blake3::hash(&job.elf).into(),
        blake3::hash(&job.input).into(),
    ];
    let binding_hex: Vec<String> = binding.iter().map(|h| hex(h)).collect();

    let prover = ProverClient::from_env();
    let elf = Elf::Dynamic(guest_bytes.into());

    // 1. Cheap pass: execute only. This yields the VM cycle count the
    //    proving decision needs, plus the committed result.
    let mut stdin = SP1Stdin::new();
    stdin.write(&job.manifest_bytes);
    stdin.write(&job.elf);
    stdin.write(&job.input);
    let (mut pv, report) = prover
        .execute(elf.clone(), stdin)
        .run()
        .map_err(|e| format!("execute: {e}"))?;
    let vm_cycles = report.total_instruction_count();
    if vm_cycles > max_cycles {
        return Err(format!(
            "vm cycle bound exceeded: {vm_cycles} > {max_cycles} — refusing to prove an unbounded trace"
        ));
    }
    let (committed_binding, status, instructions, _chain, output) = read_committed(&mut pv);
    if committed_binding != binding {
        return Err("guest binding does not match this job's (manifest, elf, input)".into());
    }

    // 2. Independent cross-check against the locally linked rvcore: the
    //    guest embeds rvcore at ITS build time, so this catches a guest
    //    artifact that drifted from the judge's pinned semantics.
    let image = rvcore::elf::parse(&job.elf).map_err(|e| format!("elf parse: {e}"))?;
    let mut mem = rvcore::Mem::new();
    rvcore::elf::load(&mut mem, &image).map_err(|e| format!("elf load: {e}"))?;
    let outcome = rvcore::interp::run(
        &mut mem,
        image.entry,
        &job.input,
        &rvcore::Config {
            chunk_size: job.chunk_size,
            max_instructions: job.max_instructions,
            ..Default::default()
        },
    );
    let rv_status = match &outcome.status {
        rvcore::interp::ExitStatus::Halted | rvcore::interp::ExitStatus::Tohost(_) => 0,
        rvcore::interp::ExitStatus::InstructionLimit => 1,
        rvcore::interp::ExitStatus::Trapped(_) => 2,
    };
    let rv_output = outcome.output.unwrap_or_default();
    if rv_status != status || outcome.instructions != instructions || rv_output != output {
        return Err(format!(
            "guest and local rvcore disagree (status {status}/{rv_status}, instructions {instructions}/{}, output {} bytes/{} bytes)",
            outcome.instructions,
            output.len(),
            rv_output.len(),
        ));
    }

    // 3. The proof. Fail-fast above already bounded the trace.
    let pk = prover.setup(elf.clone()).map_err(|e| format!("setup: {e}"))?;
    let mut stdin = SP1Stdin::new();
    stdin.write(&job.manifest_bytes);
    stdin.write(&job.elf);
    stdin.write(&job.input);
    let t0 = std::time::Instant::now();
    let mut proof = prover
        .prove(&pk, stdin)
        .core()
        .run()
        .map_err(|e| format!("prove: {e}"))?;
    let proving_secs = t0.elapsed().as_secs_f64();

    prover
        .verify(&proof, &pk.verifying_key(), None)
        .map_err(|e| format!("receipt verification: {e}"))?;
    let (_, p_status, p_instructions, _, p_output) = read_committed(&mut proof.public_values);
    if (p_status, p_instructions, p_output) != (status, instructions, output.clone()) {
        return Err("proved public values differ from the executed ones".into());
    }

    let mut receipt_saved = None;
    if let Some(out) = receipt_out {
        proof.save(out).map_err(|e| format!("receipt save: {e}"))?;
        receipt_saved = Some(out.to_string());
    }

    Ok(format!(
        "{{\"ok\":true,\"status\":{status},\"instructions\":{instructions},\"output_hex\":{},\"vm_cycles\":{vm_cycles},\"proving_secs\":{proving_secs:.1},\"binding\":{},\"receipt_saved\":{}}}",
        serde_json::to_string(&hex(&output)).unwrap(),
        serde_json::to_string(&binding_hex).unwrap(),
        serde_json::to_string(&receipt_saved).unwrap(),
    ))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
