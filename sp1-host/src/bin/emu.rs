//! Same-ELF zk tier validation: run the LOCAL rvcore on the smoke job,
//! then run the SAME emulator compiled as an SP1 guest on the SAME
//! bytes, prove the execution, and verify the receipt. The committed
//! chain, instruction count, and output must equal the local run
//! byte-for-byte. Modes:
//!   emu execute   - fast: zkVM execution without a cryptographic proof
//!   emu prove     - full receipt (slow; minutes of CPU proving)

use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
use sp1_sdk::ProvingKey;

fn job_binding(
    manifest_bytes: &[u8],
    elf_bytes: &[u8],
    input: &[u8],
) -> [[u8; 32]; 3] {
    [
        blake3::hash(manifest_bytes).into(),
        blake3::hash(elf_bytes).into(),
        blake3::hash(input).into(),
    ]
}

fn local_reference(
    manifest_bytes: &[u8],
    elf_bytes: &[u8],
    input: &[u8],
) -> (u32, u64, Vec<[u8; 32]>, Vec<u8>) {
    let manifest: jobfmt::JobManifest = serde_json::from_slice(manifest_bytes).unwrap();
    let image = rvcore::elf::parse(elf_bytes).unwrap();
    let mut mem = rvcore::Mem::new();
    rvcore::elf::load(&mut mem, &image).unwrap();
    let outcome = rvcore::interp::run(
        &mut mem,
        image.entry,
        input,
        &rvcore::interp::Config {
            chunk_size: manifest.chunk_size,
            max_instructions: manifest.max_instructions,
            ..Default::default()
        },
    );
    let status = match &outcome.status {
        rvcore::interp::ExitStatus::Halted | rvcore::interp::ExitStatus::Tohost(_) => 0,
        rvcore::interp::ExitStatus::InstructionLimit => 1,
        rvcore::interp::ExitStatus::Trapped(_) => 2,
    };
    (status, outcome.instructions, outcome.chunk_hashes.clone(), outcome.output.unwrap_or_default())
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| "execute".into());
    let job_dir = args.next().unwrap_or_else(|| "../jobs/demo-hash-smoke".into());
    assert!(
        mode == "execute" || mode == "prove" || mode == "verify",
        "mode: execute|prove|verify [job-dir] [receipt] [guest-elf]"
    );
    assert!(!mode.starts_with('-'), "mode: execute|prove [job-dir]");

    let manifest_bytes = std::fs::read(format!("{job_dir}/job.json")).expect("manifest");
    let elf_bytes = std::fs::read(format!("{job_dir}/program.elf")).expect("job elf");
    let input = std::fs::read(format!("{job_dir}/input.bin")).expect("job input");
    println!("job: {job_dir}");

    let (status, instructions, chain, output) =
        local_reference(&manifest_bytes, &elf_bytes, &input);
    println!(
        "local rvcore: status {status}, {} instructions, {} chunk(s), result {}",
        instructions,
        chain.len(),
        hex(&chain.last().copied().unwrap_or_default()),
    );

    if mode == "verify" {
        // CI mode: no proving. Load the committed receipt, re-derive
        // the verifying key from the committed guest ELF (binding the
        // receipt to that exact binary), cryptographically verify it,
        // and require the committed values to equal the local rvcore
        // run. This is how CI checks the zk tier without a prover.
        let receipt_path = std::env::args()
            .nth(3)
            .unwrap_or_else(|| "../sp1-artifacts/nano-receipt.bin".into());
        let guest_path = std::env::args()
            .nth(4)
            .unwrap_or_else(|| "../sp1-artifacts/sp1-guest-emu.elf".into());
        let mut proof =
            sp1_sdk::SP1ProofWithPublicValues::load(&receipt_path).expect("load receipt");
        let guest_bytes = std::fs::read(&guest_path).expect("load committed guest ELF");
        let prover = ProverClient::builder().cpu().build();
        let pk = prover
            .setup(Elf::Dynamic(guest_bytes.into()))
            .expect("setup from committed guest ELF");
        // The journal opens with the job binding: BLAKE3 of each blob,
        // which ARE the content-store ids the descriptor carries.
        let binding_zk: [[u8; 32]; 3] = proof.public_values.read();
        let expected_binding = job_binding(&manifest_bytes, &elf_bytes, &input);
        assert_eq!(binding_zk, expected_binding, "receipt is not for this job's (manifest, elf, input)");
        let status_zk: u32 = proof.public_values.read();
        let instructions_zk: u64 = proof.public_values.read();
        let chain_zk: Vec<[u8; 32]> = proof.public_values.read();
        let output_zk: Vec<u8> = proof.public_values.read();
        assert_eq!(status_zk, status, "status mismatch");
        assert_eq!(instructions_zk, instructions, "instruction count mismatch");
        assert_eq!(chain_zk, chain, "chunk chain mismatch");
        assert_eq!(output_zk, output, "output mismatch");
        prover.verify(&proof, &pk.verifying_key(), None).expect("receipt verification");
        println!(
            "SP1 EMU RECEIPT VERIFY PASS: committed receipt verified against the committed guest ELF - {} produced {} ({} instruction(s))",
            job_dir,
            hex(&chain_zk.last().copied().unwrap_or_default()),
            instructions_zk,
        );
        return;
    }

    let guest_bytes = std::fs::read("../elf/sp1-guest-emu").expect("guest ELF (build sp1-guest first)");
    let elf = Elf::Dynamic(guest_bytes.into());
    let prover = ProverClient::builder().cpu().build();
    let pk = prover.setup(elf.clone()).expect("setup");

    let mut stdin = SP1Stdin::new();
    stdin.write(&manifest_bytes);
    stdin.write(&elf_bytes);
    stdin.write(&input);

    if mode == "execute" {
        let t0 = std::time::Instant::now();
        let (mut pv, report) = prover.execute(elf.clone(), stdin).run().expect("execute");
        // The VM cycle count is the meta-emulation overhead baseline:
        // rvcore instructions executed inside the zkVM cost this many
        // VM cycles, which is what a prover would have to prove.
        println!(
            "sp1 execute: {} vm cycles in {:.1}s (rvcore reported {} job instructions)",
            report.total_instruction_count(),
            t0.elapsed().as_secs_f64(),
            instructions,
        );
        let binding_zk: [[u8; 32]; 3] = pv.read();
        assert_eq!(
            binding_zk,
            job_binding(&manifest_bytes, &elf_bytes, &input),
            "receipt is not for this job's (manifest, elf, input)"
        );
        let status_zk: u32 = pv.read();
        let instructions_zk: u64 = pv.read();
        let chain_zk: Vec<[u8; 32]> = pv.read();
        let output_zk: Vec<u8> = pv.read();
        assert_eq!(status_zk, status, "status mismatch");
        assert_eq!(instructions_zk, instructions, "instruction count mismatch");
        assert_eq!(chain_zk, chain, "chunk chain mismatch");
        assert_eq!(output_zk, output, "output mismatch");
        println!("SP1 EMU EXECUTE PASS: same-ELF execution matches local rvcore ({} chunk(s))", chain_zk.len());
        return;
    }

    // SP1 6.8's CPU prover errors on multi-shard programs ("artifact not
    // found") in BOTH compressed and core modes, so receipts beyond one
    // shard await a newer SP1 or the GPU prover. Core is tried first
    // here as the more permissive path.
    let t0 = std::time::Instant::now();
    let mut proof = prover.prove(&pk, stdin).core().run().expect("proving");
    let proving_secs = t0.elapsed().as_secs_f64();
    let binding_zk: [[u8; 32]; 3] = proof.public_values.read();
    assert_eq!(
        binding_zk,
        job_binding(&manifest_bytes, &elf_bytes, &input),
        "receipt is not for this job's (manifest, elf, input)"
    );
    let status_zk: u32 = proof.public_values.read();
    let instructions_zk: u64 = proof.public_values.read();
    let chain_zk: Vec<[u8; 32]> = proof.public_values.read();
    let output_zk: Vec<u8> = proof.public_values.read();
    assert_eq!(status_zk, status, "status mismatch");
    assert_eq!(instructions_zk, instructions, "instruction count mismatch");
    assert_eq!(chain_zk, chain, "chunk chain mismatch");
    assert_eq!(output_zk, output, "output mismatch");

    prover
        .verify(&proof, &pk.verifying_key(), None)
        .expect("receipt verification");
    // Persist the receipt + the guest ELF so CI can re-verify this
    // proof forever without a prover (sp1-artifacts/, committed).
    std::fs::create_dir_all("../sp1-artifacts").ok();
    proof.save("../sp1-artifacts/nano-receipt.bin").expect("save receipt");
    std::fs::copy("../elf/sp1-guest-emu", "../sp1-artifacts/sp1-guest-emu.elf")
        .expect("copy guest ELF");
    println!(
        "SP1 EMU PROVE PASS: verified receipt in {:.1}s - rvcore on the actual job ELF produced {} ({} instruction(s), {} chunk(s))",
        proving_secs,
        hex(&chain_zk.last().copied().unwrap_or_default()),
        instructions_zk,
        chain_zk.len(),
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
