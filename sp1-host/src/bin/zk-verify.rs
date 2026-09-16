//! Standalone zk receipt verifier (no prover): invoked by the
//! coordinator as an external oracle, or by a CLIENT verifying a
//! receipt offline (jobkit evidence verify). Protocol:
//!   argv: <guest-elf> <receipt-file> [--v2] [<binding-hex-1> <2> <3>]
//!     --v2: the receipt is over a V2 (SP1-native) job — public values
//!       are [input_id, output]; the binding check (when the ids are
//!       given) compares the input id only, since the elf is bound by
//!       the verifying key and the manifest is not executed.
//!     legacy: public values are [binding(3x32), status, instructions,
//!       chain, output]; all three binding ids are checked.
//!     with the binding ids: the receipt must attest THAT exact job;
//!     without them: pure proof verification — the committed values
//!     are reported, but are not pinned to a specific job.
//!   stdout: one JSON verdict:
//!     {"ok":true,"status":0,"instructions":N,"chain":["hex"],"output_hex":"hex"}
//!     {"ok":false,"error":"..."}
//! The verifying key is re-derived from the committed guest ELF, so a
//! receipt only verifies against the exact emulator binary it claims.

use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
use sp1_sdk::{ProvingKey, SP1ProofWithPublicValues};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let v2 = args.iter().any(|a| a == "--v2");
    let rest: Vec<&String> = args.iter().filter(|a| *a != "--v2").collect();
    let binding = match rest.as_slice() {
        [g, r, b1, b2, b3] => Some([b1.to_string(), b2.to_string(), b3.to_string()]),
        [g, r] => None,
        _ => {
            println!("{{\"ok\":false,\"error\":\"usage: zk-verify <guest-elf> <receipt-file> [--v2] [<binding-hex-1> <2> <3>]\"}}");
            std::process::exit(1);
        }
    };
    let (guest_elf, receipt_file) = match rest.as_slice() {
        [g, r, ..] => (g.to_string(), r.to_string()),
        _ => unreachable!(),
    };
    match run(&guest_elf, &receipt_file, binding.as_ref(), v2) {
        Ok(v) => println!("{v}"),
        Err(e) => {
            println!("{{\"ok\":false,\"error\":{}}}", serde_json::to_string(&e).unwrap());
            std::process::exit(1);
        }
    }
}

fn run(
    guest_elf: &str,
    receipt_file: &str,
    binding_hex: Option<&[String; 3]>,
    v2: bool,
) -> Result<String, String> {
    let expected_binding = match binding_hex {
        Some(ids) => {
            let decode = |s: &str| -> Result<[u8; 32], String> {
                let bytes = jobfmt::from_hex(s, 32).map_err(|e| format!("binding hex: {e}"))?;
                Ok(bytes.try_into().map_err(|_| "binding hex length".to_string())?)
            };
            Some([
                decode(&ids[0])?,
                decode(&ids[1])?,
                decode(&ids[2])?,
            ])
        }
        None => None,
    };

    let mut proof = SP1ProofWithPublicValues::load(receipt_file)
        .map_err(|e| format!("receipt load: {e}"))?;
    let guest_bytes = std::fs::read(guest_elf).map_err(|e| format!("guest ELF: {e}"))?;
    let prover = ProverClient::builder().cpu().build();
    let pk = prover
        .setup(Elf::Dynamic(guest_bytes.into()))
        .map_err(|e| format!("guest setup: {e}"))?;

    let (status, instructions, output, chain) = if v2 {
        let input_id: [u8; 32] = proof.public_values.read();
        if let Some(expected) = &expected_binding {
            // expected[2] is the input content id (decoded above).
            if input_id != expected[2] {
                return Err("receipt is not for this job's input (binding mismatch)".into());
            }
        }
        // V2 journal basis: output only (jobfmt::V2_JOURNAL_COUNT).
        (
            0u32,
            jobfmt::V2_JOURNAL_COUNT,
            {
                let output: Vec<u8> = proof.public_values.read();
                output
            },
            Vec::<[u8; 32]>::new(),
        )
    } else {
        let binding: [[u8; 32]; 3] = proof.public_values.read();
        if let Some(expected) = &expected_binding {
            if binding != *expected {
                return Err("receipt is not for this job's (manifest, elf, input)".into());
            }
        }
        let status: u32 = proof.public_values.read();
        let instructions: u64 = proof.public_values.read();
        let chain: Vec<[u8; 32]> = proof.public_values.read();
        let output: Vec<u8> = proof.public_values.read();
        (status, instructions, output, chain)
    };

    prover
        .verify(&proof, &pk.verifying_key(), None)
        .map_err(|e| format!("receipt verification: {e}"))?;

    let chain_hex: Vec<String> = chain.iter().map(|h| hex(h)).collect();
    Ok(format!(
        "{{\"ok\":true,\"status\":{status},\"instructions\":{instructions},\"chain\":{},\"output_hex\":{}}}",
        serde_json::to_string(&chain_hex).unwrap(),
        serde_json::to_string(&hex(&output)).unwrap(),
    ))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

