//! provework job — an SP1 guest program.
//!
//! This is your computation. It runs inside the SP1 zkVM on machines
//! nobody has to trust. The receipt proves the exact execution.
//!
//! ## How it works
//!
//! - Input arrives via `sp1_zkvm::io::read::<Vec<u8>>()` — your data.
//! - Compute your result using deterministic integer logic.
//! - Output is committed via `sp1_zkvm::io::commit::<Vec<u8>>(&output)`
//!   — this becomes the public journal that the coordinator compares
//!   between workers.
//!
//! ## Constraints (the zkVM enforces these)
//!
//! - Deterministic: same input → same journal, always.
//! - No network, no filesystem, no clock, no randomness, no floats.
//! - Integer arithmetic on bounded data.

#![no_main]
sp1_zkvm::entrypoint!(main);

fn main() {
    // Read the input bytes.
    let input: Vec<u8> = sp1_zkvm::io::read();

    // TODO: your computation here. Replace this FNV hash with your
    // actual logic — anything deterministic and integer-only.
    let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in &input {
        acc = (acc ^ b as u64).wrapping_mul(0x100_0000_01b3);
    }

    // Commit the output: the journal that the coordinator compares
    // between workers (quorum) and that the receipt attests (zk).
    let output = acc.to_le_bytes().to_vec();
    sp1_zkvm::io::commit(&output);
}
