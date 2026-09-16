//! The V2 (SP1-native) form of the demo job: the SAME four-stream
//! FNV-1a fold as jobs/demo-hash, expressed against SP1's I/O
//! convention instead of the bare-metal ABI. Deterministic output for
//! the same input must be byte-identical to the legacy rvcore result
//! — the V2-vs-legacy differential the network tests assert.
//!
//! Journal protocol (V2): commit blake3(input) first — the input
//! binding a verifier can pin a receipt with — then the output. No
//! cycle count and no chunk chain: those were rvcore's architectural
//! bookkeeping, and SP1 cycles are a compiler/version artifact, not
//! job semantics.

#![no_main]
sp1_zkvm::entrypoint!(main);

const MUL: u64 = 0x100_0000_01b3;
const SEEDS: [u64; 4] = [
    0xcbf2_9ce4_8422_2325,
    0x9e37_79b9_7f4a_7c15,
    0x1656_67e1_9a9c_2b1d,
    0x27d4_eb2f_1656_67c5,
];

fn fold(input: &[u8]) -> [u8; 32] {
    let mut acc = SEEDS;
    for &b in input {
        let b = b as u64;
        acc[0] = (acc[0] ^ b).wrapping_mul(MUL);
        acc[1] = (acc[1] ^ b).wrapping_mul(MUL ^ 0x1);
        acc[2] = (acc[2] ^ b.rotate_left(7)).wrapping_mul(MUL);
        acc[3] = (acc[3] ^ b).wrapping_mul(MUL).rotate_left(13) ^ b;
    }
    let mut out = [0u8; 32];
    for s in 0..4 {
        out[s * 8..(s + 1) * 8].copy_from_slice(&acc[s].to_le_bytes());
    }
    out
}

fn main() {
    let input: Vec<u8> = sp1_zkvm::io::read();
    let input_id: [u8; 32] = blake3::hash(&input).into();
    sp1_zkvm::io::commit(&input_id);
    sp1_zkvm::io::commit(&fold(&input).to_vec());
}
