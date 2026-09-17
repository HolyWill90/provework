//! Job-crate scaffolding for `jobkit new`.

pub const SCAFFOLD_ABI_RS: &str = r#"//! The job ABI, inlined so this crate compiles standalone.
//! Contract with the emulator (crates/abi in provework has the docs):

pub const INPUT_LEN_ADDR: u64 = 0x1000_0000;
pub const INPUT_DATA_ADDR: u64 = 0x1000_0008;
pub const OUTPUT_LEN_ADDR: u64 = 0x2000_0000;
pub const OUTPUT_DATA_ADDR: u64 = 0x2000_0008;
pub const ELF_BASE: u64 = 0x8000_0000;
pub const STACK_TOP: u64 = 0x83F0_0000;
pub const ISA: &str = "rv64imc";
"#;

pub const SCAFFOLD_MAIN_RS: &str = r#"//! Your job: a deterministic, integer-only program. No network, no
//! filesystem, no clock, no floats. The emulator executes exactly this
//! code and the receipt proves the exact traversal.

#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;
use core::ptr;

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe { asm!("ebreak", options(noreturn)) }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        let in_len = ptr::read_volatile(crate::abi::INPUT_LEN_ADDR as *const u64) as usize;
        let in_ptr = crate::abi::INPUT_DATA_ADDR as *const u8;

        // TODO: your computation over the input bytes.
        let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
        for i in 0..in_len {
            acc = (acc ^ ptr::read_volatile(in_ptr.add(i)) as u64).wrapping_mul(0x100_0000_01b3);
        }

        // Write the result: u64 length, then bytes.
        let result = acc.to_le_bytes();
        ptr::write_volatile(crate::abi::OUTPUT_LEN_ADDR as *mut u64, result.len() as u64);
        for (i, &b) in result.iter().enumerate() {
            ptr::write_volatile((crate::abi::OUTPUT_DATA_ADDR as *mut u8).add(i), b);
        }

        asm!("ebreak", options(noreturn))
    }
}
"#;

pub const SCAFFOLD_LINK_LD: &str = r#"OUTPUT_ARCH("riscv")
ENTRY(_start)

MEMORY {
    RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 60M
}

SECTIONS {
    .text : {
        KEEP(*(.text._start))
        *(.text .text.*)
    } > RAM

    .rodata : ALIGN(8) {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    } > RAM

    .data : ALIGN(8) {
        __global_pointer$ = . + 0x800;
        *(.sdata .sdata.*)
        *(.data .data.*)
    } > RAM

    .bss (NOLOAD) : ALIGN(8) {
        *(.sbss .sbss.*)
        *(.bss .bss.*)
    } > RAM
}
"#;

pub const SCAFFOLD_ABI_CARGO_TOML: &str = r#"[package]
name = "abi"
version = "0.1.0"
edition = "2021"

[workspace]
"#;

pub const SCAFFOLD_CARGO_TOML: &str = r#"[package]
name = "{{NAME}}"
version = "0.1.0"
edition = "2021"

# Detached from any workspace: this crate targets RISC-V.
[workspace]

[dependencies]
abi = { path = "abi" }

[profile.release]
panic = "abort"
opt-level = 2
lto = true
codegen-units = 1
"#;

pub const SCAFFOLD_CARGO_CONFIG: &str = r#"[build]
target = "riscv64imac-unknown-none-elf"

[target.riscv64imac-unknown-none-elf]
# -a: no atomics → no lr/sc in the instruction stream (the emulator
# pins rv64imc). Compressed instructions are fine.
rustflags = [
    "-C", "link-arg=-Tlink.ld",
    "-C", "target-feature=-a",
]
"#;

pub const SCAFFOLD_README: &str = r#"# {{NAME}} — a provework job

A deterministic, integer-only program that runs inside the provework
sandbox on machines nobody has to trust.

## Constraints (the sandbox enforces these)

- Integer math only — no floating point, no atomics (`-a`).
- No network, no filesystem, no clock, no randomness.
- Fully deterministic: the same input always produces the same
  receipt chain on every machine.
- Input arrives at `abi::INPUT_DATA_ADDR` (length at `INPUT_LEN_ADDR`);
  write your result to `abi::OUTPUT_DATA_ADDR` (length at
  `OUTPUT_LEN_ADDR`); halt with `ebreak`.
- Runs at ~1/100th to ~1/1000th of native speed — size accordingly.

## Flow

```bash
jobkit build .        # compile for RISC-V + validate the ELF
jobkit submit . --server <coordinator:7777>   # delegate + wait for the receipt
jobkit evidence --results <results-dir> --job-id <id>   # auditor bundle
```
"#;

pub const SCAFFOLD_MANIFEST: &str = r#"{
  "schema": 1,
  "id": "{{ID}}",
  "name": "{{NAME}}",
  "isa": "rv64imc",
  "toolchain": "rustc, riscv64imac-unknown-none-elf, rust-lld, link.ld",
  "chunk_size": 1048576,
  "max_instructions": 4000000000,
  "verification_class": "quorum3",
  "elf": "program.elf",
  "input": "input.bin"
}"#;

pub const SCAFFOLD_SAMPLE_INPUT: &[u8] = b"provework sample input\n";

// ---------- V2 (SP1-native) scaffold ----------

pub const V2_GUEST_CARGO_TOML: &str = r#"[package]
name = "{{NAME}}"
version = "0.1.0"
edition = "2021"

[workspace]

[dependencies]
sp1-zkvm = "6.8.0"
blake3 = { version = "1", default-features = false }
"#;

pub const V2_GUEST_MAIN_RS: &str = r#"//! Your V2 (SP1-native) job. This program runs DIRECTLY inside the
//! SP1 zkVM — no emulator in the loop, ~100x cheaper to prove than
//! legacy jobs — but it is only executable by SP1 fleets.
//!
//! Protocol: read your input via `sp1_zkvm::io::read::<Vec<u8>>()`,
//! commit `blake3(input)` first (the binding verifiers pin receipts
//! with), then commit your output. Deterministic integer logic only:
//! no network, filesystem, clock, randomness, or floats.

#![no_main]
sp1_zkvm::entrypoint!(main);

fn main() {
    let input: Vec<u8> = sp1_zkvm::io::read();
    let input_id: [u8; 32] = blake3::hash(&input).into();
    sp1_zkvm::io::commit(&input_id);

    // TODO: your computation here. Replace this FNV hash with your
    // actual logic — anything deterministic and integer-only.
    let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in &input {
        acc = (acc ^ b as u64).wrapping_mul(0x100_0000_01b3);
    }
    let output = acc.to_le_bytes().to_vec();
    sp1_zkvm::io::commit(&output);
}
"#;

pub const V2_MANIFEST: &str = r#"{
  "schema": 1,
  "id": "{{ID}}",
  "name": "{{NAME}}",
  "isa": "rv64imc",
  "format": "sp1-v2",
  "toolchain": "sp1 6.8.0 (riscv64im-succinct-zkvm-elf)",
  "chunk_size": 1048576,
  "max_instructions": 1000000000,
  "verification_class": "quorum3",
  "elf": "program.elf",
  "input": "input.bin"
}"#;
