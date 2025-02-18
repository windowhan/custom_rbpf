#![no_main]

use libfuzzer_sys::fuzz_target;

use semantic_aware::*;
use solana_rbpf::{insn_builder::IntoBytes, verifier::{RequisiteVerifier, Verifier}, vm::FunctionRegistry};

use crate::common::ConfigTemplate;

mod common;
mod semantic_aware;

#[derive(arbitrary::Arbitrary, Debug)]
struct FuzzData {
    template: ConfigTemplate,
    prog: FuzzProgram,
}

fuzz_target!(|data: FuzzData| {
    let prog = make_program(&data.prog);
    let config = data.template.into();
    let function_registry = FunctionRegistry::default();
    RequisiteVerifier::verify(prog.into_bytes(), &config, &function_registry).unwrap();
});
