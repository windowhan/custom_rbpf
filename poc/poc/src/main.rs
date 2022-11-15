#![feature(array_from_fn)]
extern crate solana_rbpf;
use trace::trace;

trace::init_depth_var!();

use solana_rbpf::{
    ebpf,
    elf::Executable,
    memory_region::MemoryRegion,
    verifier::RequisiteVerifier,
    vm::{Config, EbpfVm, SyscallRegistry, TestContextObject, VerifiedExecutable},
};
use std::{fs::File, io::Read};

fn main() {
    let filename = "/Users/hanhojung/Documents/GitHub/custom_rbpf/tests/elfs/pass_stack_reference.so";
    println!("filename : {:?}", filename);
    let mut file = File::open(filename).unwrap();

    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let executable = Executable::<TestContextObject>::from_elf(
        &elf,
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
    let verified_executable =
        VerifiedExecutable::<RequisiteVerifier, TestContextObject>::from_executable(executable)
            .unwrap();
            
    let mut context_object = TestContextObject::default();
    context_object.remaining=524289;
    let mut vm = EbpfVm::new(
        &verified_executable,
        &mut context_object,
        &mut [],
        Vec::new(),
    )
    .unwrap();
    println!("execution ready!!!");
    println!("{:?}", vm.execute_program(true));

}
