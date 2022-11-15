#![feature(array_from_fn)]
extern crate solana_rbpf;

use solana_rbpf::{
    ebpf,
    elf::Executable,
    memory_region::MemoryRegion,
    vm::{Config, EbpfVm, SyscallRegistry, TestContextObject, VerifiedExecutable},
};
use std::{fs::File, io::Read};

fn main() {
    let mut config = Config::default();
    config.reject_broken_elfs  = true;
    let mut file = std::fs::File::open("/Users/hanhojung/Documents/GitHub/custom_rbpf/poc/poc/src/helloworld.so").expect("open failed");
    let mut buffer: Vec<u8> = vec![];
    file.read_to_end(&mut buffer).expect("read failed"); 

    //print!("{:?}", &mut buffer);
    let execution = Executable::<TestContextObject>::load(config,&buffer,SyscallRegistry::default());
    print!("{:?}", execution);
}
