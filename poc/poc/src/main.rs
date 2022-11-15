#![feature(array_from_fn)]
extern crate solana_rbpf;

use solana_rbpf::{
    elf::Executable,
    user_error::UserError,
    vm::{SyscallRegistry, TestInstructionMeter, Config},
};

use std::io::Read;

fn main() {
    println!("Hello, world!");

    let mut config = Config::default();
    config.reject_broken_elfs  = true;
    let mut file = std::fs::File::open("/Users/hanhojung/Documents/GitHub/custom_rbpf/poc/poc/src/helloworld.so").expect("open failed");
    let mut buffer: Vec<u8> = vec![];
    file.read_to_end(&mut buffer).expect("read failed"); 
    //buffer[80+7] = 0xff;
    //buffer[96+15] = 0xff;
    Executable::<UserError, TestInstructionMeter>::load(config,&buffer,SyscallRegistry::default());
}
