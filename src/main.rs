use unicorn_engine::RegisterARM64;
use unicorn_engine::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};

const MEM_BASE: u64 = 0xfdcc_0000;
const MEM_SIZE: usize = 0x1_0000;

const TIMEOUT: u64 = 10 * SECOND_SCALE;
const MAX_INSTRUCTIONS: usize = 8000;

// https://shell-storm.org/online/Online-Assembler-and-Disassembler/
const CODE_OFFSET: u64 = 0x2528;
const CODE_SIZE: u64 = 4;
const CODE: [u8; CODE_SIZE as usize] = [
    0x40, 0x00, 0xa1, 0x9b, // umaddl x0, w2, w1, x0
];

const LOAD_OFFSET: u64 = 0x1000;
const CODE_BASE: u64 = MEM_BASE + LOAD_OFFSET + CODE_OFFSET;

// config objects are stored consecutively
const CFG_BASE: u64 = 0xfdcc8998;
const CFG_SIZE: u64 = 0x1d0;

fn main() {
    let mut emu = unicorn_engine::Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN)
        .expect("failed to initialize Unicorn instance");
    // Map our memory. Just have it all RWX, good enough for us.
    emu.mem_map(MEM_BASE, MEM_SIZE, Permission::ALL)
        .expect("failed to map code page");

    // Load our code and data.
    emu.mem_write(CODE_BASE, &CODE)
        .expect("failed to write instructions");

    emu.reg_write(RegisterARM64::X0, CFG_BASE).unwrap();
    emu.reg_write(RegisterARM64::X1, CFG_SIZE).unwrap();
    emu.reg_write(RegisterARM64::W2, 5).unwrap();

    emu.emu_start(CODE_BASE, CODE_BASE + CODE_SIZE, TIMEOUT, MAX_INSTRUCTIONS)
        .unwrap();

    let r = emu.reg_read(RegisterARM64::X0).unwrap();
    //               fdcc92a8
    println!(" X0:   {r:08x}");
}
