use unicorn_engine::RegisterARM64;
use unicorn_engine::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};

// https://shell-storm.org/online/Online-Assembler-and-Disassembler/
const CODE: [u8; 4] = [
    0x60, 0x5a, 0x75, 0xf8, // ldr   x0, [x19, w21, uxtw #3]
];
const CODE_SIZE: u64 = CODE.len() as u64;

const MEM_BASE: u64 = 0xfdcc_8000;
const MEM_SIZE: usize = 0x4000;

const TIMEOUT: u64 = 10 * SECOND_SCALE;
const MAX_INSTRUCTIONS: usize = 1000;

const DATA: [u8; 32] = [
    0x88, 0xba, 0xcc, 0xfd, 0x00, 0x00, 0x00, 0x00, // cfg slot 0
    0x68, 0xa8, 0xcc, 0xfd, 0x00, 0x00, 0x00, 0x00, // cfg slot 1
    0xb8, 0x9b, 0xcc, 0xfd, 0x00, 0x00, 0x00, 0x00, // cfg slot 2
    0x98, 0x89, 0xcc, 0xfd, 0x00, 0x00, 0x00, 0x00, // cfg slot 3
];

const CFG_BASE: u64 = 0xfdcc8940;

fn main() {
    let mut emu = unicorn_engine::Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN)
        .expect("failed to initialize Unicorn instance");
    emu.mem_map(MEM_BASE, MEM_SIZE, Permission::ALL)
        .expect("failed to map code page");
    emu.mem_write(MEM_BASE, &CODE)
        .expect("failed to write instructions");

    emu.mem_write(CFG_BASE, &DATA)
        .expect("failed to write data");

    emu.reg_write(RegisterARM64::X19, CFG_BASE)
        .expect("failed to write X19");
    emu.reg_write(RegisterARM64::W21, 0x3)
        .expect("failed to write W21");

    emu.emu_start(MEM_BASE, MEM_BASE + CODE_SIZE, TIMEOUT, MAX_INSTRUCTIONS)
        .unwrap();

    let r = emu.reg_read(RegisterARM64::W21).unwrap();
    println!("w21:   {r:08x}");

    let r = emu.reg_read(RegisterARM64::X0).unwrap();
    println!("res:   {r:08x}");
}
