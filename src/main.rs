use unicorn_engine::RegisterARM;
use unicorn_engine::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};

fn main() {
    let arm_code32 = [0x17, 0x00, 0x40, 0xe2]; // sub r0, #23

    let mut emu = unicorn_engine::Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN)
        .expect("failed to initialize Unicorn instance");
    emu.mem_map(0x1000, 0x4000, Permission::ALL)
        .expect("failed to map code page");
    emu.mem_write(0x1000, &arm_code32)
        .expect("failed to write instructions");

    emu.reg_write(RegisterARM::R0, 123)
        .expect("failed write R0");
    emu.reg_write(RegisterARM::R5, 1337)
        .expect("failed write R5");

    emu.emu_start(
        0x1000,
        (0x1000 + arm_code32.len()) as u64,
        10 * SECOND_SCALE,
        1000,
    )
    .unwrap();
    assert_eq!(emu.reg_read(RegisterARM::R0), Ok(100));
    assert_eq!(emu.reg_read(RegisterARM::R5), Ok(1337));
}
