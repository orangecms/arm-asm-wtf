# Understanding Arm

Well. Being a "reduced" instruction set... I still run into hard to understand
instructions.

## Code

This is the code I was given:

```asm
    mov x0, #0x11
    mov x1, #0xfdcc83c8
    add x0, x1, w0, uxtb #2
```

## Issue

Do you know this issue?

You want to understand an Arm instruction, and the manual is once again missing
details.

You try putting your asm in a file, compile and link it, load it into
`qemu-system -s -S`, and for whatever weird reason, it does not honor your
breakpoints when you try gdb. `qemu-user` does not even take the same flags.

You are close to "it is easier to drop inline asm into my Rust code and
`println!()` the result on hardware".

But wait... is there a unicorn 🦄 that could help?

## Research

I find the Arm online docs to be NOT helpful:

- https://developer.arm.com/documentation/dui0801/h/A64-General-Instructions/ADD--extended-register-
- https://developer.arm.com/documentation/ddi0602/2025-03/SVE-Instructions/UXTB--UXTH--UXTW--Unsigned-byte---halfword---word-extend--predicated--
- https://developer.arm.com/documentation/ddi0406/cb/Application-Level-Architecture/Instruction-Details/Alphabetical-list-of-instructions/UXTB?lang=en

The Microsoft blog helps a bit sometimes, e.g.:

https://devblogs.microsoft.com/oldnewthing/20220804-00/?p=106945

The Arm architecture reference manual is unfortunately PDF only:
https://developer.arm.com/documentation/ddi0487/latest/

## Solution

Sooooooo... just emulate and be happy!

Oops, http://163.238.35.161/~zhangs/arm64simulator/ is broken (as of the time
writing this note).

How about Unicorn :unicorn:?

https://www.unicorn-engine.org/docs/tutorial.html Well, I don't know C...

But I downloaded the source release tarball anyway, and saw a Cargo.toml in
there... Yay, Unicorn now has Rust bindings! 🦀

The lib.rs already starts with an Arm 32-bit example, so just edit it and be
done.

NOTE: There is https://alexaltea.github.io/unicorn.js/ where you can do the same
in JavaScript, but it only supports MIPS, ARM (32-bit), SPARC and x86 as of now.

## Running this

Download the Unicorn source release tarball:
https://github.com/unicorn-engine/unicorn/releases/tag/2.1.3

Extract it side by side with a clone of this repo.
Then just `cargo run --release` here as usual.
