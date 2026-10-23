//! The initial stack of a new program.
//!
//! `execve` puts the arguments, the environment and the auxiliary vector on the new stack, in the
//! layout of the System V ABI and of `create_elf_tables` in fs/binfmt_elf.c. From the top: the
//! path of the program, the environment strings, the argument strings, the platform string and
//! 16 random bytes. Below them, at a 16 byte aligned address: `argc`, the argument pointers, a
//! null pointer, the environment pointers, a null pointer and the auxiliary vector.

use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::auxv::{AT_EXECFN, AT_NULL, AT_PLATFORM, AT_RANDOM};

/// The longest argument or environment string, with its zero byte. Linux names it
/// `MAX_ARG_STRLEN`.
pub const MAX_ARG_STRLEN: usize = 32 * 4096;
/// The most bytes of strings and pointers. Linux uses a quarter of `RLIMIT_STACK`, and the default
/// limit is 8 MiB.
pub const ARG_MAX: usize = 2 << 20;

/// The bytes of the initial stack and the stack pointer. The bytes go at `sp` and end at the top.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackImage {
    /// The initial stack pointer. It points to `argc` and is 16 byte aligned.
    pub sp: usize,
    /// The bytes from `sp` to the top of the stack.
    pub bytes: Vec<u8>,
}

/// The content of the initial stack.
#[derive(Clone, Copy, Debug)]
pub struct StackArgs<'a> {
    /// The arguments.
    pub argv: &'a [Vec<u8>],
    /// The environment.
    pub envp: &'a [Vec<u8>],
    /// The path that `execve` got, for `AT_EXECFN`.
    pub execfn: &'a [u8],
    /// The platform string for `AT_PLATFORM`, or empty for none.
    pub platform: &'a [u8],
    /// The bytes for `AT_RANDOM`.
    pub random: [u8; 16],
    /// The entries of the auxiliary vector, without `AT_RANDOM`, `AT_EXECFN`, `AT_PLATFORM` and
    /// `AT_NULL`. This function adds them.
    pub auxv: &'a [(u64, u64)],
}

/// Gives the size that `argv` and `envp` take on the stack, with the pointers.
///
/// # Errors
///
/// Gives `E2BIG` if a string is longer than `MAX_ARG_STRLEN` or the total is more than `ARG_MAX`.
pub fn args_size(argv: &[Vec<u8>], envp: &[Vec<u8>]) -> Result<usize, Errno> {
    let mut total = 0usize;
    for s in argv.iter().chain(envp) {
        if s.len() + 1 > MAX_ARG_STRLEN {
            return Err(Errno::E2BIG);
        }
        total += s.len() + 1 + 8;
    }
    if total > ARG_MAX {
        return Err(Errno::E2BIG);
    }
    Ok(total)
}

/// Makes the initial stack that ends at `top`.
///
/// # Errors
///
/// Gives `E2BIG` if the strings are too long, as `args_size` tells.
pub fn build(top: usize, args: &StackArgs<'_>) -> Result<StackImage, Errno> {
    args_size(args.argv, args.envp)?;
    // Linux keeps a null pointer at the top, and the path is below it.
    let mut cur = top - 8;
    let mut strings: Vec<(usize, &[u8])> = Vec::new();
    let put = |cur: &mut usize, data: &[u8]| -> usize {
        *cur -= data.len() + 1;
        *cur
    };
    let execfn = put(&mut cur, args.execfn);
    strings.push((execfn, args.execfn));
    let mut envp = vec![0usize; args.envp.len()];
    for (i, s) in args.envp.iter().enumerate().rev() {
        envp[i] = put(&mut cur, s);
        strings.push((envp[i], s));
    }
    let mut argv = vec![0usize; args.argv.len()];
    for (i, s) in args.argv.iter().enumerate().rev() {
        argv[i] = put(&mut cur, s);
        strings.push((argv[i], s));
    }
    let platform = if args.platform.is_empty() {
        None
    } else {
        let at = put(&mut cur, args.platform);
        strings.push((at, args.platform));
        Some(at)
    };
    cur = (cur - 16) & !15;
    let random = cur;
    strings.push((random, &args.random));

    let mut auxv: Vec<(u64, u64)> = args.auxv.to_vec();
    auxv.push((u64::from(AT_RANDOM), random as u64));
    auxv.push((u64::from(AT_EXECFN), execfn as u64));
    if let Some(at) = platform {
        auxv.push((u64::from(AT_PLATFORM), at as u64));
    }
    auxv.push((u64::from(AT_NULL), 0));
    let words = 1 + argv.len() + 1 + envp.len() + 1 + 2 * auxv.len();
    let sp = (cur - 8 * words) & !15;

    let mut table = Vec::with_capacity(words);
    table.push(argv.len() as u64);
    table.extend(argv.iter().map(|&a| a as u64));
    table.push(0);
    table.extend(envp.iter().map(|&a| a as u64));
    table.push(0);
    for (key, value) in auxv {
        table.push(key);
        table.push(value);
    }
    let mut bytes = vec![0u8; top - sp];
    for (i, word) in table.iter().enumerate() {
        bytes[8 * i..8 * i + 8].copy_from_slice(&word.to_le_bytes());
    }
    for (at, data) in strings {
        bytes[at - sp..at - sp + data.len()].copy_from_slice(data);
    }
    Ok(StackImage { sp, bytes })
}
