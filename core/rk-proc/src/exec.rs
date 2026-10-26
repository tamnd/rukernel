//! `execve`: the kernel replaces the program of a process.
//!
//! The kernel finds the file, reads its headers and makes a new address space with the segments
//! of the file, the program interpreter if the file has one, and a stack with the arguments, the
//! environment and the auxiliary vector. A file that starts with `#!` runs its interpreter, as
//! fs/binfmt_script.c does. The process keeps the old address space until the new one is
//! complete, so an error before the end leaves the process as it was.

use crate::elf::{self, EHDR_SIZE, ElfHeader, ElfType, PHDR_SIZE};
use crate::process::Thread;
use crate::script::parse_script;
use crate::stack::{self, StackArgs};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_abi::native::auxv::{
    AT_BASE, AT_CLKTCK, AT_EGID, AT_ENTRY, AT_EUID, AT_FLAGS, AT_GID, AT_HWCAP, AT_PAGESZ, AT_PHDR,
    AT_PHENT, AT_PHNUM, AT_SECURE, AT_SYSINFO_EHDR, AT_UID,
};
use rk_abi::native::mount::MS_NOSUID;
use rk_mm::{AddressSpace, MmapRequest, PAGE_SIZE, Prot, STACK_SIZE, STACK_TOP, VmaKind};
use rk_vfs::cred::{Cred, ExecFile};
use rk_vfs::{FileType, FsContext, InodeRef, Location};

/// The most interpreters in a chain of `#!` scripts. Linux names it `BINPRM_MAX_RECURSION`.
const MAX_SCRIPT_DEPTH: usize = 4;
/// The longest `#!` line that the kernel reads. Linux names it `BINPRM_BUF_SIZE`.
const SCRIPT_LINE: usize = 256;
/// The base of a position independent executable. Linux names it `ELF_ET_DYN_BASE`: two thirds of
/// the user address space, at a 2 MiB boundary.
pub const ET_DYN_BASE: usize = (STACK_TOP / 3 * 2) & !0x1f_ffff;
/// The ticks of `times` each second, for `AT_CLKTCK`. Linux names it `USER_HZ`.
pub const USER_HZ: u64 = 100;

/// Where the new program starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecImage {
    /// The first instruction: the entry of the interpreter, or else the entry of the program.
    pub entry: usize,
    /// The initial stack pointer.
    pub sp: usize,
}

/// The arguments of `exec`.
#[derive(Clone, Debug)]
pub struct ExecArgs {
    /// The path that `execve` got.
    pub path: Vec<u8>,
    /// The arguments.
    pub argv: Vec<Vec<u8>>,
    /// The environment.
    pub envp: Vec<Vec<u8>>,
}

/// The ELF machine of this architecture.
#[cfg(target_arch = "x86_64")]
const MACHINE: u16 = rk_abi::native::elf::EM_X86_64 as u16;
#[cfg(target_arch = "aarch64")]
const MACHINE: u16 = rk_abi::native::elf::EM_AARCH64 as u16;
#[cfg(target_arch = "riscv64")]
const MACHINE: u16 = rk_abi::native::elf::EM_RISCV as u16;

/// Reads `buf.len()` bytes at `offset`, or fewer at the end of the file.
fn read_full(inode: &InodeRef, offset: u64, buf: &mut [u8]) -> Result<usize, Errno> {
    let mut done = 0;
    while done < buf.len() {
        let n = inode.read_at(offset + done as u64, &mut buf[done..])?;
        if n == 0 {
            break;
        }
        done += n;
    }
    Ok(done)
}

/// Finds an executable file. Gives `EACCES` for a file that is not a regular file or that the
/// process cannot run.
fn open_exec(fs: &FsContext, path: &[u8]) -> Result<Location, Errno> {
    let at = fs.resolve(fs.cwd(), path, true)?;
    if at.inode().metadata().file_type() != Some(FileType::Regular) {
        return Err(Errno::EACCES);
    }
    fs.permission(&at, rk_vfs::cred::may::EXEC)?;
    Ok(at)
}

/// The result of the load of one ELF file.
struct Loaded {
    bias: usize,
    header: ElfHeader,
    end: usize,
}

/// Loads the segments of `inode` in `space`. A `Dyn` file goes at `base`, or at an address that
/// the address space chooses if `base` is `None`.
fn load_elf(
    space: &AddressSpace,
    inode: &InodeRef,
    header: ElfHeader,
    base: Option<usize>,
) -> Result<Loaded, Errno> {
    let (low, high) = header.span();
    let size = usize::try_from(high - low).map_err(|_| Errno::ENOMEM)?;
    let bias = match header.kind {
        ElfType::Exec => 0,
        ElfType::Dyn => {
            let start = match base {
                Some(base) => base,
                None => {
                    // Take a free range, then give it back to map the segments in it.
                    let at = space.mmap(MmapRequest::anon(size, Prot::default()))?;
                    space.munmap(at, size)?;
                    at
                }
            };
            start.checked_sub(low as usize).ok_or(Errno::ENOMEM)?
        }
    };
    let page = PAGE_SIZE as u64;
    let mut mapped_end = 0usize;
    for seg in &header.segments {
        if seg.memsz == 0 {
            continue;
        }
        let start = (bias as u64 + seg.vaddr) / page * page;
        let end = (bias as u64 + seg.vaddr + seg.memsz).div_ceil(page) * page;
        let (start, end) = (start as usize, end as usize);
        // Two segments can share a page. The page is mapped one time.
        let map_start = start.max(mapped_end);
        if map_start < end {
            let req = MmapRequest {
                addr: map_start,
                fixed: true,
                kind: VmaKind::Normal,
                ..MmapRequest::anon(end - map_start, Prot::RW)
            };
            space.mmap(req)?;
            mapped_end = end;
        }
        let mut buf = vec![0u8; 64 * 1024];
        let mut done = 0u64;
        while done < seg.filesz {
            let n = (seg.filesz - done).min(buf.len() as u64) as usize;
            let got = read_full(inode, seg.offset + done, &mut buf[..n])?;
            if got < n {
                return Err(Errno::EIO);
            }
            space.write(bias + (seg.vaddr + done) as usize, &buf[..n])?;
            done += n as u64;
        }
    }
    for seg in &header.segments {
        if seg.memsz == 0 {
            continue;
        }
        let start = (bias as u64 + seg.vaddr) / page * page;
        let end = (bias as u64 + seg.vaddr + seg.memsz).div_ceil(page) * page;
        let prot = Prot { read: seg.flags.read, write: seg.flags.write, exec: seg.flags.exec };
        space.mprotect(start as usize, (end - start) as usize, prot)?;
    }
    Ok(Loaded { bias, end: bias + high as usize, header })
}

/// Reads the headers of the ELF file `inode`.
fn read_headers(inode: &InodeRef) -> Result<ElfHeader, Errno> {
    let mut ehdr = [0u8; EHDR_SIZE];
    if read_full(inode, 0, &mut ehdr)? < EHDR_SIZE {
        return Err(Errno::ENOEXEC);
    }
    let (phoff, size) = elf::parse_ehdr(&ehdr, MACHINE)?;
    let mut phdrs = vec![0u8; size];
    if read_full(inode, phoff, &mut phdrs)? < size {
        return Err(Errno::ENOEXEC);
    }
    elf::parse(&ehdr, &phdrs, MACHINE)
}

/// Makes the new address space and the initial stack for `args`. `random` gives the 16 bytes of
/// `AT_RANDOM`. Also gives the file of the program, the arguments, which an interpreter line
/// changes, the auxiliary vector and the new credentials. With `no_setid`, the set-user-ID and
/// set-group-ID bits of the file have no effect.
fn build(
    fs: &FsContext,
    mut args: ExecArgs,
    random: [u8; 16],
    cred: &Cred,
    no_setid: bool,
) -> Result<(AddressSpace, ExecImage, Location, Vec<Vec<u8>>, Vec<u8>, Cred), Errno> {
    let mut path = args.path.clone();
    let mut depth = 0;
    let (at, header) = loop {
        let at = open_exec(fs, &path)?;
        let mut head = [0u8; SCRIPT_LINE];
        let n = read_full(at.inode(), 0, &mut head)?;
        if head[..n].starts_with(b"#!") {
            depth += 1;
            if depth > MAX_SCRIPT_DEPTH {
                return Err(Errno::ELOOP);
            }
            let (interp, arg) = parse_script(&head[..n])?;
            // The new arguments: the interpreter, its argument, the path of the script and the
            // arguments after the first one.
            let mut argv = vec![interp.clone()];
            argv.extend(arg);
            argv.push(path.clone());
            argv.extend(args.argv.iter().skip(1).cloned());
            args.argv = argv;
            path = interp;
            continue;
        }
        if !elf::is_elf(&head[..n]) {
            return Err(Errno::ENOEXEC);
        }
        let header = read_headers(at.inode())?;
        break (at, header);
    };

    let meta = at.inode().metadata();
    let file = ExecFile {
        mode: meta.mode,
        uid: meta.uid,
        gid: meta.gid,
        no_setid: no_setid || at.mount.flags() & u64::from(MS_NOSUID) != 0,
    };
    let (cred, secure) = cred.exec(file);

    let space = AddressSpace::new()?;
    let interp = match header.interp {
        Some((offset, len)) => {
            let mut name = vec![0u8; len as usize];
            if read_full(at.inode(), offset, &mut name)? < name.len() {
                return Err(Errno::ENOEXEC);
            }
            // The path ends with a zero byte.
            if name.pop() != Some(0) || name.contains(&0) {
                return Err(Errno::ENOEXEC);
            }
            let interp_at = open_exec(fs, &name)?;
            let interp_header = read_headers(interp_at.inode())?;
            if interp_header.interp.is_some() {
                return Err(Errno::ELIBBAD);
            }
            Some((interp_at, interp_header))
        }
        None => None,
    };
    let main = load_elf(&space, at.inode(), header, Some(ET_DYN_BASE))?;
    let interp = match interp {
        Some((iat, ih)) => Some(load_elf(&space, iat.inode(), ih, None)?),
        None => None,
    };
    space.set_brk_start(main.end.div_ceil(PAGE_SIZE) * PAGE_SIZE);

    let stack = MmapRequest {
        addr: STACK_TOP - STACK_SIZE,
        fixed: true,
        kind: VmaKind::Stack,
        ..MmapRequest::anon(STACK_SIZE, Prot::RW)
    };
    space.mmap(stack)?;
    let vdso = crate::vdso::map(&space)?;

    let phdr = main.header.phdr_addr().map_or(0, |a| main.bias + a as usize);
    let entry = main.bias + main.header.entry as usize;
    let auxv = [
        (u64::from(AT_SYSINFO_EHDR), vdso as u64),
        (u64::from(AT_HWCAP), 0),
        (u64::from(AT_PAGESZ), PAGE_SIZE as u64),
        (u64::from(AT_CLKTCK), USER_HZ),
        (u64::from(AT_PHDR), phdr as u64),
        (u64::from(AT_PHENT), PHDR_SIZE as u64),
        (u64::from(AT_PHNUM), u64::from(main.header.phnum)),
        (u64::from(AT_BASE), interp.as_ref().map_or(0, |i| i.bias as u64)),
        (u64::from(AT_FLAGS), 0),
        (u64::from(AT_ENTRY), entry as u64),
        (u64::from(AT_UID), u64::from(cred.uid)),
        (u64::from(AT_EUID), u64::from(cred.euid)),
        (u64::from(AT_GID), u64::from(cred.gid)),
        (u64::from(AT_EGID), u64::from(cred.egid)),
        (u64::from(AT_SECURE), u64::from(secure)),
    ];
    let image = stack::build(
        STACK_TOP,
        &StackArgs {
            argv: &args.argv,
            envp: &args.envp,
            execfn: &args.path,
            platform: rk_frame::arch::UNAME_MACHINE.as_bytes(),
            random,
            auxv: &auxv,
        },
    )?;
    space.write(image.sp, &image.bytes)?;
    let start = interp.map_or(entry, |i| i.bias + i.header.entry as usize);
    Ok((space, ExecImage { entry: start, sp: image.sp }, at, args.argv, image.auxv, cred))
}

/// Runs a new program in the process of `thread`. On success the process has the new address
/// space, the descriptors with `FD_CLOEXEC` are closed and the name of the process is the name of
/// the file. The caller then starts the thread at the `ExecImage` with new registers. `release`
/// runs when the exec cannot fail any more, while the old address space is still there, as
/// `exec_mm_release` of Linux does.
///
/// # Errors
///
/// Gives the error of the lookup of the file, `EACCES` for a file that cannot run, `ENOEXEC` for
/// a file in a format that the kernel does not know, `E2BIG` for arguments that are too long and
/// `ENOMEM` if no memory is free. Then the process is as it was.
pub fn exec(
    thread: &Thread,
    args: ExecArgs,
    random: [u8; 16],
    release: fn(&Thread),
) -> Result<ExecImage, Errno> {
    let process = thread.process();
    let fs = process.fs().ok_or(Errno::ESRCH)?;
    let mut ctx = fs.lock().clone();
    ctx.set_cred(process.cred());
    let path = args.path.clone();
    // A tracer cannot follow a program that gets more rights, so the bits have no effect then.
    // A tracer with `CAP_SYS_PTRACE` can, as `cap_bprm_creds_from_file` of Linux.
    let no_setid = thread.no_new_privs() || (thread.is_traced() && !thread.tracer_capable());
    let (space, image, at, argv, auxv, cred) =
        build(&ctx, args, random, &process.cred(), no_setid)?;
    // The new program is ready, so the exec cannot fail now. The other threads end first.
    crate::process::kill_other_threads(thread);
    release(thread);
    let space = Arc::new(space);
    space.activate();
    let old = process.replace_vm(space);
    drop(old);
    thread.release_vfork();
    if let Some(files) = process.files() {
        // A table that another process shares stays with it, and this process takes a copy.
        let mut table = files.lock().clone_for_exec();
        table.close_on_exec();
        process.set_files(Arc::new(rk_frame::sync::SpinLock::new(table)));
    }
    // The handlers are in the old program, so they go back to the default action. The mask and
    // the pending signals stay, as POSIX tells.
    process.reset_actions();
    // The POSIX timers go away, and the interval timers stay.
    process.timers().clear(true);
    thread.set_altstack(crate::signal::AltStack::default());
    let name = path.rsplit(|&b| b == b'/').next().unwrap_or(&path);
    process.set_comm(name);
    process.set_cred(cred);
    process.set_image(&argv, at, auxv);
    Ok(image)
}
