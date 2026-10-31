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
use rk_abi::native::mount::{MS_NOEXEC, MS_NOSUID};
use rk_frame::mm::{Frame, alloc_frame};
use rk_frame::sync::Once;
use rk_mm::{
    AddressSpace, FileRef, MMAP_TOP, MmFile, MmapRequest, PAGE_SIZE, Prot, STACK_GUARD_GAP,
    STACK_SIZE, STACK_TOP, VmaKind,
};
use rk_vfs::cred::{Cred, ExecFile};
use rk_vfs::file::DenyWrite;
use rk_vfs::{FileType, FsContext, InodeRef, Location};

/// The most interpreters in a chain of `#!` scripts. Linux names it `BINPRM_MAX_RECURSION`.
const MAX_SCRIPT_DEPTH: usize = 4;
/// The longest `#!` line that the kernel reads. Linux names it `BINPRM_BUF_SIZE`.
const SCRIPT_LINE: usize = 256;
/// The flag of `personality` that turns off the random layout, as in Linux.
pub const ADDR_NO_RANDOMIZE: u32 = 0x0004_0000;
/// The flags of `personality` that an exec with more rights removes, as `PER_CLEAR_ON_SETID` of
/// Linux: `READ_IMPLIES_EXEC`, `ADDR_NO_RANDOMIZE`, `ADDR_COMPAT_LAYOUT` and `MMAP_PAGE_ZERO`.
pub const PER_CLEAR_ON_SETID: u32 = 0x0040_0000 | ADDR_NO_RANDOMIZE | 0x0020_0000 | 0x0010_0000;

/// The bits of the random offset of the `mmap` area, in pages. They are the defaults of
/// `mmap_rnd_bits` of Linux: 28 on x86-64 and 18 on arm64 with 4 KiB pages.
#[cfg(target_arch = "aarch64")]
const MMAP_RND_BITS: u32 = 18;
#[cfg(not(target_arch = "aarch64"))]
const MMAP_RND_BITS: u32 = 28;

/// The largest random offset of the main stack, in pages. Linux names it `STACK_RND_MASK`: 0x3ffff
/// on arm64 with 4 KiB pages (1 GiB) and 0x3fffff on x86-64 (16 GiB).
#[cfg(target_arch = "aarch64")]
const STACK_RND_MASK: usize = 0x3_ffff;
#[cfg(not(target_arch = "aarch64"))]
const STACK_RND_MASK: usize = 0x3f_ffff;

/// The distance from [`MMAP_TOP`] to the top of the `mmap` area of a program with a random layout,
/// for the random value `seed`. This is `mmap_base` in mm/util.c of Linux. The gap below the top
/// of the stack is the stack size, `stack_guard_gap` and the largest random offset of the stack,
/// and it is at least the 128 MiB of [`MMAP_TOP`]. Then `arch_mmap_rnd` moves the area down by a
/// random number of pages. LTP hugemmap24 maps fixed addresses up to 520 MiB above its heap. On
/// arm64 the random offset is at most 1 GiB, so without the gap these addresses can be on the
/// stack or past the end of the user space.
fn mmap_offset(seed: u64) -> usize {
    let gap = STACK_SIZE + STACK_GUARD_GAP + STACK_RND_MASK * PAGE_SIZE;
    let pad = gap.saturating_sub(STACK_TOP - MMAP_TOP);
    pad + (seed & ((1 << MMAP_RND_BITS) - 1)) as usize * PAGE_SIZE
}

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
    /// Where a relative path starts, for `execveat`. `None` is the working directory. An empty
    /// path is this file itself, as `AT_EMPTY_PATH` of Linux.
    pub start: Option<Location>,
    /// The lookup follows a symbolic link at the end of the path. `execveat` with
    /// `AT_SYMLINK_NOFOLLOW` clears it, and then a link gives `ELOOP`, as Linux.
    pub follow: bool,
}

impl ExecArgs {
    /// The arguments of `execve`: the path starts at the working directory and the lookup
    /// follows symbolic links.
    pub fn new(path: Vec<u8>, argv: Vec<Vec<u8>>, envp: Vec<Vec<u8>>) -> Self {
        Self { path, argv, envp, start: None, follow: true }
    }
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
    open_exec_at(fs, None, path, true)
}

/// Finds an executable file from `start`, as `do_open_execat` of Linux. An empty path is
/// `start` itself.
fn open_exec_at(
    fs: &FsContext,
    start: Option<&Location>,
    path: &[u8],
    follow: bool,
) -> Result<Location, Errno> {
    let at = match start {
        Some(start) if path.is_empty() => start.clone(),
        Some(start) => fs.resolve(start, path, follow)?,
        None => fs.resolve(fs.cwd(), path, follow)?,
    };
    if !follow && at.inode().metadata().file_type() == Some(FileType::Symlink) {
        return Err(Errno::ELOOP);
    }
    if at.inode().metadata().file_type() != Some(FileType::Regular) {
        return Err(Errno::EACCES);
    }
    fs.permission(&at, rk_vfs::cred::may::EXEC)?;
    // A mount with `MS_NOEXEC` does not run its files, as `path_noexec` of Linux.
    if at.mount.flags() & u64::from(MS_NOEXEC) != 0 {
        return Err(Errno::EACCES);
    }
    // The open of the file to run has the events of an open with `__FMODE_EXEC`, as
    // `do_open_execat` of Linux.
    rk_vfs::notify::open_perm(&at, true)?;
    rk_vfs::notify::open(&at, true);
    Ok(at)
}

/// The size of the buffer that `Segment::page` reads the file data through.
const PAGE_CHUNK: usize = 1024;

/// The function that gives the shared pages of a file, which all the mappings of the file use.
static FILE_PAGES: Once<fn(&InodeRef, Vec<u8>) -> FileRef> = Once::new();

/// Sets the function that gives the shared pages of a file, as the page cache of Linux. A program
/// then uses the same frames as the other programs that run the file, and a fault does not copy
/// the file data. Only the first call has an effect.
pub fn set_file_pages_hook(f: fn(&InodeRef, Vec<u8>) -> FileRef) {
    FILE_PAGES.call_once(|| f);
}

/// The pages of one segment of an ELF file, for a private file mapping of the segment. A page that
/// has only file data is the shared page of the file, as Linux maps the page cache, and a write
/// copies it. The other page is a new copy of the file data, which the first fault reads. The
/// bytes of the file after the segment data are zero, as `padzero` of fs/binfmt_elf.c gives them,
/// so the last page of the data starts the zero memory of the segment. `/proc/PID/maps` shows the
/// name of the file.
struct Segment {
    inode: InodeRef,
    /// The path of the file, for `/proc/PID/maps`.
    path: Vec<u8>,
    /// The offset in the file after the data of the segment.
    limit: u64,
    /// The shared pages of the file, if the kernel set them with `set_file_pages_hook`.
    shared: Option<FileRef>,
}

impl Segment {
    /// Makes the pages of the segment of the file `inode` at `path` that ends at `limit`.
    fn new(inode: &InodeRef, path: Vec<u8>, limit: u64) -> Self {
        let shared = FILE_PAGES.get().map(|f| f(inode, path.clone()));
        Segment { inode: inode.clone(), path, limit, shared }
    }

    /// The shared pages of the file, if the page `index` has only file data.
    fn shared(&self, index: u64) -> Option<&FileRef> {
        let end = index.checked_add(1)?.checked_mul(PAGE_SIZE as u64)?;
        self.shared.as_ref().filter(|_| end <= self.limit)
    }
}

impl MmFile for Segment {
    fn page(&self, index: u64) -> Result<Arc<Frame>, Errno> {
        if let Some(shared) = self.shared(index) {
            return shared.page(index);
        }
        let offset = index.checked_mul(PAGE_SIZE as u64).ok_or(Errno::EIO)?;
        // Each exec faults in many pages, so the page is filled once: the file data goes to the
        // frame through a small buffer, and only the bytes after the data are set to zero.
        let frame = alloc_frame().ok_or(Errno::ENOMEM)?;
        let len = self.limit.saturating_sub(offset).min(PAGE_SIZE as u64) as usize;
        let mut buf = [0u8; PAGE_CHUNK];
        let mut done = 0;
        while done < len {
            let want = (len - done).min(PAGE_CHUNK);
            let n = read_full(&self.inode, offset + done as u64, &mut buf[..want])?;
            frame.write_bytes(done, &buf[..n]);
            done += n;
            if n < want {
                break;
            }
        }
        frame.fill_zero(done, PAGE_SIZE - done);
        Ok(Arc::new(frame))
    }

    fn name(&self) -> (u64, u64, Vec<u8>) {
        let meta = self.inode.metadata();
        (meta.dev, meta.ino, self.path.clone())
    }

    fn cached(&self, index: u64) -> bool {
        self.shared(index).is_some_and(|shared| shared.cached(index))
    }

    /// A page that is not shared is a read of the file at each fault.
    fn ready(&self, index: u64) -> bool {
        self.shared(index).is_some_and(|shared| shared.ready(index))
    }
}

/// The result of the load of one ELF file.
struct Loaded {
    bias: usize,
    header: ElfHeader,
    end: usize,
}

/// Loads the segments of the file `at` in `space`. A `Dyn` file goes at `base`, or at an address
/// that the address space chooses if `base` is `None`.
///
/// A segment is a private mapping of the file, as `elf_map` of Linux, and anonymous memory after
/// the data of the file, so `/proc/PID/maps` shows the file. A segment whose address and offset
/// do not agree in the page, or whose first page is in the previous segment, is anonymous memory
/// with a copy of the data.
///
/// A mapping of the file gets the protection of its segment at once, as on Linux, so a segment
/// that cannot be written is not in the commit count and has no `VM_ACCOUNT` (`ac` in
/// `/proc/PID/smaps`). Only a segment that the copy of a later segment writes to is writable
/// until the end.
fn load_elf(
    space: &AddressSpace,
    at: &Location,
    header: ElfHeader,
    base: Option<usize>,
) -> Result<Loaded, Errno> {
    let inode = at.inode();
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
    for (i, seg) in header.segments.iter().enumerate() {
        if seg.memsz == 0 {
            continue;
        }
        let start = (bias as u64 + seg.vaddr) / page * page;
        let end = (bias as u64 + seg.vaddr + seg.memsz).div_ceil(page) * page;
        let copied_later = header.segments[i + 1..]
            .iter()
            .any(|s| s.memsz != 0 && (bias as u64 + s.vaddr) / page * page < end);
        let prot = if copied_later {
            Prot::RW
        } else {
            Prot { read: seg.flags.read, write: seg.flags.write, exec: seg.flags.exec }
        };
        let (start, end) = (start as usize, end as usize);
        let data_end = (bias as u64 + seg.vaddr + seg.filesz).div_ceil(page) * page;
        let aligned = seg.vaddr % page == seg.offset % page;
        if aligned && start >= mapped_end && seg.filesz != 0 {
            let file: FileRef =
                Arc::new(Segment::new(inode, at.absolute_path(), seg.offset + seg.filesz));
            let data_end = data_end as usize;
            let req = MmapRequest {
                addr: start,
                fixed: true,
                file: Some((file, seg.offset / page * page)),
                ..MmapRequest::anon(data_end - start, prot)
            };
            space.mmap(req)?;
            if data_end < end {
                let req = MmapRequest {
                    addr: data_end,
                    fixed: true,
                    ..MmapRequest::anon(end - data_end, prot)
                };
                space.mmap(req)?;
            }
            mapped_end = end;
            continue;
        }
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

/// What `build` gives: the address space, the start of the program, the file of the program
/// with the denial of its write, the arguments, the auxiliary vector and the credentials.
type Built = (AddressSpace, ExecImage, (Location, DenyWrite), Vec<Vec<u8>>, Vec<u8>, Cred, u32);

/// Makes the new address space and the initial stack for `args`. `random` gives the 16 bytes of
/// `AT_RANDOM`. Also gives the file of the program, the arguments, which an interpreter line
/// changes, the auxiliary vector, the new credentials and the flags of `personality` that the
/// exec removes. With `no_new_privs`, the set-user-ID and set-group-ID bits of the file have no
/// effect. With `traced`, they change no ID, but they still remove the flags, as on Linux.
/// Without `ADDR_NO_RANDOMIZE` in `personality` after the removal, the top of the `mmap` area gets
/// a random offset.
fn build(
    fs: &FsContext,
    mut args: ExecArgs,
    random: [u8; 16],
    cred: &Cred,
    (no_new_privs, traced): (bool, bool),
    memcg: u32,
    personality: u32,
) -> Result<Built, Errno> {
    let mut path = args.path.clone();
    let mut depth = 0;
    // The first lookup uses the start and the flags of `execveat`. An interpreter of a script
    // is a path from the working directory, as Linux.
    let mut first = Some((args.start.take(), args.follow));
    let (at, header) = loop {
        let at = match first.take() {
            Some((start, follow)) => open_exec_at(fs, start.as_ref(), &path, follow)?,
            None => open_exec(fs, &path)?,
        };
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
    // A file that is open for a write does not run, and a write of the file of the program
    // fails while it runs, as `exe_file_deny_write_access` in `do_open_execat` of Linux.
    let deny = rk_vfs::file::DenyWrite::new(at.inode())?;

    let meta = at.inode().metadata();
    let nosuid = at.mount.flags() & u64::from(MS_NOSUID) != 0;
    let file = ExecFile {
        mode: meta.mode,
        uid: meta.uid,
        gid: meta.gid,
        no_setid: no_new_privs || traced || nosuid,
    };
    let old_permitted = cred.cap_permitted;
    let (cred, secure) = cred.exec(file);
    // A file with the set-user-ID bit or the set-group-ID bit, and an exec that gives more
    // capabilities, remove the flags that make the layout easy to guess, as `bprm_fill_uid` and
    // `cap_bprm_creds_from_file` of Linux.
    let setid_file = meta.mode & 0o4000 != 0 || meta.mode & 0o2010 == 0o2010;
    let per_clear =
        if (setid_file && !no_new_privs && !nosuid) || cred.cap_permitted & !old_permitted != 0 {
            PER_CLEAR_ON_SETID
        } else {
            0
        };
    let randomize = personality & !per_clear & ADDR_NO_RANDOMIZE == 0;

    let space = AddressSpace::new()?;
    // The pages of the new program go to the memory cgroup of the process.
    space.set_memcg(memcg);
    if randomize {
        space.set_mmap_offset(mmap_offset(rk_frame::arch::random_seed()));
    }
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
    let main = load_elf(&space, &at, header, Some(ET_DYN_BASE))?;
    let interp = match interp {
        Some((iat, ih)) => Some(load_elf(&space, &iat, ih, None)?),
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
    let exec_image = ExecImage { entry: start, sp: image.sp };
    Ok((space, exec_image, (at, deny), args.argv, image.auxv, cred, per_clear))
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
    let mut args = args;
    // A program gets at least one argument: an empty argument list gets an empty `argv[0]`, as
    // `do_execveat_common` in fs/exec.c of Linux.
    if args.argv.is_empty() {
        args.argv.push(Vec::new());
    }
    let process = thread.process();
    let fs = process.fs().ok_or(Errno::ESRCH)?;
    let mut ctx = fs.lock().clone();
    ctx.set_cred(process.cred());
    let path = args.path.clone();
    // A tracer cannot follow a program that gets more rights, so the bits have no effect then.
    // A tracer with `CAP_SYS_PTRACE` can, as `cap_bprm_creds_from_file` of Linux.
    let traced = thread.is_traced() && !thread.tracer_capable();
    let setid = (thread.no_new_privs(), traced);
    let personality = process.personality();
    let (space, image, (at, deny), argv, auxv, cred, per_clear) =
        build(&ctx, args, random, &process.cred(), setid, process.memcg(), personality)?;
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
    process.set_did_exec();
    // The POSIX timers go away, and the interval timers stay.
    process.timers().clear(true);
    thread.set_altstack(crate::signal::AltStack::default());
    let name = path.rsplit(|&b| b == b'/').next().unwrap_or(&path);
    // `execveat` with `AT_EMPTY_PATH` has no name, so the process keeps its name.
    if !name.is_empty() {
        process.set_comm(name);
    }
    // The dump rule of `begin_new_exec` in fs/exec.c of Linux: a program that the user cannot
    // read (`would_dump`) or that runs with another user or group ID gets `fs.suid_dumpable`.
    let readable = ctx.permission(&at, rk_vfs::cred::may::READ).is_ok();
    let dumpable = if !readable || cred.uid != cred.euid || cred.gid != cred.egid {
        crate::coredump::suid_dumpable()
    } else {
        crate::coredump::SUID_DUMP_USER
    };
    process.set_dumpable(dumpable);
    process.set_personality(personality & !per_clear);
    process.set_cred(cred);
    thread.exec_keys();
    process.set_image(&argv, at, auxv, deny);
    Ok(image)
}
