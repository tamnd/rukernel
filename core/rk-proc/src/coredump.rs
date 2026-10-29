//! The settings of core dumps and the parts of the ELF core file, as fs/coredump.c and
//! fs/binfmt_elf.c (`elf_core_dump`) of Linux.
//!
//! This module keeps `kernel.core_pattern`, `kernel.core_uses_pid` and `fs.suid_dumpable`,
//! expands the pattern to the name of the core file, and makes the ELF header, the program
//! headers and the notes. The code is pure, so the tests on the host examine it. rk-syscall
//! stops the threads, reads the memory and writes the file.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

/// The most bytes of `core_pattern` with the null byte, `CORENAME_MAX_SIZE` of Linux.
pub const CORENAME_MAX_SIZE: usize = 128;

/// The value of `dumpable` that allows no core dump, `SUID_DUMP_DISABLE` of Linux.
pub const SUID_DUMP_DISABLE: u8 = 0;
/// The value of `dumpable` that allows a core dump that the user owns, `SUID_DUMP_USER`.
pub const SUID_DUMP_USER: u8 = 1;
/// The value of `dumpable` that allows a core dump that root owns, to an absolute path only,
/// `SUID_DUMP_ROOT`.
pub const SUID_DUMP_ROOT: u8 = 2;

/// The smallest `RLIMIT_CORE` that gives a file, `min_coredump` of `elf_format` in
/// fs/binfmt_elf.c of Linux.
pub const MIN_COREDUMP: u64 = 4096;

/// `core_pattern`, with its length. The text has no null byte.
static PATTERN: SpinLock<([u8; CORENAME_MAX_SIZE], usize)> = SpinLock::new(default_pattern());

/// `core_uses_pid`.
static USES_PID: AtomicI32 = AtomicI32::new(0);

/// `fs.suid_dumpable`: the `dumpable` value of a process after a change of its credentials.
static SUID_DUMPABLE: AtomicU32 = AtomicU32::new(0);

const fn default_pattern() -> ([u8; CORENAME_MAX_SIZE], usize) {
    let mut p = [0u8; CORENAME_MAX_SIZE];
    p[0] = b'c';
    p[1] = b'o';
    p[2] = b'r';
    p[3] = b'e';
    (p, 4)
}

/// The value of `kernel.core_pattern`.
pub fn pattern() -> Vec<u8> {
    let p = PATTERN.lock();
    p.0[..p.1].to_vec()
}

/// Sets `kernel.core_pattern` from the bytes of a write, as `proc_dostring_coredump` in
/// fs/coredump.c of Linux. The text ends at a newline or a null byte, and only the first 127
/// bytes count.
///
/// # Errors
///
/// `EINVAL` for a socket pattern (`@`) that `check_coredump_socket` refuses. The old value
/// stays then.
pub fn set_pattern(data: &[u8]) -> Result<(), Errno> {
    let end = data.iter().position(|&b| b == b'\n' || b == 0).unwrap_or(data.len());
    let text = &data[..end.min(CORENAME_MAX_SIZE - 1)];
    if !socket_ok(text) {
        return Err(Errno::EINVAL);
    }
    let mut p = PATTERN.lock();
    p.0 = [0; CORENAME_MAX_SIZE];
    p.0[..text.len()].copy_from_slice(text);
    p.1 = text.len();
    Ok(())
}

/// Checks a socket pattern, as `check_coredump_socket` in fs/coredump.c of Linux: `@` or `@@`
/// and then an absolute path that is shorter than `UNIX_PATH_MAX` and has no `..`.
fn socket_ok(p: &[u8]) -> bool {
    let Some(rest) = p.strip_prefix(b"@") else { return true };
    let path = rest.strip_prefix(b"@").unwrap_or(rest);
    path.first() == Some(&b'/')
        && path.len() < 108
        && !path.split(|&b| b == b'/').any(|c| c == b"..")
}

/// The value of `kernel.core_uses_pid`.
pub fn uses_pid() -> i32 {
    USES_PID.load(Ordering::Relaxed)
}

/// Sets `kernel.core_uses_pid`. Linux takes each `int`, and each value that is not 0 is on.
pub fn set_uses_pid(value: i32) {
    USES_PID.store(value, Ordering::Relaxed);
}

/// The value of `fs.suid_dumpable`.
pub fn suid_dumpable() -> u8 {
    SUID_DUMPABLE.load(Ordering::Relaxed) as u8
}

/// Sets `fs.suid_dumpable`.
///
/// # Errors
///
/// `EINVAL` for a value larger than 2, as `proc_dointvec_minmax_coredump` of Linux.
pub fn set_suid_dumpable(value: u32) -> Result<(), Errno> {
    if value > u32::from(SUID_DUMP_ROOT) {
        return Err(Errno::EINVAL);
    }
    SUID_DUMPABLE.store(value, Ordering::Relaxed);
    Ok(())
}

/// The facts that the specifiers of `core_pattern` give.
#[derive(Clone, Copy, Debug, Default)]
pub struct PatternInfo<'a> {
    /// `%p` and `%P`: the process ID.
    pub tgid: u32,
    /// `%i` and `%I`: the thread ID.
    pub tid: u32,
    /// `%u`: the real user ID.
    pub uid: u32,
    /// `%g`: the real group ID.
    pub gid: u32,
    /// `%d`: the `dumpable` value.
    pub dumpable: u8,
    /// `%s`: the signal.
    pub signo: u32,
    /// `%t`: the time in seconds since the epoch.
    pub time: i64,
    /// `%h`: the host name.
    pub hostname: &'a [u8],
    /// `%e`: the name of the thread (`comm`).
    pub comm: &'a [u8],
    /// `%E`: the path of the program. `%f` is the last part of it.
    pub exe: &'a [u8],
    /// `%c`: the soft `RLIMIT_CORE`.
    pub limit: u64,
    /// `%C`: the CPU.
    pub cpu: u32,
}

/// Where the core dump goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// A file with this path.
    File(Vec<u8>),
    /// A pattern that starts with `|`: a program gets the dump on its standard input.
    /// rukernel does not run it, and makes no dump.
    Pipe,
    /// A pattern that starts with `@`: a socket gets the dump. rukernel makes no dump.
    Socket,
}

/// Expands `pattern` to the target of the dump, as `coredump_parse` in fs/coredump.c of Linux.
/// `uses_pid` is `core_uses_pid`: a file pattern without `%p` then gets `.PID` at the end.
pub fn expand(pattern: &[u8], info: &PatternInfo<'_>, uses_pid: bool) -> Target {
    match pattern.first() {
        Some(b'|') => return Target::Pipe,
        Some(b'@') => return Target::Socket,
        _ => {}
    }
    let mut out = Vec::new();
    let mut pid_in_pattern = false;
    let mut i = 0;
    while i < pattern.len() {
        let c = pattern[i];
        i += 1;
        if c != b'%' {
            out.push(c);
            continue;
        }
        // A single `%` at the end goes away.
        let Some(&spec) = pattern.get(i) else { break };
        i += 1;
        match spec {
            b'%' => out.push(b'%'),
            b'p' | b'P' => {
                pid_in_pattern |= spec == b'p';
                push_num(&mut out, u64::from(info.tgid));
            }
            b'i' | b'I' => push_num(&mut out, u64::from(info.tid)),
            b'u' => push_num(&mut out, u64::from(info.uid)),
            b'g' => push_num(&mut out, u64::from(info.gid)),
            b'd' => push_num(&mut out, u64::from(info.dumpable)),
            b's' => push_num(&mut out, u64::from(info.signo)),
            b't' => {
                if info.time < 0 {
                    out.push(b'-');
                }
                push_num(&mut out, info.time.unsigned_abs());
            }
            b'h' => push_escaped(&mut out, info.hostname),
            b'e' => push_escaped(&mut out, info.comm),
            b'f' => {
                let name = info.exe.rsplit(|&b| b == b'/').next().unwrap_or(info.exe);
                push_escaped(&mut out, name);
            }
            b'E' => push_escaped(&mut out, info.exe),
            b'c' => push_num(&mut out, info.limit),
            b'C' => push_num(&mut out, u64::from(info.cpu)),
            // `%F` gives a pidfd only to a pipe program, and each other letter gives nothing.
            _ => {}
        }
    }
    if uses_pid && !pid_in_pattern {
        out.push(b'.');
        push_num(&mut out, u64::from(info.tgid));
    }
    Target::File(out)
}

fn push_num(out: &mut Vec<u8>, mut n: u64) {
    let mut digits = [0u8; 20];
    let mut len = 0;
    loop {
        digits[len] = b'0' + (n % 10) as u8;
        len += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend(digits[..len].iter().rev());
}

/// Adds a part of the name that comes from a name of the process or the host, as
/// `cn_esc_printf` of Linux: a part `.` or `..` gets `!` for its first byte, an empty part is
/// `!`, and each `/` becomes `!`. So the part cannot change the directory of the file.
fn push_escaped(out: &mut Vec<u8>, part: &[u8]) {
    let cur = out.len();
    out.extend_from_slice(part);
    if part == b"." || part == b".." {
        out[cur] = b'!';
    }
    if part.is_empty() {
        out.push(b'!');
    }
    for b in &mut out[cur..] {
        if *b == b'/' {
            *b = b'!';
        }
    }
}

/// Tells if a credential change makes the process not dumpable, as `commit_creds` in
/// kernel/cred.c of Linux: a change of the effective or file system user or group ID, or new
/// permitted capabilities.
pub fn cred_change_drops_dumpable(
    old_ids: [u32; 4],
    new_ids: [u32; 4],
    old_permitted: u64,
    new_permitted: u64,
) -> bool {
    old_ids != new_ids || new_permitted & !old_permitted != 0
}

/// The note types of the core file.
pub mod nt {
    /// `NT_PRSTATUS`: `struct elf_prstatus` of a thread.
    pub const PRSTATUS: u32 = 1;
    /// `NT_PRFPREG`: the floating point registers of a thread.
    pub const PRFPREG: u32 = 2;
    /// `NT_PRPSINFO`: `struct elf_prpsinfo` of the process.
    pub const PRPSINFO: u32 = 3;
    /// `NT_AUXV`: the auxiliary vector.
    pub const AUXV: u32 = 6;
    /// `NT_SIGINFO`: the `siginfo_t` of the signal.
    pub const SIGINFO: u32 = 0x5349_4749;
    /// `NT_FILE`: the files that the process maps.
    pub const FILE: u32 = 0x4649_4c45;
}

/// The size of the ELF header of a 64 bit file.
pub const EHDR_SIZE: usize = 64;
/// The size of a program header of a 64 bit file.
pub const PHDR_SIZE: usize = 56;
/// The size of a section header of a 64 bit file.
pub const SHDR_SIZE: usize = 64;
/// `PN_XNUM`: the program header count does not fit in `e_phnum`, and the section header 0
/// has it.
pub const PN_XNUM: usize = 0xffff;

/// `PT_LOAD`.
pub const PT_LOAD: u32 = 1;
/// `PT_NOTE`.
pub const PT_NOTE: u32 = 4;
/// `PF_X`, `PF_W` and `PF_R`.
pub const PF_X: u32 = 1;
/// `PF_W`.
pub const PF_W: u32 = 2;
/// `PF_R`.
pub const PF_R: u32 = 4;

fn put16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// The ELF header of a core file, as `fill_elf_header` in fs/binfmt_elf.c of Linux. `segs` is
/// the count of program headers. With `PN_XNUM` or more, `e_phnum` is `PN_XNUM`, and the one
/// section header at `shoff` has the count, as `fill_extnum_info`.
pub fn elf_header(machine: u16, segs: usize, shoff: u64) -> [u8; EHDR_SIZE] {
    let mut h = [0u8; EHDR_SIZE];
    h[..4].copy_from_slice(b"\x7fELF");
    h[4] = 2; // ELFCLASS64
    h[5] = 1; // ELFDATA2LSB
    h[6] = 1; // EV_CURRENT
    put16(&mut h, 16, 4); // ET_CORE
    put16(&mut h, 18, machine);
    put32(&mut h, 20, 1); // EV_CURRENT
    put64(&mut h, 32, EHDR_SIZE as u64); // e_phoff
    put16(&mut h, 52, EHDR_SIZE as u16); // e_ehsize
    put16(&mut h, 54, PHDR_SIZE as u16); // e_phentsize
    put16(&mut h, 56, segs.min(PN_XNUM) as u16); // e_phnum
    if segs >= PN_XNUM {
        put64(&mut h, 40, shoff); // e_shoff
        put16(&mut h, 58, SHDR_SIZE as u16); // e_shentsize
        put16(&mut h, 60, 1); // e_shnum
    }
    h
}

/// The section header that has the program header count when it is `PN_XNUM` or more, as
/// `fill_extnum_info` in fs/binfmt_elf.c of Linux.
pub fn extnum_section(segs: usize) -> [u8; SHDR_SIZE] {
    let mut s = [0u8; SHDR_SIZE];
    put32(&mut s, 40, segs as u32); // sh_info
    s
}

/// A program header of a core file.
pub fn phdr(
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
) -> [u8; PHDR_SIZE] {
    let mut p = [0u8; PHDR_SIZE];
    put32(&mut p, 0, kind);
    put32(&mut p, 4, flags);
    put64(&mut p, 8, offset);
    put64(&mut p, 16, vaddr);
    put64(&mut p, 32, filesz);
    put64(&mut p, 40, memsz);
    put64(&mut p, 48, align);
    p
}

/// Adds a note to `out`, as `writenote` in fs/binfmt_elf.c of Linux: the 12 byte header, the
/// name with its null byte and the description, each padded to 4 bytes.
pub fn push_note(out: &mut Vec<u8>, name: &[u8], kind: u32, desc: &[u8]) {
    let mut h = [0u8; 12];
    put32(&mut h, 0, name.len() as u32 + 1);
    put32(&mut h, 4, desc.len() as u32);
    put32(&mut h, 8, kind);
    out.extend_from_slice(&h);
    out.extend_from_slice(name);
    out.push(0);
    pad4(out);
    out.extend_from_slice(desc);
    pad4(out);
}

fn pad4(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// A time as `struct __kernel_old_timeval`: seconds and microseconds.
pub type TimeVal = (u64, u64);

/// The facts of `struct elf_prstatus` of one thread, as `fill_prstatus` in fs/binfmt_elf.c of
/// Linux.
#[derive(Clone, Copy, Debug, Default)]
pub struct PrStatus {
    /// The signal of the dump: `pr_info.si_signo` and `pr_cursig`.
    pub signo: u32,
    /// The first word of the pending signals of the thread.
    pub sigpend: u64,
    /// The first word of the blocked signals of the thread.
    pub sighold: u64,
    /// The thread ID.
    pub pid: u32,
    /// The process ID of the parent.
    pub ppid: u32,
    /// The process group.
    pub pgrp: u32,
    /// The session.
    pub sid: u32,
    /// The user time.
    pub utime: TimeVal,
    /// The system time.
    pub stime: TimeVal,
    /// The user time of the children that a wait reaped.
    pub cutime: TimeVal,
    /// The system time of the children that a wait reaped.
    pub cstime: TimeVal,
}

impl PrStatus {
    /// The bytes of `struct elf_prstatus` with the registers `regs` (`elf_gregset_t`). The
    /// size is 336 bytes with the 27 registers of x86-64 and 392 bytes with the 34 registers of
    /// arm64. `pr_fpvalid` is 1, because the floating point note follows.
    pub fn to_bytes(&self, regs: &[u64]) -> Vec<u8> {
        let regs_end = 112 + regs.len() * 8;
        let size = (regs_end + 4).next_multiple_of(8);
        let mut b = alloc::vec![0u8; size];
        put32(&mut b, 0, self.signo); // pr_info.si_signo
        put16(&mut b, 12, self.signo as u16); // pr_cursig
        put64(&mut b, 16, self.sigpend);
        put64(&mut b, 24, self.sighold);
        put32(&mut b, 32, self.pid);
        put32(&mut b, 36, self.ppid);
        put32(&mut b, 40, self.pgrp);
        put32(&mut b, 44, self.sid);
        for (i, t) in [self.utime, self.stime, self.cutime, self.cstime].iter().enumerate() {
            put64(&mut b, 48 + i * 16, t.0);
            put64(&mut b, 56 + i * 16, t.1);
        }
        for (i, r) in regs.iter().enumerate() {
            put64(&mut b, 112 + i * 8, *r);
        }
        put32(&mut b, regs_end, 1); // pr_fpvalid
        b
    }
}

/// The size of `struct elf_prpsinfo` on a 64 bit machine.
pub const PRPSINFO_SIZE: usize = 136;

/// `PF_SIGNALED` of `task_struct.flags`: a signal ends the task. `get_signal` sets it before
/// the dump.
pub const PF_SIGNALED: u64 = 0x400;

/// The facts of `struct elf_prpsinfo`, as `fill_psinfo` in fs/binfmt_elf.c of Linux.
#[derive(Clone, Copy, Debug, Default)]
pub struct PrPsInfo<'a> {
    /// The nice value.
    pub nice: i8,
    /// `pr_flag`: the flags of the task.
    pub flag: u64,
    /// The real user ID.
    pub uid: u32,
    /// The real group ID.
    pub gid: u32,
    /// The process ID.
    pub pid: u32,
    /// The process ID of the parent.
    pub ppid: u32,
    /// The process group.
    pub pgrp: u32,
    /// The session.
    pub sid: u32,
    /// The name of the thread (`comm`).
    pub fname: &'a [u8],
    /// The command line, with a null byte after each argument.
    pub args: &'a [u8],
}

impl PrPsInfo<'_> {
    /// The bytes of `struct elf_prpsinfo`. The task runs, so the state is 0 and `R`. The
    /// command line has at most 79 bytes, and each null byte in it becomes a space.
    pub fn to_bytes(&self) -> [u8; PRPSINFO_SIZE] {
        let mut b = [0u8; PRPSINFO_SIZE];
        b[1] = b'R'; // pr_sname
        b[3] = self.nice as u8;
        put64(&mut b, 8, self.flag);
        put32(&mut b, 16, self.uid);
        put32(&mut b, 20, self.gid);
        put32(&mut b, 24, self.pid);
        put32(&mut b, 28, self.ppid);
        put32(&mut b, 32, self.pgrp);
        put32(&mut b, 36, self.sid);
        let n = self.fname.len().min(15);
        b[40..40 + n].copy_from_slice(&self.fname[..n]);
        let n = self.args.len().min(79);
        for (d, &s) in b[56..56 + n].iter_mut().zip(&self.args[..n]) {
            *d = if s == 0 { b' ' } else { s };
        }
        b
    }
}

/// One file area for the `NT_FILE` note: the start, the end, the offset in the file in pages,
/// and the path.
pub type FileArea<'a> = (u64, u64, u64, &'a [u8]);

/// The description of the `NT_FILE` note, as `fill_files_note` in fs/binfmt_elf.c of Linux: the
/// count, the page size, three words for each area, and then the paths with null bytes.
pub fn files_note(areas: &[FileArea<'_>]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&(areas.len() as u64).to_le_bytes());
    b.extend_from_slice(&4096u64.to_le_bytes());
    for (start, end, pgoff, _) in areas {
        b.extend_from_slice(&start.to_le_bytes());
        b.extend_from_slice(&end.to_le_bytes());
        b.extend_from_slice(&pgoff.to_le_bytes());
    }
    for (_, _, _, name) in areas {
        b.extend_from_slice(name);
        b.push(0);
    }
    b
}

/// The notes of a thread that is not the dumping thread, which it saves before it exits: the
/// description of `NT_PRSTATUS` and of `NT_PRFPREG`.
#[derive(Clone, Debug, Default)]
pub struct CoreThread {
    /// The bytes of `struct elf_prstatus`.
    pub prstatus: Vec<u8>,
    /// The floating point registers.
    pub fpregs: Vec<u8>,
}

/// The `bits` of `/proc/PID/coredump_filter`, `MMF_DUMP_*` of Linux.
pub mod filter {
    /// Anonymous private memory.
    pub const ANON_PRIVATE: u32 = 1 << 0;
    /// Anonymous shared memory.
    pub const ANON_SHARED: u32 = 1 << 1;
    /// Private file mappings.
    pub const MAPPED_PRIVATE: u32 = 1 << 2;
    /// Shared file mappings.
    pub const MAPPED_SHARED: u32 = 1 << 3;
    /// The first page of an ELF file mapping.
    pub const ELF_HEADERS: u32 = 1 << 4;
    /// Private hugetlb memory.
    pub const HUGETLB_PRIVATE: u32 = 1 << 5;
    /// Shared hugetlb memory.
    pub const HUGETLB_SHARED: u32 = 1 << 6;
}

/// The facts of an area that decide its dump size.
#[derive(Clone, Copy, Debug, Default)]
pub struct AreaFacts {
    /// The size of the area.
    pub len: u64,
    /// The vDSO or its data page, which each dump holds.
    pub special: bool,
    /// `MADV_DONTDUMP`.
    pub dont_dump: bool,
    /// A hugetlb area.
    pub hugetlb: bool,
    /// `MAP_SHARED`.
    pub shared: bool,
    /// The area maps a file.
    pub file: bool,
    /// The file has no name in the file system: shared anonymous memory, System V shared
    /// memory or a removed file (`i_nlink == 0`).
    pub unlinked: bool,
    /// The private area has anonymous pages (`vma->anon_vma`).
    pub anon_pages: bool,
    /// The area maps the start of the file and allows a read.
    pub head_readable: bool,
}

/// What the dump holds of an area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DumpSize {
    /// This many bytes from the start.
    Bytes(u64),
    /// The first page if it starts with the ELF magic, else nothing.
    ElfHeader,
}

/// The size of the part of an area that the dump holds, as `vma_dump_size` in fs/coredump.c of
/// Linux.
pub fn vma_dump_size(a: &AreaFacts, mask: u32) -> DumpSize {
    use filter::*;
    let on = |bit: u32| mask & bit != 0;
    let whole = DumpSize::Bytes(a.len);
    if a.special {
        return whole;
    }
    if a.dont_dump {
        return DumpSize::Bytes(0);
    }
    if a.hugetlb {
        let bit = if a.shared { HUGETLB_SHARED } else { HUGETLB_PRIVATE };
        return if on(bit) { whole } else { DumpSize::Bytes(0) };
    }
    if a.shared {
        let bit = if a.unlinked { ANON_SHARED } else { MAPPED_SHARED };
        return if on(bit) { whole } else { DumpSize::Bytes(0) };
    }
    if a.anon_pages && on(ANON_PRIVATE) {
        return whole;
    }
    if !a.file {
        return DumpSize::Bytes(0);
    }
    if on(MAPPED_PRIVATE) {
        return whole;
    }
    if on(ELF_HEADERS) && a.head_readable {
        return DumpSize::ElfHeader;
    }
    DumpSize::Bytes(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> PatternInfo<'static> {
        PatternInfo {
            tgid: 42,
            tid: 43,
            uid: 1000,
            gid: 100,
            dumpable: 1,
            signo: 6,
            time: 1_700_000_000,
            hostname: b"host",
            comm: b"prog",
            exe: b"/usr/bin/prog",
            limit: 512,
            cpu: 3,
        }
    }

    fn file(p: &[u8], uses_pid: bool) -> Vec<u8> {
        match expand(p, &info(), uses_pid) {
            Target::File(f) => f,
            t => panic!("not a file: {t:?}"),
        }
    }

    #[test]
    fn expands_each_specifier() {
        assert_eq!(file(b"core", false), b"core");
        assert_eq!(file(b"/tmp/dump-%p", false), b"/tmp/dump-42");
        assert_eq!(file(b"%e.%t.%u.%g.%s.%h.%%", false), b"prog.1700000000.1000.100.6.host.%");
        assert_eq!(file(b"%i-%P-%I-%d-%c-%C", false), b"43-42-43-1-512-3");
        assert_eq!(file(b"%f|%E", false), b"prog|!usr!bin!prog");
        // An unknown letter gives nothing, and a single `%` at the end goes away.
        assert_eq!(file(b"a%zb%", false), b"ab");
    }

    #[test]
    fn core_uses_pid_adds_the_pid() {
        assert_eq!(file(b"core", true), b"core.42");
        assert_eq!(file(b"core-%p", true), b"core-42");
        // `%P` is not `%p`, so the PID comes again, as Linux.
        assert_eq!(file(b"core-%P", true), b"core-42.42");
    }

    #[test]
    fn escapes_names() {
        let mut i = info();
        i.comm = b"..";
        assert_eq!(expand(b"%e", &i, false), Target::File(b"!.".to_vec()));
        i.comm = b".";
        assert_eq!(expand(b"x/%e", &i, false), Target::File(b"x/!".to_vec()));
        i.comm = b"";
        assert_eq!(expand(b"%e", &i, false), Target::File(b"!".to_vec()));
        i.comm = b"a/b";
        assert_eq!(expand(b"%e", &i, false), Target::File(b"a!b".to_vec()));
    }

    #[test]
    fn pipe_and_socket_patterns() {
        assert_eq!(expand(b"|/bin/handler %p", &info(), true), Target::Pipe);
        assert_eq!(expand(b"@/run/core.sock", &info(), true), Target::Socket);
        assert!(socket_ok(b"@/run/core.sock"));
        assert!(socket_ok(b"@@/run/core.sock"));
        assert!(!socket_ok(b"@run/core.sock"));
        assert!(!socket_ok(b"@/run/../core.sock"));
        assert!(socket_ok(b"core"));
    }

    #[test]
    fn dump_size_follows_the_filter() {
        let anon = AreaFacts { len: 8192, anon_pages: true, ..Default::default() };
        assert_eq!(vma_dump_size(&anon, 0x33), DumpSize::Bytes(8192));
        assert_eq!(vma_dump_size(&anon, 0x32), DumpSize::Bytes(0));
        let dont = AreaFacts { dont_dump: true, ..anon };
        assert_eq!(vma_dump_size(&dont, 0x33), DumpSize::Bytes(0));
        let vdso = AreaFacts { special: true, dont_dump: true, ..anon };
        assert_eq!(vma_dump_size(&vdso, 0), DumpSize::Bytes(8192));
        let text = AreaFacts { len: 8192, file: true, head_readable: true, ..Default::default() };
        assert_eq!(vma_dump_size(&text, 0x33), DumpSize::ElfHeader);
        assert_eq!(vma_dump_size(&text, 0x37), DumpSize::Bytes(8192));
        let shm =
            AreaFacts { len: 4096, file: true, shared: true, unlinked: true, ..Default::default() };
        assert_eq!(vma_dump_size(&shm, 0x33), DumpSize::Bytes(4096));
        let shared = AreaFacts { unlinked: false, ..shm };
        assert_eq!(vma_dump_size(&shared, 0x33), DumpSize::Bytes(0));
    }

    #[test]
    fn note_layout() {
        let mut out = Vec::new();
        push_note(&mut out, b"CORE", nt::AUXV, &[1, 2, 3]);
        assert_eq!(out.len(), 12 + 8 + 4);
        assert_eq!(&out[..12], &[5, 0, 0, 0, 3, 0, 0, 0, 6, 0, 0, 0]);
        assert_eq!(&out[12..17], b"CORE\0");
        let st = PrStatus { signo: 11, pid: 7, ..Default::default() };
        assert_eq!(st.to_bytes(&[0; 27]).len(), 336);
        assert_eq!(st.to_bytes(&[0; 34]).len(), 392);
        let ps = PrPsInfo { fname: b"prog", args: b"prog\0-x\0", ..Default::default() };
        let b = ps.to_bytes();
        assert_eq!(&b[40..45], b"prog\0");
        assert_eq!(&b[56..64], b"prog -x ");
        let h = elf_header(62, 3, 0);
        assert_eq!(&h[16..20], &[4, 0, 62, 0]);
        assert_eq!(h[56], 3);
        let f = files_note(&[(0x1000, 0x2000, 0, b"/bin/a")]);
        assert_eq!(f.len(), 16 + 24 + 7);
    }
}
