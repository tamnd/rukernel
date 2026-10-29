//! The core dump of a process that a signal ends, as `vfs_coredump` in fs/coredump.c and
//! `elf_core_dump` in fs/binfmt_elf.c of Linux.
//!
//! The thread that takes the signal stops the other threads, which keep their registers, and
//! writes an ELF core file: the ELF header, a `PT_NOTE` header and a `PT_LOAD` header for each
//! area, the notes, and then the memory of each area that `coredump_filter` selects. The file
//! goes to the path of `kernel.core_pattern`. A pattern that starts with `|` or `@` gives no
//! dump, because rukernel does not run a program or connect a socket for it. The exit status
//! gets the core dump bit only when the file was written.

use crate::ptrace::user_regs;
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::native::open::{O_CREAT, O_EXCL, O_LARGEFILE, O_NOFOLLOW, O_WRONLY};
use rk_frame::println;
use rk_frame::user::UserContext;
use rk_mm::{Backing, PAGE_SIZE, VmaKind};
use rk_proc::coredump::{
    self as cd, AreaFacts, CoreThread, DumpSize, PF_R, PF_W, PF_X, PT_LOAD, PT_NOTE, PrPsInfo,
    PrStatus, Target, nt,
};
use rk_proc::limits::RLIMIT_CORE;
use rk_proc::ptrace::NO_SYSCALL;
use rk_proc::signal::SigInfo;
use rk_proc::{Process, Thread, WaitStatus};
use rk_vfs::FileType;
use rk_vfs::file::File;

/// `e_machine` of the core file.
#[cfg(target_arch = "x86_64")]
const MACHINE: u16 = 62; // EM_X86_64
#[cfg(target_arch = "aarch64")]
const MACHINE: u16 = 183; // EM_AARCH64

/// Ends the process of `thread` for the fatal signal `info` with `status`, and writes a core
/// dump if the default action of the signal dumps core. `regs` are the registers of the
/// thread, and `syscall` is the system call that it made. Gives the exit status of the group.
pub(crate) fn fatal(
    thread: &Arc<Thread>,
    regs: &UserContext,
    syscall: Option<u64>,
    status: WaitStatus,
    info: &SigInfo,
) -> WaitStatus {
    let process = thread.process();
    if !process.may_dump(info.signo) || !rk_proc::start_core_dump(thread, status) {
        rk_proc::exit_group(thread, status);
        return process.group_exit().unwrap_or(status);
    }
    let others = process.take_core_threads();
    if dump(thread, regs, syscall, info, others) {
        process.set_core_dumped();
    }
    process.group_exit().unwrap_or(status)
}

/// Keeps the notes of `thread`, which ends while another thread of its process writes a core
/// dump, as `coredump_task_exit` in kernel/exit.c of Linux.
pub(crate) fn save_thread(thread: &Thread, regs: &UserContext) {
    let process = thread.process();
    if process.core_dumping() {
        // The signal of the dump is in the notes of the dumping thread. Linux gives each
        // thread the same `pr_cursig`, which the dumping thread fills in later, so the note here
        // has 0 and the writer sets it.
        let notes = thread_notes(&process, thread, regs, NO_SYSCALL, 0);
        process.save_core_thread(notes);
    }
}

/// Makes the `NT_PRSTATUS` and `NT_PRFPREG` descriptions of `thread`, as `fill_prstatus` and
/// `fill_thread_core_info` in fs/binfmt_elf.c of Linux.
fn thread_notes(
    process: &Process,
    thread: &Thread,
    regs: &UserContext,
    orig: u64,
    signo: u32,
) -> CoreThread {
    let leader = thread.tid() == process.pid();
    // The note of the leader has the time of the whole group.
    let (user, sys) = if leader {
        (process.user_ticks(), process.sys_ticks())
    } else {
        (thread.user_ticks(), thread.sys_ticks())
    };
    let status = PrStatus {
        signo,
        sigpend: thread.pending().0,
        sighold: thread.blocked().0,
        pid: thread.tid(),
        ppid: process.ppid(),
        pgrp: process.pgid(),
        sid: process.sid(),
        utime: timeval(user),
        stime: timeval(sys),
        cutime: timeval(process.child_ticks()),
        cstime: timeval(process.child_sys_ticks()),
    };
    CoreThread {
        prstatus: status.to_bytes(&user_regs(regs, orig, regs.flags())),
        fpregs: regs.fpu().as_bytes().to_vec(),
    }
}

/// A time in timer ticks as seconds and microseconds.
fn timeval(ticks: u64) -> cd::TimeVal {
    let hz = rk_frame::time::HZ;
    (ticks / hz, (ticks % hz) * 1_000_000 / hz)
}

/// Writes the core file. Gives `true` if the file was opened and the notes were made, as the
/// value `has_dumped` of `elf_core_dump`: a file that `RLIMIT_CORE` cuts counts too.
fn dump(
    thread: &Arc<Thread>,
    regs: &UserContext,
    syscall: Option<u64>,
    info: &SigInfo,
    others: Vec<CoreThread>,
) -> bool {
    let process = thread.process();
    let limit = process.limit(RLIMIT_CORE).cur;
    let dumpable = process.dumpable();
    let (Some(fs), Some(vm)) = (process.fs(), process.vm()) else { return false };
    let mut ctx = fs.lock().clone();
    let cred = process.cred();
    let mut file_cred = (*cred).clone();
    // A process that changed its IDs dumps as root, into an absolute path only.
    if dumpable == cd::SUID_DUMP_ROOT {
        file_cred.fsuid = 0;
    }
    ctx.set_cred(Arc::new(file_cred));
    let exe = process.exe().and_then(|at| ctx.path_of(&at).ok()).unwrap_or_default();
    let comm = process.comm();
    let hostname = rk_proc::uts::hostname();
    let pinfo = cd::PatternInfo {
        tgid: process.pid(),
        tid: thread.tid(),
        uid: cred.uid,
        gid: cred.gid,
        dumpable,
        signo: info.signo,
        time: rk_vfs::now().sec,
        hostname: rk_proc::uts::bytes(&hostname),
        comm: &comm,
        exe: &exe,
        limit,
        cpu: rk_frame::cpu::id() as u32,
    };
    let name = match cd::expand(&cd::pattern(), &pinfo, cd::uses_pid() != 0) {
        Target::File(name) => name,
        Target::Pipe | Target::Socket => {
            println!(
                "coredump: pid {}: a pipe or socket core_pattern is not supported, skipping core dump",
                process.pid()
            );
            return false;
        }
    };
    if limit < cd::MIN_COREDUMP {
        return false;
    }
    let Some(file) = open_core(&ctx, &name, dumpable) else { return false };

    // The areas and the size of each one in the file, as `dump_vma_snapshot`.
    let mask = process.coredump_filter();
    let areas = vm.areas();
    let mut page = alloc::vec![0u8; PAGE_SIZE];
    let sizes: Vec<u64> = areas
        .iter()
        .map(|v| {
            let (file_backed, unlinked) = match &v.backing {
                Backing::File { file, .. } => (true, file.name().2.ends_with(b" (deleted)")),
                Backing::Anon => (false, false),
            };
            let resident = vm.resident_pages(v.start, v.end) > 0;
            let facts = AreaFacts {
                len: v.len() as u64,
                special: matches!(v.kind, VmaKind::Vdso | VmaKind::Vvar),
                dont_dump: v.dont_dump,
                hugetlb: v.hugetlb,
                shared: v.shared,
                file: file_backed,
                unlinked,
                // Linux gives a private area an `anon_vma` at its first anonymous page. A private
                // file area gets anonymous pages only from a write.
                anon_pages: resident && (!file_backed || v.prot.write),
                head_readable: matches!(&v.backing, Backing::File { offset: 0, .. }) && v.prot.read,
            };
            match cd::vma_dump_size(&facts, mask) {
                DumpSize::Bytes(n) => n,
                DumpSize::ElfHeader => {
                    let elf = vm.dump_page(v.start, &mut page) && page.starts_with(b"\x7fELF");
                    if elf { PAGE_SIZE as u64 } else { 0 }
                }
            }
        })
        .collect();

    // The notes, as `fill_note_info` and `write_note_info`: the dumping thread first, with the
    // notes of the process after its `NT_PRSTATUS`.
    let first = thread_notes(&process, thread, regs, syscall.unwrap_or(NO_SYSCALL), info.signo);
    let mut notes = Vec::new();
    cd::push_note(&mut notes, b"CORE", nt::PRSTATUS, &first.prstatus);
    let args = process.cmdline();
    let cred_ps = PrPsInfo {
        nice: 0,
        flag: cd::PF_SIGNALED,
        uid: cred.uid,
        gid: cred.gid,
        pid: process.pid(),
        ppid: process.ppid(),
        pgrp: process.pgid(),
        sid: process.sid(),
        fname: &comm,
        args: &args,
    };
    cd::push_note(&mut notes, b"CORE", nt::PRPSINFO, &cred_ps.to_bytes());
    cd::push_note(&mut notes, b"CORE", nt::SIGINFO, &info.to_bytes());
    cd::push_note(&mut notes, b"CORE", nt::AUXV, &process.auxv());
    let names: Vec<(u64, u64, u64, Vec<u8>)> = areas
        .iter()
        .filter_map(|v| match &v.backing {
            Backing::File { file, offset } => {
                Some((v.start as u64, v.end as u64, offset / PAGE_SIZE as u64, file.name().2))
            }
            Backing::Anon => None,
        })
        .collect();
    let files: Vec<cd::FileArea<'_>> =
        names.iter().map(|(s, e, o, n)| (*s, *e, *o, n.as_slice())).collect();
    cd::push_note(&mut notes, b"CORE", nt::FILE, &cd::files_note(&files));
    cd::push_note(&mut notes, b"CORE", nt::PRFPREG, &first.fpregs);
    for t in &others {
        let mut prstatus = t.prstatus.clone();
        // `pr_info.si_signo` and `pr_cursig` have the signal of the dump in each thread.
        prstatus[..4].copy_from_slice(&info.signo.to_le_bytes());
        prstatus[12..14].copy_from_slice(&(info.signo as u16).to_le_bytes());
        cd::push_note(&mut notes, b"CORE", nt::PRSTATUS, &prstatus);
        cd::push_note(&mut notes, b"CORE", nt::PRFPREG, &t.fpregs);
    }

    // The layout of the file.
    let segs = areas.len() + 1;
    let note_off = (cd::EHDR_SIZE + segs * cd::PHDR_SIZE) as u64;
    let data_off = (note_off + notes.len() as u64).next_multiple_of(PAGE_SIZE as u64);
    let data_size: u64 = sizes.iter().sum();
    let sh_off = data_off + data_size;
    let mut head = Vec::with_capacity(note_off as usize);
    head.extend_from_slice(&cd::elf_header(MACHINE, segs, sh_off));
    head.extend_from_slice(&cd::phdr(PT_NOTE, 0, note_off, 0, notes.len() as u64, 0, 4));
    let mut off = data_off;
    for (v, &size) in areas.iter().zip(&sizes) {
        let flags = if v.prot.read { PF_R } else { 0 }
            | if v.prot.write { PF_W } else { 0 }
            | if v.prot.exec { PF_X } else { 0 };
        let len = v.len() as u64;
        head.extend_from_slice(&cd::phdr(
            PT_LOAD,
            flags,
            off,
            v.start as u64,
            size,
            len,
            PAGE_SIZE as u64,
        ));
        off += size;
    }

    let mut out = Out { file, pos: 0, written: 0, skip: 0, limit };
    let ok = 'write: {
        if !out.emit(&head) || !out.emit(&notes) {
            break 'write false;
        }
        out.skip_to(data_off);
        for (v, &size) in areas.iter().zip(&sizes) {
            for addr in (v.start..v.start + size as usize).step_by(PAGE_SIZE) {
                if vm.dump_page(addr, &mut page) {
                    if !out.emit(&page) {
                        break 'write false;
                    }
                } else {
                    out.skip += PAGE_SIZE as u64;
                }
            }
        }
        if segs >= cd::PN_XNUM && !out.emit(&cd::extnum_section(segs)) {
            break 'write false;
        }
        true
    };
    // The file gets the size of the last hole, as `coredump_write` of Linux.
    if ok && out.skip > 0 {
        out.skip -= 1;
        out.emit(&[0]);
    }
    true
}

/// Opens the core file `name`, as `coredump_file` in fs/coredump.c of Linux: the old file goes
/// away first, and the new file must be a regular file with one link that the dumping user owns
/// with the mode 0600.
fn open_core(ctx: &rk_vfs::FsContext, name: &[u8], dumpable: u8) -> Option<Arc<File>> {
    let suid_safe = dumpable == cd::SUID_DUMP_ROOT;
    if suid_safe && name.first() != Some(&b'/') {
        println!(
            "coredump: this process can only dump core to a fully qualified path, skipping core dump"
        );
        return None;
    }
    let cwd = ctx.cwd().clone();
    // A SUID dump does not remove the file of another user.
    if !suid_safe {
        let _ = ctx.remove(&cwd, name, false);
    }
    let flags = O_CREAT | O_WRONLY | O_NOFOLLOW | O_LARGEFILE | O_EXCL;
    let file = ctx.open(&cwd, name, flags, 0o600).ok()?;
    let meta = file.metadata().ok()?;
    if meta.nlink > 1
        || meta.file_type() != Some(FileType::Regular)
        || meta.uid != ctx.cred().fsuid
        || meta.mode & 0o677 != 0o600
    {
        return None;
    }
    file.truncate(0).ok()?;
    Some(file)
}

/// The position in the core file and the count of bytes written, as the fields of
/// `struct coredump_params` that `dump_emit` and `dump_skip` change.
struct Out {
    file: Arc<File>,
    pos: u64,
    written: u64,
    /// The bytes of a hole before the next write.
    skip: u64,
    limit: u64,
}

impl Out {
    /// Writes `buf` after the hole, as `dump_emit`. Gives `false` if the write is past
    /// `RLIMIT_CORE` or fails. A hole does not count for the limit.
    fn emit(&mut self, buf: &[u8]) -> bool {
        self.pos += core::mem::take(&mut self.skip);
        let len = buf.len() as u64;
        if self.written.saturating_add(len) > self.limit {
            return false;
        }
        if self.file.write_at(self.pos, buf) != Ok(buf.len()) {
            return false;
        }
        self.pos += len;
        self.written += len;
        true
    }

    /// Makes a hole up to `pos`, as `dump_skip_to`.
    fn skip_to(&mut self, pos: u64) {
        self.skip = pos.saturating_sub(self.pos);
    }
}
