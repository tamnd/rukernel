use crate::elf::{self, ElfType, SegmentFlags};
use crate::signal::{
    AltStack, CLD_EXITED, DefaultAction, Pending, SEGV_MAPERR, SI_QUEUE, SI_USER, SIG_IGN,
    SS_DISABLE, SS_ONSTACK, SigAction, SigInfo, SigSet, default_action,
};
use crate::stack::{self, StackArgs};
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;

const EM: u16 = 62;

/// Makes the headers of an ELF file with the program headers `phdrs`: (type, flags, offset,
/// vaddr, filesz, memsz).
fn elf_file(kind: u16, phdrs: &[(u32, u32, u64, u64, u64, u64)]) -> (Vec<u8>, Vec<u8>) {
    let mut e = vec![0u8; 64];
    e[..4].copy_from_slice(b"\x7fELF");
    e[4] = 2;
    e[5] = 1;
    e[6] = 1;
    e[16..18].copy_from_slice(&kind.to_le_bytes());
    e[18..20].copy_from_slice(&EM.to_le_bytes());
    e[24..32].copy_from_slice(&0x40_1000u64.to_le_bytes());
    e[32..40].copy_from_slice(&64u64.to_le_bytes());
    e[54..56].copy_from_slice(&56u16.to_le_bytes());
    e[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());
    let mut p = Vec::new();
    for &(t, f, off, va, fsz, msz) in phdrs {
        let mut h = vec![0u8; 56];
        h[0..4].copy_from_slice(&t.to_le_bytes());
        h[4..8].copy_from_slice(&f.to_le_bytes());
        h[8..16].copy_from_slice(&off.to_le_bytes());
        h[16..24].copy_from_slice(&va.to_le_bytes());
        h[32..40].copy_from_slice(&fsz.to_le_bytes());
        h[40..48].copy_from_slice(&msz.to_le_bytes());
        h[48..56].copy_from_slice(&0x1000u64.to_le_bytes());
        p.extend(h);
    }
    (e, p)
}

#[test]
fn elf_static_executable() {
    let (e, p) = elf_file(
        2,
        &[
            (1, 5, 0, 0x40_0000, 0x1234, 0x1234),
            (1, 6, 0x2000, 0x40_3000, 0x100, 0x5000),
            (0x6474_e551, 6, 0, 0, 0, 0),
        ],
    );
    let h = elf::parse(&e, &p, EM).unwrap();
    assert_eq!(h.kind, ElfType::Exec);
    assert_eq!(h.entry, 0x40_1000);
    assert_eq!(h.segments.len(), 2);
    assert_eq!(h.segments[0].flags, SegmentFlags { read: true, write: false, exec: true });
    assert_eq!(h.segments[1].flags, SegmentFlags { read: true, write: true, exec: false });
    assert_eq!(h.span(), (0x40_0000, 0x40_8000));
    assert!(!h.exec_stack);
    assert_eq!(h.interp, None);
    // The headers are in the first segment.
    assert_eq!(h.phdr_addr(), Some(0x40_0040));
}

#[test]
fn elf_pie_with_interpreter() {
    let (e, p) = elf_file(
        3,
        &[(6, 4, 64, 64, 56 * 3, 56 * 3), (3, 4, 0x300, 0x300, 28, 28), (1, 5, 0, 0, 0x800, 0x800)],
    );
    let h = elf::parse(&e, &p, EM).unwrap();
    assert_eq!(h.kind, ElfType::Dyn);
    assert_eq!(h.interp, Some((0x300, 28)));
    assert_eq!(h.phdr_addr(), Some(64));
}

#[test]
fn elf_errors() {
    let (e, p) = elf_file(2, &[(1, 5, 0, 0x40_0000, 0x10, 0x10)]);
    assert_eq!(elf::parse(&e, &p, 183).unwrap_err(), Errno::ENOEXEC);
    let mut bad = e.clone();
    bad[4] = 1;
    assert_eq!(elf::parse(&bad, &p, EM).unwrap_err(), Errno::ENOEXEC);
    let mut core = e.clone();
    core[16] = 4;
    assert_eq!(elf::parse(&core, &p, EM).unwrap_err(), Errno::ENOEXEC);
    assert_eq!(elf::parse(&e[..63], &p, EM).unwrap_err(), Errno::ENOEXEC);
    assert_eq!(elf::parse(&e, &p[..55], EM).unwrap_err(), Errno::ENOEXEC);
    // A segment with more file bytes than memory bytes.
    let (e2, p2) = elf_file(2, &[(1, 5, 0, 0x40_0000, 0x20, 0x10)]);
    assert_eq!(elf::parse(&e2, &p2, EM).unwrap_err(), Errno::EINVAL);
    // An address and an offset that are not the same modulo the page size.
    let (e3, p3) = elf_file(2, &[(1, 5, 0x10, 0x40_0000, 0x10, 0x10)]);
    assert_eq!(elf::parse(&e3, &p3, EM).unwrap_err(), Errno::EINVAL);
    // No segment to load.
    let (e4, p4) = elf_file(2, &[(4, 4, 0, 0, 0, 0)]);
    assert_eq!(elf::parse(&e4, &p4, EM).unwrap_err(), Errno::ENOEXEC);
    assert!(!elf::is_elf(b"#!/bin/sh"));
}

fn word(img: &stack::StackImage, addr: usize) -> u64 {
    let at = addr - img.sp;
    u64::from_le_bytes(img.bytes[at..at + 8].try_into().unwrap())
}

fn cstr(img: &stack::StackImage, top: usize, addr: u64) -> Vec<u8> {
    let at = addr as usize - img.sp;
    assert!((addr as usize) < top);
    let end = img.bytes[at..].iter().position(|&b| b == 0).unwrap();
    img.bytes[at..at + end].to_vec()
}

#[test]
fn initial_stack_layout() {
    let top = 0x7fff_ffff_f000;
    let argv = vec![b"/bin/prog".to_vec(), b"-x".to_vec()];
    let envp = vec![b"HOME=/".to_vec()];
    let args = StackArgs {
        argv: &argv,
        envp: &envp,
        execfn: b"/bin/prog",
        platform: b"x86_64",
        random: [7; 16],
        auxv: &[(6, 4096)],
    };
    let img = stack::build(top, &args).unwrap();
    assert_eq!(img.sp % 16, 0);
    assert_eq!(img.sp + img.bytes.len(), top);
    assert_eq!(word(&img, img.sp), 2);
    assert_eq!(cstr(&img, top, word(&img, img.sp + 8)), b"/bin/prog");
    assert_eq!(cstr(&img, top, word(&img, img.sp + 16)), b"-x");
    assert_eq!(word(&img, img.sp + 24), 0);
    assert_eq!(cstr(&img, top, word(&img, img.sp + 32)), b"HOME=/");
    assert_eq!(word(&img, img.sp + 40), 0);
    // The auxiliary vector: the entry of the caller, then AT_RANDOM, AT_EXECFN, AT_PLATFORM and
    // AT_NULL.
    let aux = img.sp + 48;
    assert_eq!((word(&img, aux), word(&img, aux + 8)), (6, 4096));
    assert_eq!(word(&img, aux + 16), 25);
    let random = word(&img, aux + 24) as usize;
    assert_eq!(random % 16, 0);
    assert_eq!(&img.bytes[random - img.sp..random - img.sp + 16], &[7; 16]);
    assert_eq!(word(&img, aux + 32), 31);
    assert_eq!(cstr(&img, top, word(&img, aux + 40)), b"/bin/prog");
    assert_eq!(word(&img, aux + 48), 15);
    assert_eq!(cstr(&img, top, word(&img, aux + 56)), b"x86_64");
    assert_eq!((word(&img, aux + 64), word(&img, aux + 72)), (0, 0));
    // The copy for /proc/PID/auxv has the same words.
    assert_eq!(img.auxv, img.bytes[aux - img.sp..aux - img.sp + 80]);
    // The path is the highest string, below the null pointer at the top.
    assert_eq!(&img.bytes[img.bytes.len() - 8..], &[0; 8]);
}

#[test]
fn initial_stack_limits() {
    let long = vec![vec![b'a'; stack::MAX_ARG_STRLEN]];
    assert_eq!(stack::args_size(&long, &[]), Err(Errno::E2BIG));
    let many = vec![vec![b'a'; 1000]; 3000];
    assert_eq!(stack::args_size(&many, &[]), Err(Errno::E2BIG));
    assert_eq!(stack::args_size(&[b"ab".to_vec()], &[b"c".to_vec()]), Ok(3 + 8 + 2 + 8));
}

#[test]
fn sigset_next_gives_synchronous_signals_first() {
    use rk_abi::native::signal::{SIGINT, SIGKILL, SIGSEGV, SIGTERM, SIGUSR1};
    let mut set = SigSet::EMPTY;
    assert_eq!(set.next(), None);
    set.add(SIGTERM);
    set.add(SIGUSR1);
    assert_eq!(set.next(), Some(SIGUSR1));
    set.add(SIGSEGV);
    assert_eq!(set.next(), Some(SIGSEGV));
    set.add(SIGINT);
    assert_eq!(set.without(SigSet(SigSet::bit(SIGSEGV))).next(), Some(SIGINT));
    assert!(SigSet::UNBLOCKABLE.contains(SIGKILL));
    assert!(!set.contains(0) && !set.contains(65));
}

#[test]
fn default_actions() {
    use rk_abi::native::signal::{SIGCHLD, SIGCONT, SIGINT, SIGRTMIN, SIGSEGV, SIGTSTP};
    assert_eq!(default_action(SIGINT), DefaultAction::Terminate);
    assert_eq!(default_action(SIGSEGV), DefaultAction::CoreDump);
    assert_eq!(default_action(SIGCHLD), DefaultAction::Ignore);
    assert_eq!(default_action(SIGCONT), DefaultAction::Continue);
    assert_eq!(default_action(SIGTSTP), DefaultAction::Stop);
    assert_eq!(default_action(SIGRTMIN + 3), DefaultAction::Terminate);
    let dfl = SigAction::default();
    assert!(dfl.is_fatal(SIGINT) && !dfl.ignores(SIGINT));
    assert!(dfl.ignores(SIGCHLD) && dfl.ignores(SIGCONT) && !dfl.ignores(SIGTSTP));
    assert!(dfl.is_stop(SIGTSTP) && !dfl.is_stop(SIGCONT) && !dfl.is_fatal(SIGTSTP));
    let ign = SigAction { handler: SIG_IGN, ..SigAction::default() };
    assert!(ign.ignores(SIGINT) && !ign.is_fatal(SIGINT));
    let handler = SigAction { handler: 0x1000, ..SigAction::default() };
    assert!(!handler.ignores(SIGCHLD) && !handler.is_fatal(SIGINT));
}

#[test]
fn pending_queue() {
    use rk_abi::native::signal::{SIGINT, SIGRTMIN, SIGUSR1};
    let mut p = Pending::new();
    assert!(p.push(SigInfo::new(SIGUSR1, SI_USER, 5)));
    assert!(!p.push(SigInfo::new(SIGUSR1, SI_USER, 6)));
    assert!(p.push(SigInfo::new(SIGRTMIN, SI_USER, 7)));
    assert!(p.push(SigInfo::new(SIGRTMIN, SI_USER, 8)));
    assert!(p.push(SigInfo::new(SIGINT, SI_USER, 9)));
    let blocked = SigSet(SigSet::bit(SIGINT));
    assert_eq!(p.take(blocked).map(|i| i.pid), Some(5));
    assert_eq!(p.take(blocked).map(|i| i.pid), Some(7));
    assert!(p.set().contains(SIGRTMIN));
    assert_eq!(p.take(blocked).map(|i| i.pid), Some(8));
    assert!(!p.set().contains(SIGRTMIN));
    assert_eq!(p.take(blocked), None);
    p.discard(SIGINT);
    assert!(p.set().is_empty());
    assert_eq!(p.take(SigSet::EMPTY), None);
}

#[test]
fn siginfo_layout() {
    use rk_abi::native::signal::{SIGCHLD, SIGRTMIN, SIGSEGV};
    let mut chld = SigInfo::new(SIGCHLD, CLD_EXITED, 42);
    chld.status = 3;
    let b = chld.to_bytes();
    assert_eq!(b.len(), 128);
    assert_eq!(&b[0..4], &SIGCHLD.to_ne_bytes());
    assert_eq!(&b[8..12], &CLD_EXITED.to_ne_bytes());
    assert_eq!(&b[16..20], &42u32.to_ne_bytes());
    assert_eq!(&b[24..28], &3i32.to_ne_bytes());
    let segv = SigInfo::fault(SIGSEGV, SEGV_MAPERR, 0xdead_0000);
    let b = segv.to_bytes();
    assert_eq!(&b[16..24], &0xdead_0000u64.to_ne_bytes());
    assert_eq!(size_of::<SigAction>(), 32);
    assert_eq!(SigInfo::from_bytes(&chld.to_bytes()), chld);
    assert_eq!(SigInfo::from_bytes(&segv.to_bytes()), segv);
    let mut queued = SigInfo::new(SIGRTMIN, SI_QUEUE, 9);
    queued.value = 0x1234_5678_9abc;
    let b = queued.to_bytes();
    assert_eq!(&b[24..32], &0x1234_5678_9abcu64.to_ne_bytes());
    assert_eq!(SigInfo::from_bytes(&b), queued);
}

#[test]
fn altstack_flags() {
    let off = AltStack::default();
    assert_eq!(off.flags_at(0x1000), SS_DISABLE);
    let s = AltStack { sp: 0x1000, size: 0x2000, flags: 0 };
    assert!(s.contains(0x3000) && s.contains(0x1001));
    assert!(!s.contains(0x1000) && !s.contains(0x3001));
    assert_eq!(s.flags_at(0x2000), SS_ONSTACK);
    assert_eq!(s.flags_at(0x8000), 0);
}
