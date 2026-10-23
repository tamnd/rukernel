//! The boot self tests.
//!
//! `rk.test=NAME` on the command line runs one test and stops the virtual machine with the result.
//! `cargo xtask boot-test` boots the kernel one time for each test.

#[cfg(target_arch = "x86_64")]
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use rk_frame::addr::VirtAddr;
use rk_frame::mm::{self, Frame};
use rk_frame::println;
use rk_frame::trap::{self, Fault};
use rk_frame::{irq, time};

/// Runs the test `name`. Gives `true` when it passes.
pub(crate) fn run(name: &str) -> bool {
    match name {
        "boot" => true,
        "trap" => trap_test(),
        "mm" => mm_test(),
        "heap" => heap_test(),
        "timer" => timer_test(),
        #[cfg(target_arch = "x86_64")]
        "syscall" => syscall_test(),
        #[cfg(target_arch = "x86_64")]
        "vm" => vm_test(),
        other => {
            println!("rk.test: unknown test {other}");
            false
        }
    }
}

/// Prints the result of one check and gives it.
fn check(what: &str, ok: bool) -> bool {
    println!("rk.test: {what}: {}", if ok { "ok" } else { "FAIL" });
    ok
}

/// The permissions of the user pages of the tests.
#[cfg(target_arch = "x86_64")]
const RX: rk_frame::vm::PageProt = rk_frame::vm::PageProt { writable: false, executable: true };
#[cfg(target_arch = "x86_64")]
const RW: rk_frame::vm::PageProt = rk_frame::vm::PageProt { writable: true, executable: false };
#[cfg(target_arch = "x86_64")]
const RO: rk_frame::vm::PageProt = rk_frame::vm::PageProt { writable: false, executable: false };

/// An address that is canonical and has no mapping. A read from it is a page fault.
const UNMAPPED: usize = 0xffff_c000_0000_0000;

fn trap_test() -> bool {
    static VALUE: u64 = 0x5eed_cafe_f00d_0001;
    let before = trap::counts();
    trap::breakpoint();
    trap::breakpoint();
    let mut ok =
        check("two breakpoints return", trap::counts().breakpoints == before.breakpoints + 2);
    let read = trap::probe_read_u64(VirtAddr::new(&raw const VALUE as usize));
    ok &= check("a read of a mapped address", read == Ok(VALUE));
    let fault = trap::probe_read_u64(VirtAddr::new(UNMAPPED));
    ok &= check("a read of an unmapped address faults", fault == Err(Fault));
    let after = trap::counts();
    ok &= check("the page fault is counted", after.page_faults == before.page_faults + 1);
    ok &= check("the fixup is counted", after.fixups == before.fixups + 1);
    ok
}

/// A value in rodata.
static READ_ONLY: u64 = 0x0123_4567_89ab_cdef;
/// A value in the bss.
static WRITABLE: AtomicU64 = AtomicU64::new(0);

fn addr_of<T>(value: &T) -> VirtAddr {
    VirtAddr::new(core::ptr::from_ref(value) as usize)
}

fn heap_test() -> bool {
    use alloc::boxed::Box;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;

    let start = mm::heap_stats().in_use;
    let boxed = Box::new(0x5eed_u64);
    let mut ok = check("a box keeps its value", *boxed == 0x5eed);
    drop(boxed);

    // A vector that grows through all size classes and then into the large objects.
    let mut v: Vec<u64> = Vec::new();
    for i in 0..100_000 {
        v.push(i * 3);
    }
    ok &= check(
        "a vector of 100000 values",
        v.len() == 100_000 && v.iter().enumerate().all(|(i, &x)| x == i as u64 * 3),
    );
    drop(v);

    let mut map = BTreeMap::new();
    for i in 0..5000_u32 {
        map.insert(i.wrapping_mul(2_654_435_761), i);
    }
    ok &= check(
        "a map of 5000 keys",
        map.len() == 5000 && map.values().sum::<u32>() == 4999 * 5000 / 2,
    );
    drop(map);

    // Small objects are different and are aligned to their size.
    let boxes: Vec<Box<[u8; 48]>> = (0..1000).map(|i| Box::new([i as u8; 48])).collect();
    let aligned = boxes.iter().all(|b| (b.as_ptr() as usize).is_multiple_of(16));
    let kept = boxes.iter().enumerate().all(|(i, b)| b.iter().all(|&x| x == i as u8));
    ok &= check("1000 small boxes keep their values", aligned && kept);
    drop(boxes);

    let frames = mm::frame_stats().free;
    let big: Vec<u8> = alloc::vec![0xa5; 1 << 20];
    ok &= check("a block of 1 MiB", big.iter().all(|&b| b == 0xa5));
    let used = frames - mm::frame_stats().free;
    drop(big);
    let back = mm::frame_stats().free;
    ok &= check("the frames of a large block come back", used >= 256 && back == frames);
    ok &= check("the heap gives back each byte", mm::heap_stats().in_use == start);
    ok
}

fn mm_test() -> bool {
    let start = mm::frame_stats();
    let mut ok =
        check("the allocator has free frames", start.free > 0 && start.free <= start.total);

    // One frame: write, read, give back.
    let mut frame = mm::alloc_frame();
    ok &= check("a frame is allocated", frame.is_some());
    if let Some(f) = frame.as_mut() {
        f.zero();
        f.write_u64(0, 0xdead_beef);
        f.write_u64(Frame::WORDS - 1, 0xfeed_face);
        ok &= check(
            "a frame keeps its data",
            f.read_u64(0) == 0xdead_beef
                && f.read_u64(Frame::WORDS - 1) == 0xfeed_face
                && f.read_u64(1) == 0,
        );
        ok &= check("a frame is page aligned", f.addr().is_page_aligned());
    }
    drop(frame);
    ok &= check("a dropped frame is free again", mm::frame_stats().free == start.free);

    // Many frames: each is different, and all come back.
    let mut last = None;
    let mut distinct = true;
    let mut held = 0;
    for _ in 0..1000 {
        let Some(f) = mm::alloc_frame() else { break };
        distinct &= last.is_none_or(|l| f.addr() > l);
        last = Some(f.addr());
        held += 1;
        core::mem::forget(f);
    }
    ok &= check("1000 frames are different", held == 1000 && distinct);
    ok &= check("1000 frames are counted", mm::frame_stats().free == start.free - 1000);

    // The permissions of the kernel image.
    let text = mm::query(VirtAddr::new(mm_test as fn() -> bool as usize));
    ok &= check(
        "text is executable and read only",
        text.is_some_and(|i| i.executable && !i.writable && !i.user),
    );
    let ro = mm::query(addr_of(&READ_ONLY));
    ok &= check(
        "rodata is read only and not executable",
        ro.is_some_and(|i| !i.executable && !i.writable),
    );
    let rw = mm::query(addr_of(&WRITABLE));
    ok &= check(
        "bss is writable and not executable",
        rw.is_some_and(|i| !i.executable && i.writable),
    );
    ok &= check(
        "the CPU refuses a write to rodata",
        trap::probe_writable(addr_of(&READ_ONLY)) == Some(false),
    );
    WRITABLE.store(5, Ordering::Relaxed);
    ok &= check(
        "the CPU allows a write to bss",
        trap::probe_writable(addr_of(&WRITABLE)) == Some(true),
    );
    ok &= check("the probe does not change the value", WRITABLE.load(Ordering::Relaxed) == 5);
    ok &= check(
        "the boot identity map is gone",
        trap::probe_read_u64(VirtAddr::new(0x10_0000)) == Err(Fault),
    );

    // A vmalloc mapping of a frame.
    if let Some(mut frame) = mm::alloc_frame() {
        frame.write_u64(7, 0);
        let phys = frame.addr();
        match mm::vmap(frame) {
            Ok(mut m) => {
                m.write_u64(7, 0x7777);
                ok &= check("a mapping writes the frame", m.frame().read_u64(7) == 0x7777);
                ok &= check(
                    "a mapping translates to its frame",
                    mm::translate(m.addr()) == Some(phys),
                );
                let next = VirtAddr::new(m.addr().get() + 4096);
                ok &= check("a mapping has a guard page", trap::probe_read_u64(next) == Err(Fault));
                let addr = m.addr();
                let frame = m.unmap();
                ok &= check("an unmapped address faults", trap::probe_read_u64(addr) == Err(Fault));
                ok &= check("unmap gives back the frame", frame.addr() == phys);
            }
            Err(_) => ok &= check("vmap", false),
        }
    } else {
        ok &= check("a frame for vmap", false);
    }
    ok
}

fn timer_test() -> bool {
    // A tenth of a second of ticks. The wait stops after a fixed number of interrupts, so a timer
    // that does not work gives a failure and not a hang.
    let want = time::HZ / 10;
    let mut ok = check("interrupts are off at boot", !irq::enabled());
    ok &= check("the timer frequency is known", time::timer_frequency() > 0);
    let start = time::ticks();
    let mut waits = 0;
    while time::ticks() - start < want && waits < 10 * want {
        irq::wait();
        waits += 1;
    }
    irq::disable();
    let got = time::ticks() - start;
    println!("rk.test: {got} ticks in {waits} waits, timer at {} Hz", time::timer_frequency());
    ok &= check("the timer interrupts arrive", got >= want);
    ok &= check("interrupts are off again", !irq::enabled());
    ok
}

/// The user program of the syscall test. It makes each system call number from 0 to the end of
/// the table, and counts the returns that are not `-ENOSYS` in RBX. Then it stops with `int3`.
#[cfg(target_arch = "x86_64")]
const SYSCALL_PROGRAM: [u8; 31] = [
    0x45, 0x31, 0xe4, // xor r12d, r12d
    0x31, 0xdb, // xor ebx, ebx
    0x44, 0x89, 0xe0, // 1: mov eax, r12d
    0x0f, 0x05, // syscall
    0x48, 0x83, 0xf8, 0xda, // cmp rax, -38
    0x74, 0x02, // je 2f
    0xff, 0xc3, // inc ebx
    0x41, 0xff, 0xc4, // 2: inc r12d
    0x41, 0x81, 0xfc, 0, 0, 0, 0, // cmp r12d, NR_SYSCALLS
    0x72, 0xe7, // jb 1b
    0xcc, // int3
];

/// The offset of the 32 bit value of the `cmp r12d` instruction in `SYSCALL_PROGRAM`.
#[cfg(target_arch = "x86_64")]
const SYSCALL_PROGRAM_LIMIT: usize = 24;

#[cfg(target_arch = "x86_64")]
fn syscall_test() -> bool {
    use crate::syscall;
    use rk_abi::native::syscalls::NR_SYSCALLS;
    use rk_frame::user::{ReturnReason, UserContext};
    use rk_frame::vm::{self, MapError, VmSpace};

    const CODE: usize = 0x40_0000;
    const STACK: usize = 0x7fff_ffff_e000;
    const BREAKPOINT: u8 = 3;

    let mut program = SYSCALL_PROGRAM;
    let limit = (NR_SYSCALLS as u32).to_le_bytes();
    program[SYSCALL_PROGRAM_LIMIT..SYSCALL_PROGRAM_LIMIT + 4].copy_from_slice(&limit);
    let (Some(mut code), Some(mut stack)) = (mm::alloc_frame(), mm::alloc_frame()) else {
        return check("two frames for the user pages", false);
    };
    code.zero();
    stack.zero();
    for (i, chunk) in program.chunks(8).enumerate() {
        let mut word = [0u8; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        code.write_u64(i, u64::from_le_bytes(word));
    }
    let Some(space) = VmSpace::new() else {
        return check("an address space for the user pages", false);
    };
    let mut ok = check(
        "the user pages are mapped",
        space.map(VirtAddr::new(CODE), Arc::new(code), RX).is_ok()
            && space.map(VirtAddr::new(STACK), Arc::new(stack), RW).is_ok(),
    );
    ok &= check(
        "the kernel refuses a user page in the kernel half",
        mm::alloc_frame().is_some_and(|f| {
            space.map(VirtAddr::new(vm::USER_END), Arc::new(f), RW) == Err(MapError::BadAddress)
        }),
    );
    ok &= check(
        "the code page is executable and read only",
        space.page(VirtAddr::new(CODE)).is_some_and(|(_, p)| p == RX),
    );
    ok &= check(
        "the kernel table does not map the user page",
        mm::query(VirtAddr::new(CODE)).is_none(),
    );
    space.activate();

    let mut ctx = UserContext::new(VirtAddr::new(CODE), VirtAddr::new(STACK + 4096));
    let start = syscall::count();
    let mut interrupts = 0u64;
    // Each number is one return, and the timer can add more. The limit stops a loop that does
    // not end.
    let reason = loop {
        if syscall::count() - start > 2 * NR_SYSCALLS as u64 {
            break None;
        }
        match ctx.execute() {
            ReturnReason::Syscall => syscall::dispatch(&mut ctx),
            ReturnReason::Interrupt => interrupts += 1,
            ReturnReason::Exception(e) => break Some(e),
        }
    };
    let calls = syscall::count() - start;
    println!("rk.test: {calls} system calls, {interrupts} interrupts in user mode");
    ok &= check(
        "the program stops at its int3",
        reason.is_some_and(|e| e.vector == BREAKPOINT)
            && ctx.regs().rip == (CODE + SYSCALL_PROGRAM.len()) as u64,
    );
    ok &= check("each system call number is made", calls == NR_SYSCALLS as u64);
    ok &= check(
        "each number gives -ENOSYS",
        ctx.regs().r12 == NR_SYSCALLS as u64 && ctx.regs().rbx == 0,
    );
    ok &= check("interrupts are off again", !irq::enabled());
    VmSpace::deactivate();
    drop(space);
    ok &= fpu_test();
    ok
}

/// The user programs of the FPU test. Program A puts a value in XMM0, makes a system call, copies
/// XMM0 to RBX and reads the word at FS:0 into RCX. Program B puts another value in XMM0. The
/// test runs B between the system call of A and its return, so A sees its own value only if the
/// kernel keeps the SSE state of each context.
#[cfg(target_arch = "x86_64")]
const FPU_PROGRAM_A: [u8; 36] = [
    0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // mov rax, 0x1122334455667788
    0x66, 0x48, 0x0f, 0x6e, 0xc0, // movq xmm0, rax
    0xb8, 0x27, 0, 0, 0, // mov eax, 39
    0x0f, 0x05, // syscall
    0x66, 0x48, 0x0f, 0x7e, 0xc3, // movq rbx, xmm0
    0x64, 0x48, 0x8b, 0x0c, 0x25, 0, 0, 0, 0, // mov rcx, fs:[0]
];
#[cfg(target_arch = "x86_64")]
const FPU_PROGRAM_B: [u8; 15] = [
    0x48, 0xb8, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, // mov rax, 0x9999999999999999
    0x66, 0x48, 0x0f, 0x6e, 0xc0, // movq xmm0, rax
];

#[cfg(target_arch = "x86_64")]
fn fpu_test() -> bool {
    use crate::syscall;
    use rk_frame::user::{ReturnReason, UserContext};
    use rk_frame::vm::VmSpace;

    const CODE: usize = 0x40_1000;
    const B_OFFSET: usize = 0x80;
    const DATA: usize = 0x60_0000;
    const STACK: usize = 0x7fff_fffd_e000;
    const INT3: u8 = 0xcc;

    let (Some(mut code), Some(mut data), Some(stack)) =
        (mm::alloc_frame(), mm::alloc_frame(), mm::alloc_frame())
    else {
        return check("three frames for the FPU test", false);
    };
    let mut bytes = [INT3; 4096];
    bytes[..FPU_PROGRAM_A.len()].copy_from_slice(&FPU_PROGRAM_A);
    bytes[B_OFFSET..B_OFFSET + FPU_PROGRAM_B.len()].copy_from_slice(&FPU_PROGRAM_B);
    for (i, chunk) in bytes.chunks(8).enumerate() {
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        code.write_u64(i, u64::from_le_bytes(word));
    }
    data.zero();
    data.write_u64(2, 0xfeed_f00d);
    let Some(space) = VmSpace::new() else {
        return check("an address space for the FPU test", false);
    };
    let mut ok = check(
        "the FPU test pages are mapped",
        space.map(VirtAddr::new(CODE), Arc::new(code), RX).is_ok()
            && space.map(VirtAddr::new(DATA), Arc::new(data), RO).is_ok()
            && space.map(VirtAddr::new(STACK), Arc::new(stack), RW).is_ok(),
    );
    space.activate();

    let mut a = UserContext::new(VirtAddr::new(CODE), VirtAddr::new(STACK + 4096));
    a.set_fs_base((DATA + 16) as u64);
    let mut b = UserContext::new(VirtAddr::new(CODE + B_OFFSET), VirtAddr::new(STACK + 4096));
    let run = |ctx: &mut UserContext| loop {
        match ctx.execute() {
            ReturnReason::Interrupt => continue,
            other => break other,
        }
    };
    ok &= check("program A makes a system call", run(&mut a) == ReturnReason::Syscall);
    syscall::dispatch(&mut a);
    ok &= check("program B stops at its int3", matches!(run(&mut b), ReturnReason::Exception(_)));
    ok &= check("program A stops at its int3", matches!(run(&mut a), ReturnReason::Exception(_)));
    ok &= check("XMM0 of program A is kept", a.regs().rbx == 0x1122_3344_5566_7788);
    ok &= check("the FS base of program A is used", a.regs().rcx == 0xfeed_f00d);
    ok &= check("the SSE state of the two programs is different", a.fpu() != b.fpu());
    VmSpace::deactivate();
    ok
}

/// The user program of the address space test: it reads the word at `VM_DATA` into RBX.
#[cfg(target_arch = "x86_64")]
const VM_PROGRAM: [u8; 9] = [
    0x48, 0x8b, 0x1c, 0x25, 0, 0, 0x60, 0,    // mov rbx, [0x600000]
    0xcc, // int3
];

/// Two address spaces map the same code frame and different data frames at the same addresses.
/// Each program reads its own data. When the address spaces go, each frame goes back.
#[cfg(target_arch = "x86_64")]
fn vm_test() -> bool {
    use rk_frame::user::{ReturnReason, UserContext};
    use rk_frame::vm::{UserFault, VmSpace};

    const CODE: usize = 0x40_0000;
    const DATA: usize = 0x60_0000;
    const STACK: usize = 0x7fff_ffff_e000;

    // The heap keeps its slab pages, so one address space with one page comes and goes before
    // the count. Then the nodes of the page map come from a slab that exists.
    let warm = VmSpace::new().zip(mm::alloc_zeroed_frame());
    if let Some((space, frame)) = warm {
        let _ = space.map(VirtAddr::new(DATA), Arc::new(frame), RW);
    }
    let free_before = mm::frame_stats().free;
    let Some(code) = mm::alloc_zeroed_frame() else {
        return check("a frame for the code", false);
    };
    code.write_bytes(0, &VM_PROGRAM);
    let code = Arc::new(code);
    let mut ok = true;
    let mut values = [0u64; 2];
    for (i, value) in values.iter_mut().enumerate() {
        let (Some(space), Some(data), Some(stack)) =
            (VmSpace::new(), mm::alloc_zeroed_frame(), mm::alloc_zeroed_frame())
        else {
            return check("an address space and two frames", false);
        };
        ok &= check(
            "the pages are mapped",
            space.map(VirtAddr::new(CODE), code.clone(), RX).is_ok()
                && space.map(VirtAddr::new(DATA), Arc::new(data), RW).is_ok()
                && space.map(VirtAddr::new(STACK), Arc::new(stack), RW).is_ok(),
        );
        let word = 0x1111_0000 + i as u64;
        ok &= check(
            "the kernel writes user memory",
            space.write(VirtAddr::new(DATA), &word.to_le_bytes()).is_ok(),
        );
        let mut back = [0u8; 8];
        ok &= check(
            "the kernel reads user memory",
            space.read(VirtAddr::new(DATA), &mut back).is_ok() && u64::from_le_bytes(back) == word,
        );
        ok &= check(
            "a write to the code page faults",
            space.write(VirtAddr::new(CODE), &[0]) == Err(UserFault { addr: CODE, write: true }),
        );
        ok &= check(
            "a read across the end of a page stops at the unmapped page",
            space.read(VirtAddr::new(DATA + 4092), &mut back)
                == Err(UserFault { addr: DATA + 4096, write: false }),
        );
        space.activate();
        let mut ctx = UserContext::new(VirtAddr::new(CODE), VirtAddr::new(STACK + 4096));
        let reason = loop {
            match ctx.execute() {
                ReturnReason::Interrupt => continue,
                other => break other,
            }
        };
        ok &= check(
            "the program stops at its int3",
            matches!(reason, ReturnReason::Exception(e) if e.vector == 3),
        );
        *value = ctx.regs().rbx;
        // The address space is active when it goes, so the drop loads the kernel table.
        drop(space);
    }
    ok &= check("each address space has its own data", values == [0x1111_0000, 0x1111_0001]);
    ok &=
        check("the address spaces give back the shared code frame", Arc::strong_count(&code) == 1);
    drop(code);
    ok &= check("the frames and the page tables go back", mm::frame_stats().free == free_before);
    ok
}
