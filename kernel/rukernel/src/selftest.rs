//! The boot self tests.
//!
//! `rk.test=NAME` on the command line runs one test and stops the virtual machine with the result.
//! `cargo xtask boot-test` boots the kernel one time for each test.

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
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
        "initramfs" => initramfs_test(),
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        "syscall" => syscall_test(),
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        "vm" => vm_test(),
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        "task" => task_test(),
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        "fault" => fault_test(),
        #[cfg(target_arch = "x86_64")]
        "net" => net_test(),
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
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const RX: rk_frame::vm::PageProt =
    rk_frame::vm::PageProt { readable: true, writable: false, executable: true };
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const RW: rk_frame::vm::PageProt =
    rk_frame::vm::PageProt { readable: true, writable: true, executable: false };
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const RO: rk_frame::vm::PageProt =
    rk_frame::vm::PageProt { readable: true, writable: false, executable: false };

/// The register where the user programs of the tests put a result: RBX on x86-64, x19 on arm64.
#[cfg(target_arch = "x86_64")]
fn result_reg(ctx: &rk_frame::user::UserContext) -> u64 {
    ctx.regs().rbx
}
#[cfg(target_arch = "aarch64")]
fn result_reg(ctx: &rk_frame::user::UserContext) -> u64 {
    ctx.regs().x[19]
}

/// The register where the syscall program counts the numbers: R12 on x86-64, x20 on arm64.
#[cfg(target_arch = "x86_64")]
fn counter_reg(ctx: &rk_frame::user::UserContext) -> u64 {
    ctx.regs().r12
}
#[cfg(target_arch = "aarch64")]
fn counter_reg(ctx: &rk_frame::user::UserContext) -> u64 {
    ctx.regs().x[20]
}

/// The register where the FPU program puts the word at the thread pointer: RCX on x86-64, x21 on
/// arm64.
#[cfg(target_arch = "x86_64")]
fn tls_reg(ctx: &rk_frame::user::UserContext) -> u64 {
    ctx.regs().rcx
}
#[cfg(target_arch = "aarch64")]
fn tls_reg(ctx: &rk_frame::user::UserContext) -> u64 {
    ctx.regs().x[21]
}

/// The distance from the end of a program to the program counter when it stops at its last
/// instruction, a breakpoint. `int3` gives the address after it, and `brk` gives its own address.
#[cfg(target_arch = "x86_64")]
const BREAK_PC_FROM_END: usize = 0;
#[cfg(target_arch = "aarch64")]
const BREAK_PC_FROM_END: usize = 4;

/// Tells if the user program stopped at a breakpoint instruction.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn is_breakpoint(e: &rk_frame::user::UserException) -> bool {
    e.kind() == rk_frame::user::ExceptionKind::Breakpoint
}

/// Makes the bytes of an arm64 program from its instructions.
#[cfg(target_arch = "aarch64")]
const fn arm64_code<const N: usize>(words: &[u32]) -> [u8; N] {
    let mut bytes = [0u8; N];
    let mut i = 0;
    while i < words.len() {
        let w = words[i].to_le_bytes();
        bytes[4 * i] = w[0];
        bytes[4 * i + 1] = w[1];
        bytes[4 * i + 2] = w[2];
        bytes[4 * i + 3] = w[3];
        i += 1;
    }
    bytes
}

/// The instruction that fills the free space of a code page: `int3` on x86-64, `brk #0` on arm64.
#[cfg(target_arch = "x86_64")]
const BREAK_FILL: [u8; 4] = [0xcc; 4];
#[cfg(target_arch = "aarch64")]
const BREAK_FILL: [u8; 4] = 0xd420_0000_u32.to_le_bytes();

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
    // The 256 data frames come back. The block can need a new page table, and the page tables of
    // the heap range stay.
    let tables = used.saturating_sub(256);
    ok &= check(
        "the frames of a large block come back",
        used >= 256 && tables <= 2 && back + tables == frames,
    );
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

    // Many frames: each is different, and all come back. The list of each CPU gives the frames
    // in no fixed order, so the addresses are sorted. The vector has its memory before the count.
    let mut addrs = alloc::vec::Vec::with_capacity(1000);
    let before = mm::frame_stats().free;
    for _ in 0..1000 {
        let Some(f) = mm::alloc_frame() else { break };
        addrs.push(f.addr().get());
        core::mem::forget(f);
    }
    let held = addrs.len();
    ok &= check("1000 frames are counted", mm::frame_stats().free == before - 1000);
    addrs.sort_unstable();
    addrs.dedup();
    ok &= check("1000 frames are different", held == 1000 && addrs.len() == 1000);
    drop(addrs);

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
    #[cfg(target_arch = "x86_64")]
    {
        // The kernel keeps interrupts off for a tenth of a second, so the APIC keeps only one
        // interrupt of the timer. The tick count must still add each tick of that time.
        let start = time::ticks();
        let until = time::nanos() + 100_000_000;
        while time::nanos() < until {
            core::hint::spin_loop();
        }
        irq::wait();
        irq::disable();
        let got = time::ticks() - start;
        println!("rk.test: {got} ticks after a tenth of a second with interrupts off");
        ok &= check("the ticks with interrupts off are counted", got + 2 >= want);
    }
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

/// The user program of the syscall test on arm64. It makes each system call number from 0 to the
/// end of the table, and counts the returns that are not `-ENOSYS` in x19. Then it stops with
/// `brk`.
#[cfg(target_arch = "aarch64")]
const SYSCALL_PROGRAM: [u8; 48] = arm64_code(&[
    0xd280_0014, // mov x20, #0
    0xd280_0013, // mov x19, #0
    0xaa14_03e8, // 1: mov x8, x20
    0xd400_0001, // svc #0
    0xb100_981f, // cmn x0, #38
    0x5400_0040, // b.eq 2f
    0x9100_0673, // add x19, x19, #1
    0x9100_0694, // 2: add x20, x20, #1
    0x5280_0009, // mov w9, #NR_SYSCALLS
    0xeb09_029f, // cmp x20, x9
    0x54ff_ff03, // b.lo 1b
    0xd420_0000, // brk #0
]);

/// Gives the syscall program with the number of system calls in it.
#[cfg(target_arch = "x86_64")]
fn syscall_program(count: u32) -> [u8; SYSCALL_PROGRAM.len()] {
    let mut program = SYSCALL_PROGRAM;
    program[SYSCALL_PROGRAM_LIMIT..SYSCALL_PROGRAM_LIMIT + 4].copy_from_slice(&count.to_le_bytes());
    program
}

/// Gives the syscall program with the number of system calls in the `mov w9` instruction at
/// offset 32. The immediate value is in bits 5 to 20.
#[cfg(target_arch = "aarch64")]
fn syscall_program(count: u32) -> [u8; SYSCALL_PROGRAM.len()] {
    let mut program = SYSCALL_PROGRAM;
    program[32..36].copy_from_slice(&(0x5280_0009 | (count & 0xffff) << 5).to_le_bytes());
    program
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn syscall_test() -> bool {
    use crate::syscall;
    use rk_abi::native::syscalls::NR_SYSCALLS;
    use rk_frame::user::{ReturnReason, UserContext};
    use rk_frame::vm::{self, MapError, VmSpace};

    const CODE: usize = 0x40_0000;
    const STACK: usize = 0x7fff_ffff_e000;

    let program = syscall_program(NR_SYSCALLS as u32);
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
        "the program stops at its breakpoint",
        reason.is_some_and(|e| is_breakpoint(&e))
            && ctx.pc() == (CODE + SYSCALL_PROGRAM.len() - BREAK_PC_FROM_END) as u64,
    );
    ok &= check("each system call number is made", calls == NR_SYSCALLS as u64);
    ok &= check(
        "each number gives -ENOSYS",
        counter_reg(&ctx) == NR_SYSCALLS as u64 && result_reg(&ctx) == 0,
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

/// The user programs of the FPU test on arm64. Program A puts a value in d0, makes a system call,
/// copies d0 to x19 and reads the word at TPIDR_EL0 into x21. Program B puts another value in d0.
#[cfg(target_arch = "aarch64")]
const FPU_PROGRAM_A: [u8; 44] = arm64_code(&[
    0xd28e_f100, // mov x0, #0x7788
    0xf2aa_acc0, // movk x0, #0x5566, lsl #16
    0xf2c6_6880, // movk x0, #0x3344, lsl #32
    0xf2e2_2440, // movk x0, #0x1122, lsl #48
    0x9e67_0000, // fmov d0, x0
    0xd280_1588, // mov x8, #172 (getpid)
    0xd400_0001, // svc #0
    0x9e66_0013, // fmov x19, d0
    0xd53b_d049, // mrs x9, tpidr_el0
    0xf940_0135, // ldr x21, [x9]
    0xd420_0000, // brk #0
]);
#[cfg(target_arch = "aarch64")]
const FPU_PROGRAM_B: [u8; 24] = arm64_code(&[
    0xd293_3320, // mov x0, #0x9999
    0xf2b3_3320, // movk x0, #0x9999, lsl #16
    0xf2d3_3320, // movk x0, #0x9999, lsl #32
    0xf2f3_3320, // movk x0, #0x9999, lsl #48
    0x9e67_0000, // fmov d0, x0
    0xd420_0000, // brk #0
]);

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn fpu_test() -> bool {
    use crate::syscall;
    use rk_frame::user::{ReturnReason, UserContext};
    use rk_frame::vm::VmSpace;

    const CODE: usize = 0x40_1000;
    const B_OFFSET: usize = 0x80;
    const DATA: usize = 0x60_0000;
    const STACK: usize = 0x7fff_fffd_e000;

    let (Some(mut code), Some(mut data), Some(stack)) =
        (mm::alloc_frame(), mm::alloc_frame(), mm::alloc_frame())
    else {
        return check("three frames for the FPU test", false);
    };
    let mut bytes = [0u8; 4096];
    for chunk in bytes.chunks_mut(4) {
        chunk.copy_from_slice(&BREAK_FILL);
    }
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
    a.set_tls((DATA + 16) as u64);
    let mut b = UserContext::new(VirtAddr::new(CODE + B_OFFSET), VirtAddr::new(STACK + 4096));
    let run = |ctx: &mut UserContext| loop {
        match ctx.execute() {
            ReturnReason::Interrupt => continue,
            other => break other,
        }
    };
    ok &= check("program A makes a system call", run(&mut a) == ReturnReason::Syscall);
    syscall::dispatch(&mut a);
    ok &= check(
        "program B stops at its breakpoint",
        matches!(run(&mut b), ReturnReason::Exception(_)),
    );
    ok &= check(
        "program A stops at its breakpoint",
        matches!(run(&mut a), ReturnReason::Exception(_)),
    );
    ok &= check("the SIMD register of program A is kept", result_reg(&a) == 0x1122_3344_5566_7788);
    ok &= check("the thread pointer of program A is used", tls_reg(&a) == 0xfeed_f00d);
    ok &= check("the FP state of the two programs is different", a.fpu() != b.fpu());
    VmSpace::deactivate();
    ok
}

/// The user program of the address space test: it reads the word at `VM_DATA` into RBX.
#[cfg(target_arch = "x86_64")]
const VM_PROGRAM: [u8; 9] = [
    0x48, 0x8b, 0x1c, 0x25, 0, 0, 0x60, 0,    // mov rbx, [0x600000]
    0xcc, // int3
];

/// The user program of the address space test on arm64: it reads the word at `VM_DATA` into x19.
#[cfg(target_arch = "aarch64")]
const VM_PROGRAM: [u8; 12] = arm64_code(&[
    0xd2a0_0c09, // mov x9, #0x600000
    0xf940_0133, // ldr x19, [x9]
    0xd420_0000, // brk #0
]);

/// Two address spaces map the same code frame and different data frames at the same addresses.
/// Each program reads its own data. When the address spaces go, each frame goes back.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
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
            "the program stops at its breakpoint",
            matches!(reason, ReturnReason::Exception(e) if is_breakpoint(&e)),
        );
        *value = result_reg(&ctx);
        // The address space is active when it goes, so the drop loads the kernel table.
        drop(space);
    }
    ok &= check("each address space has its own data", values == [0x1111_0000, 0x1111_0001]);
    ok &=
        check("the address spaces give back the shared code frame", Arc::strong_count(&code) == 1);
    drop(code);
    ok &= check("the frames and the page tables go back", mm::frame_stats().free == free_before);
    ok &= vm_status_test();
    ok
}

/// The status table of each last level page table keeps the status of each page, also of a page
/// with no frame, and a `fork` copies it with the pages, as the CortenMM backend of rk-mm uses it.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn vm_status_test() -> bool {
    use alloc::vec::Vec;
    use rk_frame::status::PageStatus;
    use rk_frame::vm::{PageChange, VmSpace};

    const BASE: usize = 0x80_0000;
    const PAGE: usize = 4096;

    let (Some(space), Some(frame)) = (VmSpace::new(), mm::alloc_zeroed_frame()) else {
        return check("an address space and a frame for the statuses", false);
    };
    let at = |n: usize| VirtAddr::new(BASE + n * PAGE);
    let value = |s: &PageStatus| s.downcast_ref::<u32>().copied();
    let status = |n: usize| space.status(at(n)).as_ref().and_then(value);
    let (a, b): (PageStatus, PageStatus) = (Arc::new(1u32), Arc::new(2u32));
    // Only the holder of the status table of a block reads or changes its statuses.
    space.hold_status(at(0), true);
    space.set_status(at(0), at(8), Some(&a));
    space.set_status(at(2), at(4), Some(&b));
    let mut ok = check(
        "a page with no frame has a status",
        status(1) == Some(1) && status(2) == Some(2) && status(8).is_none(),
    );
    let mut runs = Vec::new();
    space.status_runs(at(0), at(16), |s, e, st| runs.push((s, e, value(st))));
    ok &= check(
        "the statuses of the pages are in runs",
        runs == [
            (BASE, BASE + 2 * PAGE, Some(1)),
            (BASE + 2 * PAGE, BASE + 4 * PAGE, Some(2)),
            (BASE + 4 * PAGE, BASE + 8 * PAGE, Some(1)),
        ],
    );
    ok &= check(
        "a run of statuses joins the values that the caller joins",
        space.status_run(at(5), |_, _| true).map(|r| (r.0, r.1)) == Some((BASE, BASE + 8 * PAGE)),
    );
    ok &= check(
        "a map and an unmap of a page keep its status",
        space.map(at(3), Arc::new(frame), RW).is_ok() && status(3) == Some(2) && {
            space.unmap_range(at(0), at(8));
            space.page(at(3)).is_none() && status(3) == Some(2)
        },
    );
    let child =
        space.fork_with(&[], |s| (value(s) == Some(1)).then(|| Arc::new(11u32) as PageStatus));
    ok &= check(
        "fork copies the statuses that the caller keeps",
        child.as_ref().is_ok_and(|c| {
            c.hold_status(at(0), false) && {
                let ok = c.status(at(0)).as_ref().and_then(value) == Some(11)
                    && c.status(at(2)).is_none();
                c.release_status(at(0));
                ok
            }
        }),
    );
    drop(child);
    ok &= check(
        "a change of the statuses changes the pages in the same pass",
        mm::alloc_zeroed_frame().is_some_and(|f| space.map(at(6), Arc::new(f), RW).is_ok())
            && {
                let mut change = PageChange::protect(at(4), at(8), RO);
                let mut old = Vec::new();
                space.change_status(at(4), at(8), Some(&b), Some(&mut change), |s, e, st| {
                    old.push((s, e, value(st)))
                });
                space.finish(change);
                old == [(BASE + 4 * PAGE, BASE + 8 * PAGE, Some(1))]
                    && space.page(at(6)).is_some_and(|(_, p)| p == RO)
                    && status(6) == Some(2)
            }
            && {
                let mut change = PageChange::unmap(at(0), at(8));
                space.change_status(at(0), at(8), Some(&a), Some(&mut change), |_, _, _| {});
                space.finish(change);
                space.page(at(6)).is_none() && status(6) == Some(1)
            },
    );
    space.release_status(at(0));
    ok &= check(
        "a hold of a status table excludes a second hold",
        !space.hold_status(at(512), false)
            && space.hold_status(at(0), false)
            && !space.try_hold_status(at(5))
            && {
                space.release_status(at(5));
                space.try_hold_status(at(0))
            },
    );
    space.set_status(at(0), at(8), None);
    space.release_status(at(0));
    ok &= check(
        "a clear removes the statuses",
        !space.has_status(at(0)) && Arc::strong_count(&a) == 1 && Arc::strong_count(&b) == 1,
    );
    ok
}

/// Three tasks take turns, a task waits in a wait queue for another task, and the stacks of the
/// exited tasks go back to the heap.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn task_test() -> bool {
    use alloc::vec::Vec;
    use rk_frame::sync::SpinLock;
    use rk_frame::task::{self, Task, TaskOptions, WaitQueue};

    static LOG: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());
    static QUEUE: WaitQueue = WaitQueue::new();
    static VALUE: AtomicU64 = AtomicU64::new(0);

    let heap_before = mm::heap_stats().in_use;
    // The log has room for each entry, so the first push of a task takes no more time than the
    // other pushes. The fair scheduler charges the time that a task runs.
    LOG.lock().reserve(16);
    let mut tasks = Vec::new();
    for n in 1..=3u64 {
        let task = TaskOptions::new(move || {
            for round in 0..3 {
                LOG.lock().push(n * 10 + round);
                task::yield_now();
            }
        })
        .data(n)
        .spawn();
        let Some(task) = task else { return check("a stack for each task", false) };
        tasks.push(task);
    }
    let mut ok = check(
        "each task has its data",
        tasks.iter().zip(1..).all(|(t, n)| t.data().downcast_ref::<u64>() == Some(&n)),
    );
    while !tasks.iter().all(|t| t.is_exited()) {
        task::yield_now();
    }
    let log = core::mem::take(&mut *LOG.lock());
    println!("rk.test: the tasks ran in the order {log:?}");
    // The fair scheduler charges the time that each task runs. Without KVM, an interrupt can make
    // one turn much longer, and then the other tasks can run more turns first. So the check is
    // the first turn of each task in the order of the spawns, and the order of the turns of each
    // task.
    let turns = |n: u64| log.iter().filter(|&&v| v / 10 == n).copied().collect::<Vec<_>>();
    ok &= check(
        "the tasks take turns",
        log.len() == 9
            && log[..3] == [10, 20, 30]
            && (1..=3).all(|n| turns(n) == [n * 10, n * 10 + 1, n * 10 + 2]),
    );
    ok &= check("the boot task is the current task", Task::current().id() == 0);

    let waiter = TaskOptions::new(|| {
        let value = QUEUE.wait_until(|| match VALUE.load(Ordering::Acquire) {
            0 => None,
            v => Some(v),
        });
        LOG.lock().push(value);
    })
    .spawn();
    let Some(waiter) = waiter else { return check("a stack for the waiter", false) };
    // The waiter runs and blocks. Then the boot task is the only task that can run.
    task::yield_now();
    ok &= check("the waiter blocks", !waiter.is_exited() && LOG.lock().is_empty());
    VALUE.store(42, Ordering::Release);
    ok &= check("the wake finds the waiter", QUEUE.wake_one());
    while !waiter.is_exited() {
        task::yield_now();
    }
    ok &= check("the waiter gets the value", *LOG.lock() == [42]);

    drop(tasks);
    drop(waiter);
    LOG.lock().clear();
    LOG.lock().shrink_to_fit();
    let heap_after = mm::heap_stats().in_use;
    println!("rk.test: heap in use {heap_before} before, {heap_after} after");
    // The boot task and the buffers of the queues stay, but each stack is larger than them.
    ok &= check(
        "the stacks go back to the heap",
        heap_after - heap_before < task::KERNEL_STACK_SIZE as u64,
    );
    ok
}

/// The user program of the fault test. It writes the first two pages of the data area and reads
/// the third one. Each page has no frame before the access.
#[cfg(target_arch = "x86_64")]
const FAULT_PROGRAM: [u8; 33] = [
    0x48, 0xc7, 0x04, 0x25, 0, 0, 0, 0x10, 1, 0, 0, 0, // mov qword [0x10000000], 1
    0x48, 0xc7, 0x04, 0x25, 0, 0x10, 0, 0x10, 1, 0, 0, 0, // mov qword [0x10001000], 1
    0x48, 0x8b, 0x1c, 0x25, 0, 0x20, 0, 0x10, // mov rbx, [0x10002000]
    0xcc, // int3
];

/// The user program of the fault test on arm64, as `FAULT_PROGRAM` of x86-64.
#[cfg(target_arch = "aarch64")]
const FAULT_PROGRAM: [u8; 32] = arm64_code(&[
    0xd2a2_0009, // mov x9, #0x10000000
    0xd280_002a, // mov x10, #1
    0xf900_012a, // str x10, [x9]
    0x9140_052b, // add x11, x9, #0x1000
    0xf900_016a, // str x10, [x11]
    0x9140_092c, // add x12, x9, #0x2000
    0xf940_0193, // ldr x19, [x12]
    0xd420_0000, // brk #0
]);

/// A user program gets its pages at the first access, and `fork`, copy on write, `munmap`,
/// `mprotect` and `brk` change the address space as Linux does.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn fault_test() -> bool {
    use rk_abi::Errno;
    use rk_frame::user::{ExceptionKind, FaultAccess, ReturnReason, UserContext};
    use rk_mm::{Access, AddressSpace, MmapRequest, Prot};

    const CODE: usize = 0x40_0000;
    const DATA: usize = 0x1000_0000;
    const HEAP: usize = 0x80_0000;
    const RX: Prot = Prot { read: true, write: false, exec: true };
    const RO: Prot = Prot { read: true, write: false, exec: false };

    let Ok(space) = AddressSpace::new() else { return check("an address space", false) };
    let fixed = |addr, len, prot| MmapRequest { addr, fixed: true, ..MmapRequest::anon(len, prot) };
    let stack_top = rk_mm::STACK_TOP;
    let mut ok = check(
        "the areas are mapped",
        space.mmap(fixed(CODE, 4096, Prot::RW)) == Ok(CODE)
            && space.mmap(fixed(DATA, 3 * 4096, Prot::RW)) == Ok(DATA)
            && space.mmap(fixed(stack_top - 0x1_0000, 0x1_0000, Prot::RW)).is_ok(),
    );
    ok &= check(
        "the program is written and made executable",
        space.write(CODE, &FAULT_PROGRAM).is_ok() && space.mprotect(CODE, 4096, RX).is_ok(),
    );
    ok &= check("no data page has a frame yet", space.vm().page_count() == 1);

    space.activate();
    let mut ctx = UserContext::new(VirtAddr::new(CODE), VirtAddr::new(stack_top));
    let mut faults = 0;
    let reason = loop {
        match ctx.execute() {
            ReturnReason::Interrupt => {}
            ReturnReason::Exception(e) => match e.kind() {
                ExceptionKind::PageFault { addr, access, .. } => {
                    faults += 1;
                    let access =
                        if access == FaultAccess::Write { Access::Write } else { Access::Read };
                    if space.handle_fault(addr as usize, access).is_err() {
                        break None;
                    }
                }
                _ => break Some(ReturnReason::Exception(e)),
            },
            other => break Some(other),
        }
    };
    rk_frame::vm::VmSpace::deactivate();
    ok &= check(
        "the program stops at its breakpoint",
        matches!(reason, Some(ReturnReason::Exception(e)) if is_breakpoint(&e)),
    );
    ok &= check("each data page is one fault", faults == 3);
    ok &= check("a new page reads as zero", result_reg(&ctx) == 0);
    let read = |s: &AddressSpace, addr| {
        let mut b = [0u8; 8];
        s.read(addr, &mut b).map(|()| u64::from_le_bytes(b))
    };
    ok &= check("the kernel reads what the program wrote", read(&space, DATA) == Ok(1));

    let Ok(child) = space.fork() else { return check("the fork", false) };
    ok &= check(
        "a write in the child copies the page",
        child.write(DATA, &2u64.to_le_bytes()).is_ok()
            && read(&child, DATA) == Ok(2)
            && read(&space, DATA) == Ok(1),
    );
    ok &= check(
        "a write in the parent copies the page too",
        space.write(DATA + 4096, &3u64.to_le_bytes()).is_ok()
            && read(&space, DATA + 4096) == Ok(3)
            && read(&child, DATA + 4096) == Ok(1),
    );
    ok &= check(
        "mprotect makes a page read only",
        child.mprotect(DATA, 4096, RO).is_ok()
            && child.write(DATA, &[0]) == Err(Errno::EFAULT)
            && read(&child, DATA) == Ok(2),
    );
    ok &= check(
        "mprotect of an unmapped range fails",
        child.mprotect(0x2000_0000, 4096, RO) == Err(Errno::ENOMEM),
    );
    ok &= check(
        "munmap removes the middle page",
        space.munmap(DATA + 4096, 4096).is_ok()
            && read(&space, DATA + 4096) == Err(Errno::EFAULT)
            && read(&space, DATA) == Ok(1)
            && read(&child, DATA + 4096) == Ok(1),
    );
    let gap = space.mmap(MmapRequest::anon(4096, Prot::RW));
    ok &= check(
        "mmap without an address takes the top of the mmap area",
        gap == Ok(rk_mm::MMAP_TOP - 4096),
    );

    space.set_brk_start(HEAP);
    ok &= check("brk grows the heap", space.brk(HEAP + 0x1800) == HEAP + 0x1800);
    ok &= check("the heap can be written", space.write(HEAP + 0x1000, &[7]).is_ok());
    ok &= check("brk below the start fails", space.brk(HEAP - 4096) == HEAP + 0x1800);
    ok &= check(
        "brk shrinks the heap",
        space.brk(HEAP) == HEAP && space.write(HEAP + 0x1000, &[7]) == Err(Errno::EFAULT),
    );
    ok &= check(
        "a string is read up to its zero byte",
        space.write(DATA + 4000, b"hello\0").is_ok()
            && space.read_cstr(DATA + 4000, 64).as_deref() == Ok(&b"hello"[..]),
    );
    let mut long = [b'a'; 301];
    long[300] = 0;
    ok &= check(
        "a string longer than one read chunk is read whole",
        space.write(DATA + 200, &long).is_ok()
            && space.read_cstr(DATA + 200, 4096).as_deref() == Ok(&long[..300])
            && space.read_cstr(DATA + 200, 300) == Err(Errno::ENAMETOOLONG),
    );
    ok &= check(
        "a string that runs into an unmapped page is a bad address",
        space.write(DATA + 4000, &[b'x'; 96]).is_ok()
            && space.read_cstr(DATA + 4000, 4096) == Err(Errno::EFAULT),
    );
    ok &= mremap_checks(&space, &read);
    ok
}

/// `mremap` grows an area in place, moves it with its pages, and gives the errors of Linux.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn mremap_checks(
    space: &rk_mm::AddressSpace,
    read: &dyn Fn(&rk_mm::AddressSpace, usize) -> Result<u64, rk_abi::Errno>,
) -> bool {
    use rk_abi::Errno;
    use rk_mm::{MmapRequest, Prot, Remap};

    const AREA: usize = 0x3000_0000;
    const MOVE: Remap = Remap { may_move: true, fixed: false, dont_unmap: false, new_addr: 0 };
    let fixed = |addr| MmapRequest { addr, fixed: true, ..MmapRequest::anon(4096, Prot::RW) };
    let mut ok = check(
        "an area for mremap",
        space.mmap(fixed(AREA)).is_ok() && space.write(AREA, &5u64.to_le_bytes()).is_ok(),
    );
    ok &= check(
        "mremap grows the area in place",
        space.mremap(AREA, 4096, 2 * 4096, Remap::default()) == Ok(AREA)
            && space.write(AREA + 4096, &[1]).is_ok(),
    );
    ok &= check(
        "mremap without MREMAP_MAYMOVE cannot grow into an area",
        space.mmap(fixed(AREA + 2 * 4096)).is_ok()
            && space.mremap(AREA, 2 * 4096, 3 * 4096, Remap::default()) == Err(Errno::ENOMEM),
    );
    let moved = space.mremap(AREA, 2 * 4096, 3 * 4096, MOVE);
    ok &= check(
        "mremap moves the area with its pages",
        moved.is_ok_and(|to| to != AREA && read(space, to) == Ok(5))
            && read(space, AREA) == Err(Errno::EFAULT),
    );
    ok &= check(
        "mremap of an unmapped address fails",
        space.mremap(AREA, 4096, 4096, MOVE) == Err(Errno::EFAULT),
    );
    ok &= check(
        "mremap of an address that is not aligned fails",
        space.mremap(AREA + 1, 4096, 4096, MOVE) == Err(Errno::EINVAL),
    );
    ok
}

/// The content of /etc/motd in the initramfs that `cargo xtask boot-test` makes.
const MOTD: &[u8] = b"rukernel initramfs\n";

/// Reads the initramfs that `cargo xtask boot-test` makes: a file, a symbolic link, a hard link
/// and a directory entry list.
fn initramfs_test() -> bool {
    let Some(fs) = crate::rootfs::context() else {
        return check("the root file system is there", false);
    };
    let read = |path: &[u8]| -> Option<alloc::vec::Vec<u8>> {
        let at = fs.resolve(fs.root(), path, true).ok()?;
        rk_vfs::file::read_all(at.inode()).ok()
    };
    let mut ok =
        check("/etc/motd has the correct content", read(b"/etc/motd").as_deref() == Some(MOTD));
    ok &= check("/motd follows the symbolic link", read(b"/motd").as_deref() == Some(MOTD));
    ok &= check(
        "/etc/motd.link is a hard link",
        fs.resolve(fs.root(), b"/etc/motd.link", false)
            .map(|at| at.inode().metadata())
            .is_ok_and(|m| m.nlink == 2),
    );
    ok &= check(
        "/init is executable",
        fs.resolve(fs.root(), b"/init", false)
            .map(|at| at.inode().metadata())
            .is_ok_and(|m| m.mode & 0o111 != 0),
    );
    ok &= check("/missing is not there", fs.resolve(fs.root(), b"/missing", true).is_err());
    ok
}

/// The address of the guest and of the gateway in the user network of QEMU.
#[cfg(target_arch = "x86_64")]
const QEMU_GUEST_IP: [u8; 4] = [10, 0, 2, 15];
#[cfg(target_arch = "x86_64")]
const QEMU_GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];

/// The kernel finds the virtio-net device of the user network of QEMU, sends an ARP request for
/// the gateway and receives the reply. The loopback device gives back a frame.
#[cfg(target_arch = "x86_64")]
fn net_test() -> bool {
    use rk_abi::native::if_ether::ETH_P_ARP;
    use rk_net::arp::ArpPacket;
    use rk_net::buf::NetBuf;
    use rk_net::dev;
    use rk_net::ether::{EthHeader, MacAddr};

    dev::init();
    rk_drv_virtio::init();
    let mut ok = true;
    if let Some(lo) = dev::by_name("lo") {
        ok &= check("lo has the interface index 1", lo.ifindex() == 1);
        lo.set_up(true);
        let sent = ArpPacket::request(MacAddr::ZERO, [127, 0, 0, 1], [127, 0, 0, 1])
            .to_frame(MacAddr::ZERO);
        let ok_tx = lo.transmit(sent.clone()).is_ok();
        let mut back = None;
        lo.poll(8, &mut |_, b| back = Some(b));
        ok &= check(
            "lo gives back the frame",
            ok_tx && back.is_some_and(|b: NetBuf| b.data() == sent.data()),
        );
    } else {
        ok &= check("lo is there", false);
    }
    let Some(eth) = dev::by_name("eth0") else {
        return check("eth0 is there", false);
    };
    ok &= check("eth0 has a MAC address", eth.mac() != MacAddr::ZERO && !eth.mac().is_multicast());
    eth.set_up(true);
    ok &= check("the link of eth0 is up", eth.flags() & rk_net::consts::IFF_RUNNING != 0);

    // The user network of QEMU answers an ARP request for the gateway. A frame can be lost, so
    // the request goes again after each wait of 200 ms, five times at most.
    let request = ArpPacket::request(eth.mac(), QEMU_GUEST_IP, QEMU_GATEWAY_IP);
    let mut reply = None;
    for _ in 0..5 {
        if eth.transmit(request.to_frame(MacAddr::BROADCAST)).is_err() {
            break;
        }
        let deadline = time::nanos() + 200_000_000;
        while reply.is_none() && time::nanos() < deadline {
            eth.poll(16, &mut |_, mut frame| {
                let is_arp = EthHeader::pull(&mut frame).is_some_and(|h| {
                    u32::from(h.ethertype) == ETH_P_ARP && h.dst == request.sender_mac
                });
                let p = ArpPacket::parse(frame.data()).filter(|_| is_arp);
                if let Some(p) = p.filter(|p| p.is_reply() && p.sender_ip == QEMU_GATEWAY_IP) {
                    reply = Some(p);
                }
            });
            core::hint::spin_loop();
        }
        if reply.is_some() {
            break;
        }
    }
    let stats = eth.stats();
    println!("rk.test: eth0 sent {} frames and received {}", stats.tx_packets, stats.rx_packets);
    match reply {
        Some(p) => {
            println!("rk.test: ARP reply: 10.0.2.2 is at {}", p.sender_mac);
            ok &= check("the gateway answers the ARP request", p.target_ip == QEMU_GUEST_IP);
        }
        None => ok &= check("the gateway answers the ARP request", false),
    }
    ok
}
