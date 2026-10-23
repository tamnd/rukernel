//! The boot self tests.
//!
//! `rk.test=NAME` on the command line runs one test and stops the virtual machine with the result.
//! `cargo xtask boot-test` boots the kernel one time for each test.

use core::sync::atomic::{AtomicU64, Ordering};
use rk_frame::addr::VirtAddr;
use rk_frame::mm::{self, Frame};
use rk_frame::println;
use rk_frame::trap::{self, Fault};

/// Runs the test `name`. Gives `true` when it passes.
pub(crate) fn run(name: &str) -> bool {
    match name {
        "boot" => true,
        "trap" => trap_test(),
        "mm" => mm_test(),
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
