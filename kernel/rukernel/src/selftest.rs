//! The boot self tests.
//!
//! `rk.test=NAME` on the command line runs one test and stops the virtual machine with the result.
//! `cargo xtask boot-test` boots the kernel one time for each test.

use rk_frame::addr::VirtAddr;
use rk_frame::println;
use rk_frame::trap::{self, Fault};

/// Runs the test `name`. Gives `true` when it passes.
pub(crate) fn run(name: &str) -> bool {
    match name {
        "boot" => true,
        "trap" => trap_test(),
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
