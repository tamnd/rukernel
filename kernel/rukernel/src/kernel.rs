//! The main function and the panic handler.

use rk_frame::boot::BootInfo;
use rk_frame::{arch, println};

/// The release that the kernel claims, per spec/17-upstream-tracking.md section 17.4.
const UNAME_RELEASE: &str = "7.3.0-rukernel";

/// The exit code for a passed self test. QEMU exits with the status 33.
const EXIT_PASS: u32 = 0x10;
/// The exit code for a failed self test or a panic. QEMU exits with the status 35.
const EXIT_FAIL: u32 = 0x11;

rk_frame::kernel_main!(main);

fn main(boot: &'static BootInfo) -> ! {
    println!(
        "rukernel {} ({UNAME_RELEASE}) {} booting with {}",
        env!("CARGO_PKG_VERSION"),
        arch::UNAME_MACHINE,
        boot.protocol()
    );
    println!("command line: {}", boot.cmdline());
    for r in boot.memory() {
        println!(
            "memory: [{:#014x}-{:#014x}] {}",
            r.start.get(),
            r.start.get() + r.len - 1,
            r.kind
        );
    }
    println!("memory: {} MiB usable", boot.usable_bytes() >> 20);

    if let Some(test) = param(boot.cmdline(), "rk.test") {
        let passed = match test {
            "boot" => true,
            other => {
                println!("rk.test: unknown test {other}");
                false
            }
        };
        println!("rk.test={test}: {}", if passed { "pass" } else { "fail" });
        arch::qemu_exit(if passed { EXIT_PASS } else { EXIT_FAIL });
    }

    println!("rukernel: nothing to run yet, the CPU stops");
    arch::halt_forever()
}

/// Gives the value of `name=value` on the command line.
fn param<'a>(cmdline: &'a str, name: &str) -> Option<&'a str> {
    cmdline.split_ascii_whitespace().find_map(|w| w.strip_prefix(name)?.strip_prefix('='))
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    rk_frame::console::_print_panic(format_args!("kernel panic: {info}\n"));
    arch::qemu_exit(EXIT_FAIL)
}
