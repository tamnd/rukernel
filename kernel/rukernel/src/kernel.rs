//! The main function and the panic handler.

use crate::{rootfs, selftest};
use rk_frame::boot::BootInfo;
use rk_frame::{arch, println};

#[cfg(target_arch = "x86_64")]
use rk_syscall::UNAME_RELEASE;
#[cfg(not(target_arch = "x86_64"))]
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
    let frames = rk_frame::mm::frame_stats();
    println!("memory: {} of {} frames free", frames.free, frames.total);
    println!("timer: {} Hz, tick at {} Hz", rk_frame::time::timer_frequency(), rk_frame::time::HZ);

    #[cfg(target_arch = "x86_64")]
    {
        rk_sched::init();
        println!("smp: {} CPUs run", rk_frame::cpu::start_all());
    }
    rootfs::init(boot);

    let test = param(boot.cmdline(), "rk.test");
    if let Some(test) = test.filter(|&t| t != "init") {
        let passed = selftest::run(test);
        println!("rk.test={test}: {}", if passed { "pass" } else { "fail" });
        arch::qemu_exit(if passed { EXIT_PASS } else { EXIT_FAIL });
    }

    #[cfg(target_arch = "x86_64")]
    run_init(boot, test.is_some());
    #[cfg(not(target_arch = "x86_64"))]
    {
        println!("rukernel: no user mode on this architecture yet, the CPU stops");
        arch::halt_forever()
    }
}

/// Starts init and waits for it to end. Linux stops with a panic when init ends, and so does
/// rukernel. With `rk.test=init`, the test passes if init exits with the code 0.
#[cfg(target_arch = "x86_64")]
fn run_init(boot: &'static BootInfo, test: bool) -> ! {
    use alloc::vec;
    use alloc::vec::Vec;

    rk_drv_mem::init();
    rk_drv_tty::init();
    rk_net::dev::init();
    rk_drv_virtio::init();
    rk_syscall::init();
    rk_vfs::loopdev::init();
    let Some(fs) = rootfs::context() else {
        panic!("no root file system");
    };
    rootfs::make_dev(fs);
    let path = param(boot.cmdline(), "rdinit").unwrap_or("/init");
    // The words after `--` are the arguments of init, as Linux gives them.
    let mut argv = vec![Vec::from(path.as_bytes())];
    argv.extend(init_args(boot.cmdline()).map(|w| w.as_bytes().to_vec()));
    let envp = vec![b"HOME=/".to_vec(), b"TERM=linux".to_vec()];
    if let Err(e) = rk_syscall::spawn_init(fs.clone(), path.as_bytes(), argv, envp) {
        panic!("No working init found. Error {} for {path}.", e.get());
    }
    let status = rk_proc::wait_for_init();
    println!("rukernel: {} system calls", rk_syscall::count());
    if test {
        let passed = status.exit_code() == Some(0);
        println!("rk.test=init: {}", if passed { "pass" } else { "fail" });
        arch::qemu_exit(if passed { EXIT_PASS } else { EXIT_FAIL });
    }
    panic!("Attempted to kill init! exitcode={:#010x}", status.0);
}

/// Gives the value of `name=value` on the command line. A word after `--` is for init.
fn param<'a>(cmdline: &'a str, name: &str) -> Option<&'a str> {
    cmdline
        .split_ascii_whitespace()
        .take_while(|w| *w != "--")
        .find_map(|w| w.strip_prefix(name)?.strip_prefix('='))
}

/// Gives the words after `--` on the command line.
#[cfg(target_arch = "x86_64")]
fn init_args(cmdline: &str) -> impl Iterator<Item = &str> {
    cmdline.split_ascii_whitespace().skip_while(|w| *w != "--").skip(1)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    rk_frame::console::_print_panic(format_args!("kernel panic: {info}\n"));
    arch::qemu_exit(EXIT_FAIL)
}
