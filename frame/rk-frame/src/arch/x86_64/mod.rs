//! x86-64.

pub(crate) mod apic;
mod boot;
mod boot_params;
mod gdt;
mod idt;
mod io;
pub(crate) mod paging;
pub(crate) mod serial;
pub(crate) mod task;
pub(crate) mod trap;
pub(crate) mod user;

use io::Port;

/// Sets up the CPU tables of the boot CPU: the GDT, the TSS and the IDT. Also sets up the
/// `syscall` instruction.
pub(crate) fn init_cpu() {
    gdt::init();
    idt::init();
    user::init();
}

/// Handles an interrupt from a device or the local APIC.
fn interrupt(vector: u8) {
    if !apic::handle(vector) {
        crate::console::_print_panic(format_args!(
            "rk-frame: spurious interrupt on vector {vector}\n"
        ));
        apic::eoi();
    }
}

/// The timer values that the architecture independent code reads.
pub(crate) mod timer {
    pub(crate) use super::apic::{HZ, TICKS, TIMER_HZ};
}

/// Interrupt control on this CPU.
///
/// The interrupt handlers use only atomic values and the local APIC. They take no lock, so an
/// interrupt cannot stop on a lock that the interrupted code holds.
pub(crate) mod irq {
    /// Lets this CPU take interrupts.
    pub(crate) fn enable() {
        // SAFETY: the IDT has a gate for each vector, and the handlers take no locks.
        unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
    }

    /// Stops this CPU from taking interrupts.
    pub(crate) fn disable() {
        // SAFETY: `cli` changes only the interrupt flag.
        unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
    }

    /// Tells if this CPU takes interrupts.
    pub(crate) fn enabled() -> bool {
        let flags: u64;
        // SAFETY: `pushfq` and `pop` read the flags through the stack and change nothing else.
        unsafe {
            core::arch::asm!("pushfq", "pop {}", out(reg) flags, options(nomem, preserves_flags))
        };
        flags & (1 << 9) != 0
    }

    /// Lets this CPU take interrupts and waits for the next one. `sti` takes effect after the next
    /// instruction, so an interrupt that comes before `hlt` still wakes the CPU.
    pub(crate) fn wait() {
        // SAFETY: as for `enable`. `hlt` waits for an interrupt and changes no memory.
        unsafe { core::arch::asm!("sti", "hlt", options(nomem, nostack)) };
    }
}

/// Stops this CPU with interrupts off. The CPU does not continue.
pub fn halt_forever() -> ! {
    loop {
        // SAFETY: `cli` and `hlt` change no memory. With interrupts off, the CPU stays halted.
        unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

/// Stops the virtual machine with an exit code, through the `isa-debug-exit` device at port 0xf4.
/// QEMU exits with the status `(code << 1) | 1`. If the device is not there, the CPU stops.
pub fn qemu_exit(code: u32) -> ! {
    // SAFETY: port 0xf4 is the QEMU debug exit device, or nothing on other machines.
    let port = unsafe { Port::new(0xf4) };
    port.write_u32(code);
    halt_forever()
}
