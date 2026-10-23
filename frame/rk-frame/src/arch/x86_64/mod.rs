//! x86-64.

mod boot;
mod gdt;
mod idt;
mod io;
pub(crate) mod serial;
pub(crate) mod trap;

use io::Port;

/// Sets up the CPU tables of the boot CPU: the GDT, the TSS and the IDT.
pub(crate) fn init_cpu() {
    gdt::init();
    idt::init();
}

/// Handles an interrupt from a device or the local APIC.
fn interrupt(vector: u8) {
    crate::console::_print_panic(format_args!("rk-frame: spurious interrupt on vector {vector}\n"));
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
