//! x86-64.

mod acpi;
pub(crate) mod apic;
mod boot;
mod boot_params;
pub(crate) mod cpu;
mod gdt;
mod idt;
pub(crate) mod io;
pub(crate) mod paging;
pub(crate) mod rtc;
pub(crate) mod serial;
pub(crate) mod smp;
pub(crate) mod task;
pub(crate) mod trap;
pub(crate) mod user;

use io::Port;

/// Sets up the CPU tables of the boot CPU: the GDT, the TSS and the IDT. Also sets up the
/// `syscall` instruction.
pub(crate) fn init_cpu() {
    gdt::init();
    // The GDT load sets GS to 0, so the GS base comes after it. `smp::start_cpus` sets the local
    // APIC ID of the boot CPU.
    cpu::init(0, 0);
    idt::init();
    user::init();
}

/// Gives 64 bits for a random seed. The value comes from `rdrand` if the CPU has it, or else from
/// the time stamp counter, which is not random but is different at each call.
pub fn random_seed() -> u64 {
    // CPUID leaf 1, ECX bit 30.
    let ecx: u32;
    // SAFETY: `cpuid` only writes the four registers. LLVM uses rbx, so the code keeps it.
    unsafe {
        core::arch::asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "mov rbx, {tmp:r}",
            tmp = out(reg) _,
            inout("eax") 1u32 => _,
            inout("ecx") 0u32 => ecx,
            out("edx") _,
            options(nomem, nostack, preserves_flags),
        );
    }
    if ecx & (1 << 30) != 0 {
        for _ in 0..10 {
            let value: u64;
            let ok: u8;
            // SAFETY: CPUID tells that the CPU has `rdrand`. It writes only the two registers and
            // the flags.
            unsafe {
                core::arch::asm!(
                    "rdrand {v}",
                    "setc {ok}",
                    v = out(reg) value,
                    ok = out(reg_byte) ok,
                    options(nomem, nostack),
                );
            }
            if ok != 0 {
                return value;
            }
        }
    }
    let (lo, hi): (u32, u32);
    // SAFETY: `rdtsc` writes only EAX and EDX.
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)) };
    (u64::from(hi) << 32) | u64::from(lo)
}

/// Handles an interrupt from a device or the local APIC.
fn interrupt(vector: u8) {
    if !smp::handle(vector) && !apic::handle(vector) {
        crate::console::_print_panic(format_args!(
            "rk-frame: spurious interrupt on vector {vector}\n"
        ));
        apic::eoi();
    }
}

/// Copies of memory that user code can write at the same time, such as the frames of user pages.
/// A `rep movs` or a `rep stos` does each copy. The compiler does not know the instruction, so it
/// cannot assume that the memory does not change, and the CPU copies whole lines when it can.
pub(crate) mod mem {
    /// Copies `len` bytes from `src` to `dst`.
    ///
    /// # Safety
    ///
    /// The two ranges must be valid kernel memory, and they must not overlap.
    pub(crate) unsafe fn copy(dst: *mut u8, src: *const u8, len: usize) {
        // A `rep movsq` copies the words, and a `rep movsb` copies the rest. QEMU without KVM does
        // each step of a `rep` alone, so a copy of words is 8 times faster there than a copy of
        // bytes.
        // SAFETY: the caller gives two valid ranges of `len` bytes. The ABI keeps the direction
        // flag clear, so the copy goes up.
        unsafe {
            core::arch::asm!(
                "rep movsq",
                "mov rcx, {rest}",
                "rep movsb",
                rest = in(reg) len % 8,
                inout("rcx") len / 8 => _,
                inout("rdi") dst => _,
                inout("rsi") src => _,
                options(nostack, preserves_flags),
            );
        }
    }

    /// Writes `len` zero bytes at `dst`.
    ///
    /// # Safety
    ///
    /// The range must be valid kernel memory.
    pub(crate) unsafe fn zero(dst: *mut u8, len: usize) {
        // As in `copy`, a `rep stosq` writes the words, and a `rep stosb` writes the rest.
        // SAFETY: as for `copy`.
        unsafe {
            core::arch::asm!(
                "rep stosq",
                "mov rcx, {rest}",
                "rep stosb",
                rest = in(reg) len % 8,
                inout("rcx") len / 8 => _,
                inout("rdi") dst => _,
                in("rax") 0u64,
                options(nostack, preserves_flags),
            );
        }
    }
}

/// The early console that the architecture independent code writes to: COM1.
pub(crate) mod console {
    pub(crate) use super::serial::{try_read, write_bytes, write_raw};
}

/// The timer values that the architecture independent code reads.
pub(crate) mod timer {
    pub(crate) use super::apic::{
        HZ, TICKS, TIMER_HZ, clock_ns, nanos, tsc_state as counter_state,
    };
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
