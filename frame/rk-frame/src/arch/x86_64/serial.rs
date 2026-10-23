//! The 16550 UART at COM1, the early console.
//!
//! The kernel writes the boot log here before any other device works. The console is polled. The
//! interrupt driven tty comes in milestone R1.

use super::io::Port;

const COM1: u16 = 0x3f8;

/// The registers of COM1, by their offset from the base port.
struct Uart {
    data: Port,
    int_enable: Port,
    fifo: Port,
    line_control: Port,
    modem_control: Port,
    line_status: Port,
}

// SAFETY: COM1 is a legacy UART that rk-frame owns. Its registers have no effect on memory.
const UART: Uart = unsafe {
    Uart {
        data: Port::new(COM1),
        int_enable: Port::new(COM1 + 1),
        fifo: Port::new(COM1 + 2),
        line_control: Port::new(COM1 + 3),
        modem_control: Port::new(COM1 + 4),
        line_status: Port::new(COM1 + 5),
    }
};

/// Sets 115200 baud, 8 data bits, no parity and one stop bit, and turns the interrupts off.
pub(crate) fn init() {
    UART.int_enable.write(0x00);
    UART.line_control.write(0x80); // Set DLAB to write the divisor.
    UART.data.write(0x01); // Divisor 1 is 115200 baud.
    UART.int_enable.write(0x00);
    UART.line_control.write(0x03); // 8N1, DLAB off.
    UART.fifo.write(0xc7); // FIFO on, clear both FIFOs, 14 byte threshold.
    UART.modem_control.write(0x03); // DTR and RTS.
}

/// Writes bytes to COM1. A line feed becomes a carriage return and a line feed.
pub(crate) fn write_bytes(bytes: &[u8]) {
    for &b in bytes {
        if b == b'\n' {
            put(b'\r');
        }
        put(b);
    }
}

fn put(b: u8) {
    // Bit 5 of the line status is set when the transmit holding register is empty.
    while UART.line_status.read() & 0x20 == 0 {
        core::hint::spin_loop();
    }
    UART.data.write(b);
}
