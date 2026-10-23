// rk-abigen generated this file from Linux 7.3, from <asm/termbits.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The flags, the control characters and the speeds of `struct termios`.

/// Hang up.
pub const B0: u32 = 0;
/// `BS0` from `<asm/termbits.h>`.
pub const BS0: u32 = 0;
/// `CR0` from `<asm/termbits.h>`.
pub const CR0: u32 = 0;
/// `CS5` from `<asm/termbits.h>`.
pub const CS5: u32 = 0;
/// `FF0` from `<asm/termbits.h>`.
pub const FF0: u32 = 0;
/// `NL0` from `<asm/termbits.h>`.
pub const NL0: u32 = 0;
/// `TAB0` from `<asm/termbits.h>`.
pub const TAB0: u32 = 0;
/// Discard data received but not yet read.
pub const TCIFLUSH: u32 = 0;
/// Suspend output.
pub const TCOOFF: u32 = 0;
/// `TCSANOW` from `<asm/termbits.h>`.
pub const TCSANOW: u32 = 0;
/// `VINTR` from `<asm/termbits.h>`.
pub const VINTR: u32 = 0;
/// `VT0` from `<asm/termbits.h>`.
pub const VT0: u32 = 0;
/// `B50` from `<asm/termbits.h>`.
pub const B50: u32 = 1;
/// Ignore break condition.
pub const IGNBRK: u32 = 1;
/// `ISIG` from `<asm/termbits.h>`.
pub const ISIG: u32 = 1;
/// Perform output processing.
pub const OPOST: u32 = 1;
/// Discard data written but not yet sent.
pub const TCOFLUSH: u32 = 1;
/// Restart suspended output.
pub const TCOON: u32 = 1;
/// `TCSADRAIN` from `<asm/termbits.h>`.
pub const TCSADRAIN: u32 = 1;
/// `VQUIT` from `<asm/termbits.h>`.
pub const VQUIT: u32 = 1;
/// `B75` from `<asm/termbits.h>`.
pub const B75: u32 = 2;
/// Signal interrupt on break.
pub const BRKINT: u32 = 2;
/// `ICANON` from `<asm/termbits.h>`.
pub const ICANON: u32 = 2;
/// `OLCUC` from `<asm/termbits.h>`.
pub const OLCUC: u32 = 2;
/// Send a STOP character.
pub const TCIOFF: u32 = 2;
/// Discard all pending data.
pub const TCIOFLUSH: u32 = 2;
/// `TCSAFLUSH` from `<asm/termbits.h>`.
pub const TCSAFLUSH: u32 = 2;
/// `VERASE` from `<asm/termbits.h>`.
pub const VERASE: u32 = 2;
/// `B110` from `<asm/termbits.h>`.
pub const B110: u32 = 3;
/// Send a START character.
pub const TCION: u32 = 3;
/// `VKILL` from `<asm/termbits.h>`.
pub const VKILL: u32 = 3;
/// `B134` from `<asm/termbits.h>`.
pub const B134: u32 = 4;
/// Ignore characters with parity errors.
pub const IGNPAR: u32 = 4;
/// `ONLCR` from `<asm/termbits.h>`.
pub const ONLCR: u32 = 4;
/// `VEOF` from `<asm/termbits.h>`.
pub const VEOF: u32 = 4;
/// `XCASE` from `<asm/termbits.h>`.
pub const XCASE: u32 = 4;
/// `B150` from `<asm/termbits.h>`.
pub const B150: u32 = 5;
/// `VTIME` from `<asm/termbits.h>`.
pub const VTIME: u32 = 5;
/// `B200` from `<asm/termbits.h>`.
pub const B200: u32 = 6;
/// `VMIN` from `<asm/termbits.h>`.
pub const VMIN: u32 = 6;
/// `B300` from `<asm/termbits.h>`.
pub const B300: u32 = 7;
/// `VSWTC` from `<asm/termbits.h>`.
pub const VSWTC: u32 = 7;
/// `B600` from `<asm/termbits.h>`.
pub const B600: u32 = 8;
/// `ECHO` from `<asm/termbits.h>`.
pub const ECHO: u32 = 8;
/// `OCRNL` from `<asm/termbits.h>`.
pub const OCRNL: u32 = 8;
/// Mark parity and framing errors.
pub const PARMRK: u32 = 8;
/// `VSTART` from `<asm/termbits.h>`.
pub const VSTART: u32 = 8;
/// `B1200` from `<asm/termbits.h>`.
pub const B1200: u32 = 9;
/// `VSTOP` from `<asm/termbits.h>`.
pub const VSTOP: u32 = 9;
/// `B1800` from `<asm/termbits.h>`.
pub const B1800: u32 = 10;
/// `VSUSP` from `<asm/termbits.h>`.
pub const VSUSP: u32 = 10;
/// `B2400` from `<asm/termbits.h>`.
pub const B2400: u32 = 11;
/// `VEOL` from `<asm/termbits.h>`.
pub const VEOL: u32 = 11;
/// `B4800` from `<asm/termbits.h>`.
pub const B4800: u32 = 12;
/// `VREPRINT` from `<asm/termbits.h>`.
pub const VREPRINT: u32 = 12;
/// `B9600` from `<asm/termbits.h>`.
pub const B9600: u32 = 13;
/// `VDISCARD` from `<asm/termbits.h>`.
pub const VDISCARD: u32 = 13;
/// `B19200` from `<asm/termbits.h>`.
pub const B19200: u32 = 14;
/// The same value as `B19200`.
pub const EXTA: u32 = 14;
/// `VWERASE` from `<asm/termbits.h>`.
pub const VWERASE: u32 = 14;
/// `B38400` from `<asm/termbits.h>`.
pub const B38400: u32 = 15;
/// The same value as `B38400`.
pub const EXTB: u32 = 15;
/// `VLNEXT` from `<asm/termbits.h>`.
pub const VLNEXT: u32 = 15;
/// `CS6` from `<asm/termbits.h>`.
pub const CS6: u32 = 16;
/// `ECHOE` from `<asm/termbits.h>`.
pub const ECHOE: u32 = 16;
/// Shift from CBAUD to CIBAUD.
pub const IBSHIFT: u32 = 16;
/// Enable input parity check.
pub const INPCK: u32 = 16;
/// `ONOCR` from `<asm/termbits.h>`.
pub const ONOCR: u32 = 16;
/// `VEOL2` from `<asm/termbits.h>`.
pub const VEOL2: u32 = 16;
/// `NCCS` from `<asm/termbits.h>`.
pub const NCCS: u32 = 19;
/// `CS7` from `<asm/termbits.h>`.
pub const CS7: u32 = 32;
/// `ECHOK` from `<asm/termbits.h>`.
pub const ECHOK: u32 = 32;
/// Strip 8th bit off characters.
pub const ISTRIP: u32 = 32;
/// `ONLRET` from `<asm/termbits.h>`.
pub const ONLRET: u32 = 32;
/// `CS8` from `<asm/termbits.h>`.
pub const CS8: u32 = 48;
/// `CSIZE` from `<asm/termbits.h>`.
pub const CSIZE: u32 = 48;
/// `CSTOPB` from `<asm/termbits.h>`.
pub const CSTOPB: u32 = 64;
/// `ECHONL` from `<asm/termbits.h>`.
pub const ECHONL: u32 = 64;
/// Map NL to CR on input.
pub const INLCR: u32 = 64;
/// `OFILL` from `<asm/termbits.h>`.
pub const OFILL: u32 = 64;
/// `CREAD` from `<asm/termbits.h>`.
pub const CREAD: u32 = 128;
/// Ignore CR.
pub const IGNCR: u32 = 128;
/// `NOFLSH` from `<asm/termbits.h>`.
pub const NOFLSH: u32 = 128;
/// `OFDEL` from `<asm/termbits.h>`.
pub const OFDEL: u32 = 128;
/// Map CR to NL on input.
pub const ICRNL: u32 = 0x100;
/// `NL1` from `<asm/termbits.h>`.
pub const NL1: u32 = 0x100;
/// `NLDLY` from `<asm/termbits.h>`.
pub const NLDLY: u32 = 0x100;
/// `PARENB` from `<asm/termbits.h>`.
pub const PARENB: u32 = 0x100;
/// `TOSTOP` from `<asm/termbits.h>`.
pub const TOSTOP: u32 = 0x100;
/// `CR1` from `<asm/termbits.h>`.
pub const CR1: u32 = 0x200;
/// `ECHOCTL` from `<asm/termbits.h>`.
pub const ECHOCTL: u32 = 0x200;
/// `IUCLC` from `<asm/termbits.h>`.
pub const IUCLC: u32 = 0x200;
/// `PARODD` from `<asm/termbits.h>`.
pub const PARODD: u32 = 0x200;
/// `CR2` from `<asm/termbits.h>`.
pub const CR2: u32 = 0x400;
/// `ECHOPRT` from `<asm/termbits.h>`.
pub const ECHOPRT: u32 = 0x400;
/// `HUPCL` from `<asm/termbits.h>`.
pub const HUPCL: u32 = 0x400;
/// `IXON` from `<asm/termbits.h>`.
pub const IXON: u32 = 0x400;
/// `CR3` from `<asm/termbits.h>`.
pub const CR3: u32 = 0x600;
/// `CRDLY` from `<asm/termbits.h>`.
pub const CRDLY: u32 = 0x600;
/// `CLOCAL` from `<asm/termbits.h>`.
pub const CLOCAL: u32 = 0x800;
/// `ECHOKE` from `<asm/termbits.h>`.
pub const ECHOKE: u32 = 0x800;
/// Any character will restart after stop.
pub const IXANY: u32 = 0x800;
/// `TAB1` from `<asm/termbits.h>`.
pub const TAB1: u32 = 0x800;
/// `BOTHER` from `<asm/termbits.h>`.
pub const BOTHER: u32 = 0x1000;
/// `CBAUDEX` from `<asm/termbits.h>`.
pub const CBAUDEX: u32 = 0x1000;
/// `FLUSHO` from `<asm/termbits.h>`.
pub const FLUSHO: u32 = 0x1000;
/// `IXOFF` from `<asm/termbits.h>`.
pub const IXOFF: u32 = 0x1000;
/// `TAB2` from `<asm/termbits.h>`.
pub const TAB2: u32 = 0x1000;
/// `B57600` from `<asm/termbits.h>`.
pub const B57600: u32 = 0x1001;
/// `B115200` from `<asm/termbits.h>`.
pub const B115200: u32 = 0x1002;
/// `B230400` from `<asm/termbits.h>`.
pub const B230400: u32 = 0x1003;
/// `B460800` from `<asm/termbits.h>`.
pub const B460800: u32 = 0x1004;
/// `B500000` from `<asm/termbits.h>`.
pub const B500000: u32 = 0x1005;
/// `B576000` from `<asm/termbits.h>`.
pub const B576000: u32 = 0x1006;
/// `B921600` from `<asm/termbits.h>`.
pub const B921600: u32 = 0x1007;
/// `B1000000` from `<asm/termbits.h>`.
pub const B1000000: u32 = 0x1008;
/// `B1152000` from `<asm/termbits.h>`.
pub const B1152000: u32 = 0x1009;
/// `B1500000` from `<asm/termbits.h>`.
pub const B1500000: u32 = 0x100a;
/// `B2000000` from `<asm/termbits.h>`.
pub const B2000000: u32 = 0x100b;
/// `B2500000` from `<asm/termbits.h>`.
pub const B2500000: u32 = 0x100c;
/// `B3000000` from `<asm/termbits.h>`.
pub const B3000000: u32 = 0x100d;
/// `B3500000` from `<asm/termbits.h>`.
pub const B3500000: u32 = 0x100e;
/// `B4000000` from `<asm/termbits.h>`.
pub const B4000000: u32 = 0x100f;
/// `CBAUD` from `<asm/termbits.h>`.
pub const CBAUD: u32 = 0x100f;
/// `TAB3` from `<asm/termbits.h>`.
pub const TAB3: u32 = 0x1800;
/// `TABDLY` from `<asm/termbits.h>`.
pub const TABDLY: u32 = 0x1800;
/// `XTABS` from `<asm/termbits.h>`.
pub const XTABS: u32 = 0x1800;
/// `BS1` from `<asm/termbits.h>`.
pub const BS1: u32 = 0x2000;
/// `BSDLY` from `<asm/termbits.h>`.
pub const BSDLY: u32 = 0x2000;
/// `IMAXBEL` from `<asm/termbits.h>`.
pub const IMAXBEL: u32 = 0x2000;
/// `IUTF8` from `<asm/termbits.h>`.
pub const IUTF8: u32 = 0x4000;
/// `PENDIN` from `<asm/termbits.h>`.
pub const PENDIN: u32 = 0x4000;
/// `VT1` from `<asm/termbits.h>`.
pub const VT1: u32 = 0x4000;
/// `VTDLY` from `<asm/termbits.h>`.
pub const VTDLY: u32 = 0x4000;
/// `FF1` from `<asm/termbits.h>`.
pub const FF1: u32 = 0x8000;
/// `FFDLY` from `<asm/termbits.h>`.
pub const FFDLY: u32 = 0x8000;
/// `IEXTEN` from `<asm/termbits.h>`.
pub const IEXTEN: u32 = 0x8000;
/// `EXTPROC` from `<asm/termbits.h>`.
pub const EXTPROC: u32 = 0x1_0000;
/// Input baud rate.
pub const CIBAUD: u32 = 0x100f_0000;
/// Address bit.
pub const ADDRB: u32 = 0x2000_0000;
/// Mark or space (stick) parity.
pub const CMSPAR: u32 = 0x4000_0000;
/// Flow control.
pub const CRTSCTS: u32 = 0x8000_0000;
