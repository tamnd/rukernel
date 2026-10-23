// rk-abigen generated this file from Linux 7.3, from <asm/ioctls.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The generic `ioctl` commands of terminals and files.

/// `TIOCPKT_DATA` from `<asm/ioctls.h>`.
pub const TIOCPKT_DATA: u32 = 0;
/// `TIOCPKT_FLUSHREAD` from `<asm/ioctls.h>`.
pub const TIOCPKT_FLUSHREAD: u32 = 1;
/// Transmitter physically empty.
pub const TIOCSER_TEMT: u32 = 1;
/// `TIOCPKT_FLUSHWRITE` from `<asm/ioctls.h>`.
pub const TIOCPKT_FLUSHWRITE: u32 = 2;
/// `TIOCPKT_STOP` from `<asm/ioctls.h>`.
pub const TIOCPKT_STOP: u32 = 4;
/// `TIOCPKT_START` from `<asm/ioctls.h>`.
pub const TIOCPKT_START: u32 = 8;
/// `TIOCPKT_NOSTOP` from `<asm/ioctls.h>`.
pub const TIOCPKT_NOSTOP: u32 = 16;
/// `TIOCPKT_DOSTOP` from `<asm/ioctls.h>`.
pub const TIOCPKT_DOSTOP: u32 = 32;
/// `TIOCPKT_IOCTL` from `<asm/ioctls.h>`.
pub const TIOCPKT_IOCTL: u32 = 64;
/// `TCGETS` from `<asm/ioctls.h>`.
pub const TCGETS: u32 = 0x5401;
/// `TCSETS` from `<asm/ioctls.h>`.
pub const TCSETS: u32 = 0x5402;
/// `TCSETSW` from `<asm/ioctls.h>`.
pub const TCSETSW: u32 = 0x5403;
/// `TCSETSF` from `<asm/ioctls.h>`.
pub const TCSETSF: u32 = 0x5404;
/// `TCGETA` from `<asm/ioctls.h>`.
pub const TCGETA: u32 = 0x5405;
/// `TCSETA` from `<asm/ioctls.h>`.
pub const TCSETA: u32 = 0x5406;
/// `TCSETAW` from `<asm/ioctls.h>`.
pub const TCSETAW: u32 = 0x5407;
/// `TCSETAF` from `<asm/ioctls.h>`.
pub const TCSETAF: u32 = 0x5408;
/// `TCSBRK` from `<asm/ioctls.h>`.
pub const TCSBRK: u32 = 0x5409;
/// `TCXONC` from `<asm/ioctls.h>`.
pub const TCXONC: u32 = 0x540a;
/// `TCFLSH` from `<asm/ioctls.h>`.
pub const TCFLSH: u32 = 0x540b;
/// `TIOCEXCL` from `<asm/ioctls.h>`.
pub const TIOCEXCL: u32 = 0x540c;
/// `TIOCNXCL` from `<asm/ioctls.h>`.
pub const TIOCNXCL: u32 = 0x540d;
/// `TIOCSCTTY` from `<asm/ioctls.h>`.
pub const TIOCSCTTY: u32 = 0x540e;
/// `TIOCGPGRP` from `<asm/ioctls.h>`.
pub const TIOCGPGRP: u32 = 0x540f;
/// `TIOCSPGRP` from `<asm/ioctls.h>`.
pub const TIOCSPGRP: u32 = 0x5410;
/// `TIOCOUTQ` from `<asm/ioctls.h>`.
pub const TIOCOUTQ: u32 = 0x5411;
/// `TIOCSTI` from `<asm/ioctls.h>`.
pub const TIOCSTI: u32 = 0x5412;
/// `TIOCGWINSZ` from `<asm/ioctls.h>`.
pub const TIOCGWINSZ: u32 = 0x5413;
/// `TIOCSWINSZ` from `<asm/ioctls.h>`.
pub const TIOCSWINSZ: u32 = 0x5414;
/// `TIOCMGET` from `<asm/ioctls.h>`.
pub const TIOCMGET: u32 = 0x5415;
/// `TIOCMBIS` from `<asm/ioctls.h>`.
pub const TIOCMBIS: u32 = 0x5416;
/// `TIOCMBIC` from `<asm/ioctls.h>`.
pub const TIOCMBIC: u32 = 0x5417;
/// `TIOCMSET` from `<asm/ioctls.h>`.
pub const TIOCMSET: u32 = 0x5418;
/// `TIOCGSOFTCAR` from `<asm/ioctls.h>`.
pub const TIOCGSOFTCAR: u32 = 0x5419;
/// `TIOCSSOFTCAR` from `<asm/ioctls.h>`.
pub const TIOCSSOFTCAR: u32 = 0x541a;
/// `FIONREAD` from `<asm/ioctls.h>`.
pub const FIONREAD: u32 = 0x541b;
/// The same value as `FIONREAD`.
pub const TIOCINQ: u32 = 0x541b;
/// `TIOCLINUX` from `<asm/ioctls.h>`.
pub const TIOCLINUX: u32 = 0x541c;
/// `TIOCCONS` from `<asm/ioctls.h>`.
pub const TIOCCONS: u32 = 0x541d;
/// `TIOCGSERIAL` from `<asm/ioctls.h>`.
pub const TIOCGSERIAL: u32 = 0x541e;
/// `TIOCSSERIAL` from `<asm/ioctls.h>`.
pub const TIOCSSERIAL: u32 = 0x541f;
/// `TIOCPKT` from `<asm/ioctls.h>`.
pub const TIOCPKT: u32 = 0x5420;
/// `FIONBIO` from `<asm/ioctls.h>`.
pub const FIONBIO: u32 = 0x5421;
/// `TIOCNOTTY` from `<asm/ioctls.h>`.
pub const TIOCNOTTY: u32 = 0x5422;
/// `TIOCSETD` from `<asm/ioctls.h>`.
pub const TIOCSETD: u32 = 0x5423;
/// `TIOCGETD` from `<asm/ioctls.h>`.
pub const TIOCGETD: u32 = 0x5424;
/// Needed for POSIX tcsendbreak().
pub const TCSBRKP: u32 = 0x5425;
/// BSD compatibility.
pub const TIOCSBRK: u32 = 0x5427;
/// BSD compatibility.
pub const TIOCCBRK: u32 = 0x5428;
/// Return the session ID of FD.
pub const TIOCGSID: u32 = 0x5429;
/// `TIOCGRS485` from `<asm/ioctls.h>`.
pub const TIOCGRS485: u32 = 0x542e;
/// `TIOCSRS485` from `<asm/ioctls.h>`.
pub const TIOCSRS485: u32 = 0x542f;
/// SYS5 TCGETX compatibility.
pub const TCGETX: u32 = 0x5432;
/// `TCSETX` from `<asm/ioctls.h>`.
pub const TCSETX: u32 = 0x5433;
/// `TCSETXF` from `<asm/ioctls.h>`.
pub const TCSETXF: u32 = 0x5434;
/// `TCSETXW` from `<asm/ioctls.h>`.
pub const TCSETXW: u32 = 0x5435;
/// `TIOCVHANGUP` from `<asm/ioctls.h>`.
pub const TIOCVHANGUP: u32 = 0x5437;
/// Safely open the slave.
pub const TIOCGPTPEER: u32 = 0x5441;
/// `FIONCLEX` from `<asm/ioctls.h>`.
pub const FIONCLEX: u32 = 0x5450;
/// `FIOCLEX` from `<asm/ioctls.h>`.
pub const FIOCLEX: u32 = 0x5451;
/// `FIOASYNC` from `<asm/ioctls.h>`.
pub const FIOASYNC: u32 = 0x5452;
/// `TIOCSERCONFIG` from `<asm/ioctls.h>`.
pub const TIOCSERCONFIG: u32 = 0x5453;
/// `TIOCSERGWILD` from `<asm/ioctls.h>`.
pub const TIOCSERGWILD: u32 = 0x5454;
/// `TIOCSERSWILD` from `<asm/ioctls.h>`.
pub const TIOCSERSWILD: u32 = 0x5455;
/// `TIOCGLCKTRMIOS` from `<asm/ioctls.h>`.
pub const TIOCGLCKTRMIOS: u32 = 0x5456;
/// `TIOCSLCKTRMIOS` from `<asm/ioctls.h>`.
pub const TIOCSLCKTRMIOS: u32 = 0x5457;
/// For debugging only.
pub const TIOCSERGSTRUCT: u32 = 0x5458;
/// Get line status register.
pub const TIOCSERGETLSR: u32 = 0x5459;
/// Get multiport config.
pub const TIOCSERGETMULTI: u32 = 0x545a;
/// Set multiport config.
pub const TIOCSERSETMULTI: u32 = 0x545b;
/// Wait for a change on serial input line(s).
pub const TIOCMIWAIT: u32 = 0x545c;
/// Read serial port \_\_inline\_\_ interrupt counts.
pub const TIOCGICOUNT: u32 = 0x545d;
/// `FIOQSIZE` from `<asm/ioctls.h>`.
pub const FIOQSIZE: u32 = 0x5460;
/// Lock/unlock Pty.
pub const TIOCSPTLCK: u32 = 0x4004_5431;
/// Pty: generate signal.
pub const TIOCSIG: u32 = 0x4004_5436;
/// Get Pty Number (of pty-mux device).
pub const TIOCGPTN: u32 = 0x8004_5430;
/// Get primary device node of /dev/console.
pub const TIOCGDEV: u32 = 0x8004_5432;
/// Get packet mode state.
pub const TIOCGPKT: u32 = 0x8004_5438;
/// Get Pty lock state.
pub const TIOCGPTLCK: u32 = 0x8004_5439;
/// Get exclusive mode state.
pub const TIOCGEXCL: u32 = 0x8004_5440;
