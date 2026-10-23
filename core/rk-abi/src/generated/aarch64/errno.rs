// rk-abigen generated this file from Linux 7.3, from <asm/errno.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The error numbers.

/// Operation not permitted.
pub const EPERM: u16 = 1;
/// No such file or directory.
pub const ENOENT: u16 = 2;
/// No such process.
pub const ESRCH: u16 = 3;
/// Interrupted system call.
pub const EINTR: u16 = 4;
/// I/O error.
pub const EIO: u16 = 5;
/// No such device or address.
pub const ENXIO: u16 = 6;
/// Argument list too long.
pub const E2BIG: u16 = 7;
/// Exec format error.
pub const ENOEXEC: u16 = 8;
/// Bad file number.
pub const EBADF: u16 = 9;
/// No child processes.
pub const ECHILD: u16 = 10;
/// Try again.
pub const EAGAIN: u16 = 11;
/// Operation would block.
pub const EWOULDBLOCK: u16 = 11;
/// Out of memory.
pub const ENOMEM: u16 = 12;
/// Permission denied.
pub const EACCES: u16 = 13;
/// Bad address.
pub const EFAULT: u16 = 14;
/// Block device required.
pub const ENOTBLK: u16 = 15;
/// Device or resource busy.
pub const EBUSY: u16 = 16;
/// File exists.
pub const EEXIST: u16 = 17;
/// Cross-device link.
pub const EXDEV: u16 = 18;
/// No such device.
pub const ENODEV: u16 = 19;
/// Not a directory.
pub const ENOTDIR: u16 = 20;
/// Is a directory.
pub const EISDIR: u16 = 21;
/// Invalid argument.
pub const EINVAL: u16 = 22;
/// File table overflow.
pub const ENFILE: u16 = 23;
/// Too many open files.
pub const EMFILE: u16 = 24;
/// Not a typewriter.
pub const ENOTTY: u16 = 25;
/// Text file busy.
pub const ETXTBSY: u16 = 26;
/// File too large.
pub const EFBIG: u16 = 27;
/// No space left on device.
pub const ENOSPC: u16 = 28;
/// Illegal seek.
pub const ESPIPE: u16 = 29;
/// Read-only file system.
pub const EROFS: u16 = 30;
/// Too many links.
pub const EMLINK: u16 = 31;
/// Broken pipe.
pub const EPIPE: u16 = 32;
/// Math argument out of domain of func.
pub const EDOM: u16 = 33;
/// Math result not representable.
pub const ERANGE: u16 = 34;
/// Resource deadlock would occur.
pub const EDEADLK: u16 = 35;
/// The same value as `EDEADLK`.
pub const EDEADLOCK: u16 = 35;
/// File name too long.
pub const ENAMETOOLONG: u16 = 36;
/// No record locks available.
pub const ENOLCK: u16 = 37;
/// Invalid system call number.
pub const ENOSYS: u16 = 38;
/// Directory not empty.
pub const ENOTEMPTY: u16 = 39;
/// Too many symbolic links encountered.
pub const ELOOP: u16 = 40;
/// No message of desired type.
pub const ENOMSG: u16 = 42;
/// Identifier removed.
pub const EIDRM: u16 = 43;
/// Channel number out of range.
pub const ECHRNG: u16 = 44;
/// Level 2 not synchronized.
pub const EL2NSYNC: u16 = 45;
/// Level 3 halted.
pub const EL3HLT: u16 = 46;
/// Level 3 reset.
pub const EL3RST: u16 = 47;
/// Link number out of range.
pub const ELNRNG: u16 = 48;
/// Protocol driver not attached.
pub const EUNATCH: u16 = 49;
/// No CSI structure available.
pub const ENOCSI: u16 = 50;
/// Level 2 halted.
pub const EL2HLT: u16 = 51;
/// Invalid exchange.
pub const EBADE: u16 = 52;
/// Invalid request descriptor.
pub const EBADR: u16 = 53;
/// Exchange full.
pub const EXFULL: u16 = 54;
/// No anode.
pub const ENOANO: u16 = 55;
/// Invalid request code.
pub const EBADRQC: u16 = 56;
/// Invalid slot.
pub const EBADSLT: u16 = 57;
/// Bad font file format.
pub const EBFONT: u16 = 59;
/// Device not a stream.
pub const ENOSTR: u16 = 60;
/// No data available.
pub const ENODATA: u16 = 61;
/// Timer expired.
pub const ETIME: u16 = 62;
/// Out of streams resources.
pub const ENOSR: u16 = 63;
/// Machine is not on the network.
pub const ENONET: u16 = 64;
/// Package not installed.
pub const ENOPKG: u16 = 65;
/// Object is remote.
pub const EREMOTE: u16 = 66;
/// Link has been severed.
pub const ENOLINK: u16 = 67;
/// Advertise error.
pub const EADV: u16 = 68;
/// Srmount error.
pub const ESRMNT: u16 = 69;
/// Communication error on send.
pub const ECOMM: u16 = 70;
/// Protocol error.
pub const EPROTO: u16 = 71;
/// Multihop attempted.
pub const EMULTIHOP: u16 = 72;
/// RFS specific error.
pub const EDOTDOT: u16 = 73;
/// Not a data message.
pub const EBADMSG: u16 = 74;
/// Bad CRC detected.
pub const EFSBADCRC: u16 = 74;
/// Value too large for defined data type.
pub const EOVERFLOW: u16 = 75;
/// Name not unique on network.
pub const ENOTUNIQ: u16 = 76;
/// File descriptor in bad state.
pub const EBADFD: u16 = 77;
/// Remote address changed.
pub const EREMCHG: u16 = 78;
/// Can not access a needed shared library.
pub const ELIBACC: u16 = 79;
/// Accessing a corrupted shared library.
pub const ELIBBAD: u16 = 80;
/// .lib section in a.out corrupted.
pub const ELIBSCN: u16 = 81;
/// Attempting to link in too many shared libraries.
pub const ELIBMAX: u16 = 82;
/// Cannot exec a shared library directly.
pub const ELIBEXEC: u16 = 83;
/// Illegal byte sequence.
pub const EILSEQ: u16 = 84;
/// Interrupted system call should be restarted.
pub const ERESTART: u16 = 85;
/// Streams pipe error.
pub const ESTRPIPE: u16 = 86;
/// Too many users.
pub const EUSERS: u16 = 87;
/// Socket operation on non-socket.
pub const ENOTSOCK: u16 = 88;
/// Destination address required.
pub const EDESTADDRREQ: u16 = 89;
/// Message too long.
pub const EMSGSIZE: u16 = 90;
/// Protocol wrong type for socket.
pub const EPROTOTYPE: u16 = 91;
/// Protocol not available.
pub const ENOPROTOOPT: u16 = 92;
/// Protocol not supported.
pub const EPROTONOSUPPORT: u16 = 93;
/// Socket type not supported.
pub const ESOCKTNOSUPPORT: u16 = 94;
/// Operation not supported on transport endpoint.
pub const EOPNOTSUPP: u16 = 95;
/// Protocol family not supported.
pub const EPFNOSUPPORT: u16 = 96;
/// Address family not supported by protocol.
pub const EAFNOSUPPORT: u16 = 97;
/// Address already in use.
pub const EADDRINUSE: u16 = 98;
/// Cannot assign requested address.
pub const EADDRNOTAVAIL: u16 = 99;
/// Network is down.
pub const ENETDOWN: u16 = 100;
/// Network is unreachable.
pub const ENETUNREACH: u16 = 101;
/// Network dropped connection because of reset.
pub const ENETRESET: u16 = 102;
/// Software caused connection abort.
pub const ECONNABORTED: u16 = 103;
/// Connection reset by peer.
pub const ECONNRESET: u16 = 104;
/// No buffer space available.
pub const ENOBUFS: u16 = 105;
/// Transport endpoint is already connected.
pub const EISCONN: u16 = 106;
/// Transport endpoint is not connected.
pub const ENOTCONN: u16 = 107;
/// Cannot send after transport endpoint shutdown.
pub const ESHUTDOWN: u16 = 108;
/// Too many references: cannot splice.
pub const ETOOMANYREFS: u16 = 109;
/// Connection timed out.
pub const ETIMEDOUT: u16 = 110;
/// Connection refused.
pub const ECONNREFUSED: u16 = 111;
/// Host is down.
pub const EHOSTDOWN: u16 = 112;
/// No route to host.
pub const EHOSTUNREACH: u16 = 113;
/// Operation already in progress.
pub const EALREADY: u16 = 114;
/// Operation now in progress.
pub const EINPROGRESS: u16 = 115;
/// Stale file handle.
pub const ESTALE: u16 = 116;
/// Filesystem is corrupted.
pub const EFSCORRUPTED: u16 = 117;
/// Structure needs cleaning.
pub const EUCLEAN: u16 = 117;
/// Not a XENIX named type file.
pub const ENOTNAM: u16 = 118;
/// No XENIX semaphores available.
pub const ENAVAIL: u16 = 119;
/// Is a named type file.
pub const EISNAM: u16 = 120;
/// Remote I/O error.
pub const EREMOTEIO: u16 = 121;
/// Quota exceeded.
pub const EDQUOT: u16 = 122;
/// No medium found.
pub const ENOMEDIUM: u16 = 123;
/// Wrong medium type.
pub const EMEDIUMTYPE: u16 = 124;
/// Operation Canceled.
pub const ECANCELED: u16 = 125;
/// Required key not available.
pub const ENOKEY: u16 = 126;
/// Key has expired.
pub const EKEYEXPIRED: u16 = 127;
/// Key has been revoked.
pub const EKEYREVOKED: u16 = 128;
/// Key was rejected by service.
pub const EKEYREJECTED: u16 = 129;
/// Owner died.
pub const EOWNERDEAD: u16 = 130;
/// State not recoverable.
pub const ENOTRECOVERABLE: u16 = 131;
/// Operation not possible due to RF-kill.
pub const ERFKILL: u16 = 132;
/// Memory page has hardware error.
pub const EHWPOISON: u16 = 133;
/// Wrong file type for the intended operation.
pub const EFTYPE: u16 = 134;
