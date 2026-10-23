// rk-abigen generated this file from Linux 7.3, from <asm/errno.h>.
// Do not edit it. Change rk-abigen and run it again.

//! The error numbers as `Errno` values. They are the same on each architecture.

impl crate::Errno {
    /// Operation not permitted.
    pub const EPERM: Self = Self(1);
    /// No such file or directory.
    pub const ENOENT: Self = Self(2);
    /// No such process.
    pub const ESRCH: Self = Self(3);
    /// Interrupted system call.
    pub const EINTR: Self = Self(4);
    /// I/O error.
    pub const EIO: Self = Self(5);
    /// No such device or address.
    pub const ENXIO: Self = Self(6);
    /// Argument list too long.
    pub const E2BIG: Self = Self(7);
    /// Exec format error.
    pub const ENOEXEC: Self = Self(8);
    /// Bad file number.
    pub const EBADF: Self = Self(9);
    /// No child processes.
    pub const ECHILD: Self = Self(10);
    /// Try again.
    pub const EAGAIN: Self = Self(11);
    /// Operation would block.
    pub const EWOULDBLOCK: Self = Self(11);
    /// Out of memory.
    pub const ENOMEM: Self = Self(12);
    /// Permission denied.
    pub const EACCES: Self = Self(13);
    /// Bad address.
    pub const EFAULT: Self = Self(14);
    /// Block device required.
    pub const ENOTBLK: Self = Self(15);
    /// Device or resource busy.
    pub const EBUSY: Self = Self(16);
    /// File exists.
    pub const EEXIST: Self = Self(17);
    /// Cross-device link.
    pub const EXDEV: Self = Self(18);
    /// No such device.
    pub const ENODEV: Self = Self(19);
    /// Not a directory.
    pub const ENOTDIR: Self = Self(20);
    /// Is a directory.
    pub const EISDIR: Self = Self(21);
    /// Invalid argument.
    pub const EINVAL: Self = Self(22);
    /// File table overflow.
    pub const ENFILE: Self = Self(23);
    /// Too many open files.
    pub const EMFILE: Self = Self(24);
    /// Not a typewriter.
    pub const ENOTTY: Self = Self(25);
    /// Text file busy.
    pub const ETXTBSY: Self = Self(26);
    /// File too large.
    pub const EFBIG: Self = Self(27);
    /// No space left on device.
    pub const ENOSPC: Self = Self(28);
    /// Illegal seek.
    pub const ESPIPE: Self = Self(29);
    /// Read-only file system.
    pub const EROFS: Self = Self(30);
    /// Too many links.
    pub const EMLINK: Self = Self(31);
    /// Broken pipe.
    pub const EPIPE: Self = Self(32);
    /// Math argument out of domain of func.
    pub const EDOM: Self = Self(33);
    /// Math result not representable.
    pub const ERANGE: Self = Self(34);
    /// Resource deadlock would occur.
    pub const EDEADLK: Self = Self(35);
    /// The same value as `EDEADLK`.
    pub const EDEADLOCK: Self = Self(35);
    /// File name too long.
    pub const ENAMETOOLONG: Self = Self(36);
    /// No record locks available.
    pub const ENOLCK: Self = Self(37);
    /// Invalid system call number.
    pub const ENOSYS: Self = Self(38);
    /// Directory not empty.
    pub const ENOTEMPTY: Self = Self(39);
    /// Too many symbolic links encountered.
    pub const ELOOP: Self = Self(40);
    /// No message of desired type.
    pub const ENOMSG: Self = Self(42);
    /// Identifier removed.
    pub const EIDRM: Self = Self(43);
    /// Channel number out of range.
    pub const ECHRNG: Self = Self(44);
    /// Level 2 not synchronized.
    pub const EL2NSYNC: Self = Self(45);
    /// Level 3 halted.
    pub const EL3HLT: Self = Self(46);
    /// Level 3 reset.
    pub const EL3RST: Self = Self(47);
    /// Link number out of range.
    pub const ELNRNG: Self = Self(48);
    /// Protocol driver not attached.
    pub const EUNATCH: Self = Self(49);
    /// No CSI structure available.
    pub const ENOCSI: Self = Self(50);
    /// Level 2 halted.
    pub const EL2HLT: Self = Self(51);
    /// Invalid exchange.
    pub const EBADE: Self = Self(52);
    /// Invalid request descriptor.
    pub const EBADR: Self = Self(53);
    /// Exchange full.
    pub const EXFULL: Self = Self(54);
    /// No anode.
    pub const ENOANO: Self = Self(55);
    /// Invalid request code.
    pub const EBADRQC: Self = Self(56);
    /// Invalid slot.
    pub const EBADSLT: Self = Self(57);
    /// Bad font file format.
    pub const EBFONT: Self = Self(59);
    /// Device not a stream.
    pub const ENOSTR: Self = Self(60);
    /// No data available.
    pub const ENODATA: Self = Self(61);
    /// Timer expired.
    pub const ETIME: Self = Self(62);
    /// Out of streams resources.
    pub const ENOSR: Self = Self(63);
    /// Machine is not on the network.
    pub const ENONET: Self = Self(64);
    /// Package not installed.
    pub const ENOPKG: Self = Self(65);
    /// Object is remote.
    pub const EREMOTE: Self = Self(66);
    /// Link has been severed.
    pub const ENOLINK: Self = Self(67);
    /// Advertise error.
    pub const EADV: Self = Self(68);
    /// Srmount error.
    pub const ESRMNT: Self = Self(69);
    /// Communication error on send.
    pub const ECOMM: Self = Self(70);
    /// Protocol error.
    pub const EPROTO: Self = Self(71);
    /// Multihop attempted.
    pub const EMULTIHOP: Self = Self(72);
    /// RFS specific error.
    pub const EDOTDOT: Self = Self(73);
    /// Not a data message.
    pub const EBADMSG: Self = Self(74);
    /// Bad CRC detected.
    pub const EFSBADCRC: Self = Self(74);
    /// Value too large for defined data type.
    pub const EOVERFLOW: Self = Self(75);
    /// Name not unique on network.
    pub const ENOTUNIQ: Self = Self(76);
    /// File descriptor in bad state.
    pub const EBADFD: Self = Self(77);
    /// Remote address changed.
    pub const EREMCHG: Self = Self(78);
    /// Can not access a needed shared library.
    pub const ELIBACC: Self = Self(79);
    /// Accessing a corrupted shared library.
    pub const ELIBBAD: Self = Self(80);
    /// .lib section in a.out corrupted.
    pub const ELIBSCN: Self = Self(81);
    /// Attempting to link in too many shared libraries.
    pub const ELIBMAX: Self = Self(82);
    /// Cannot exec a shared library directly.
    pub const ELIBEXEC: Self = Self(83);
    /// Illegal byte sequence.
    pub const EILSEQ: Self = Self(84);
    /// Interrupted system call should be restarted.
    pub const ERESTART: Self = Self(85);
    /// Streams pipe error.
    pub const ESTRPIPE: Self = Self(86);
    /// Too many users.
    pub const EUSERS: Self = Self(87);
    /// Socket operation on non-socket.
    pub const ENOTSOCK: Self = Self(88);
    /// Destination address required.
    pub const EDESTADDRREQ: Self = Self(89);
    /// Message too long.
    pub const EMSGSIZE: Self = Self(90);
    /// Protocol wrong type for socket.
    pub const EPROTOTYPE: Self = Self(91);
    /// Protocol not available.
    pub const ENOPROTOOPT: Self = Self(92);
    /// Protocol not supported.
    pub const EPROTONOSUPPORT: Self = Self(93);
    /// Socket type not supported.
    pub const ESOCKTNOSUPPORT: Self = Self(94);
    /// Operation not supported on transport endpoint.
    pub const EOPNOTSUPP: Self = Self(95);
    /// Protocol family not supported.
    pub const EPFNOSUPPORT: Self = Self(96);
    /// Address family not supported by protocol.
    pub const EAFNOSUPPORT: Self = Self(97);
    /// Address already in use.
    pub const EADDRINUSE: Self = Self(98);
    /// Cannot assign requested address.
    pub const EADDRNOTAVAIL: Self = Self(99);
    /// Network is down.
    pub const ENETDOWN: Self = Self(100);
    /// Network is unreachable.
    pub const ENETUNREACH: Self = Self(101);
    /// Network dropped connection because of reset.
    pub const ENETRESET: Self = Self(102);
    /// Software caused connection abort.
    pub const ECONNABORTED: Self = Self(103);
    /// Connection reset by peer.
    pub const ECONNRESET: Self = Self(104);
    /// No buffer space available.
    pub const ENOBUFS: Self = Self(105);
    /// Transport endpoint is already connected.
    pub const EISCONN: Self = Self(106);
    /// Transport endpoint is not connected.
    pub const ENOTCONN: Self = Self(107);
    /// Cannot send after transport endpoint shutdown.
    pub const ESHUTDOWN: Self = Self(108);
    /// Too many references: cannot splice.
    pub const ETOOMANYREFS: Self = Self(109);
    /// Connection timed out.
    pub const ETIMEDOUT: Self = Self(110);
    /// Connection refused.
    pub const ECONNREFUSED: Self = Self(111);
    /// Host is down.
    pub const EHOSTDOWN: Self = Self(112);
    /// No route to host.
    pub const EHOSTUNREACH: Self = Self(113);
    /// Operation already in progress.
    pub const EALREADY: Self = Self(114);
    /// Operation now in progress.
    pub const EINPROGRESS: Self = Self(115);
    /// Stale file handle.
    pub const ESTALE: Self = Self(116);
    /// Filesystem is corrupted.
    pub const EFSCORRUPTED: Self = Self(117);
    /// Structure needs cleaning.
    pub const EUCLEAN: Self = Self(117);
    /// Not a XENIX named type file.
    pub const ENOTNAM: Self = Self(118);
    /// No XENIX semaphores available.
    pub const ENAVAIL: Self = Self(119);
    /// Is a named type file.
    pub const EISNAM: Self = Self(120);
    /// Remote I/O error.
    pub const EREMOTEIO: Self = Self(121);
    /// Quota exceeded.
    pub const EDQUOT: Self = Self(122);
    /// No medium found.
    pub const ENOMEDIUM: Self = Self(123);
    /// Wrong medium type.
    pub const EMEDIUMTYPE: Self = Self(124);
    /// Operation Canceled.
    pub const ECANCELED: Self = Self(125);
    /// Required key not available.
    pub const ENOKEY: Self = Self(126);
    /// Key has expired.
    pub const EKEYEXPIRED: Self = Self(127);
    /// Key has been revoked.
    pub const EKEYREVOKED: Self = Self(128);
    /// Key was rejected by service.
    pub const EKEYREJECTED: Self = Self(129);
    /// Owner died.
    pub const EOWNERDEAD: Self = Self(130);
    /// State not recoverable.
    pub const ENOTRECOVERABLE: Self = Self(131);
    /// Operation not possible due to RF-kill.
    pub const ERFKILL: Self = Self(132);
    /// Memory page has hardware error.
    pub const EHWPOISON: Self = Self(133);
    /// Wrong file type for the intended operation.
    pub const EFTYPE: Self = Self(134);
}
