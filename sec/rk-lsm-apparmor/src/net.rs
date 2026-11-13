//! The mediation of the sockets, as net.c and af_inet.c of the Ubuntu kernel that the
//! reference runs.
//!
//! The network rules of a profile name an address family and a socket type. For an IPv4 or an
//! IPv6 socket, a rule can also name the protocol, the local address and port, the address
//! and port of the peer, and the option or the backlog. The DFA matches them in turn. The
//! match stops early when the state has the permissions, or when it does not tell the match
//! to go on (`AA_CONT_MATCH`). Each profile of the label of the task must allow the
//! operation. A denial gives `EACCES` and a record of the class `net`:
//!
//! ```text
//! apparmor="DENIED" operation="create" class="net" profile="P" pid=PID comm="COMM"
//!     family="inet" sock_type="stream" protocol=0 requested="create" denied="create"
//! ```

use crate::dfa::{NOMATCH, State};
use crate::domain;
use crate::label;
use crate::policy::{Mode, Profile};
use crate::unpack::{Pdb, Perms, class, perm};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::cred::Cred;
use rk_vfs::inode::Result;
use rk_vfs::security::Sock;

/// `AA_MAY_SEND`.
pub const SEND: u32 = perm::WRITE;
/// `AA_MAY_RECEIVE`.
pub const RECEIVE: u32 = perm::READ;
/// `AA_MAY_CREATE`.
pub const CREATE: u32 = perm::CREATE;
/// `AA_MAY_SHUTDOWN`.
pub const SHUTDOWN: u32 = perm::DELETE;
/// `AA_MAY_CONNECT`.
pub const CONNECT: u32 = perm::OPEN;
/// `AA_MAY_GETATTR`.
pub const GETATTR: u32 = perm::GETATTR;
/// `AA_MAY_ACCEPT`.
pub const ACCEPT: u32 = 0x0010_0000;
/// `AA_MAY_BIND`.
pub const BIND: u32 = 0x0020_0000;
/// `AA_MAY_LISTEN`.
pub const LISTEN: u32 = 0x0040_0000;
/// `AA_MAY_SETOPT`.
pub const SETOPT: u32 = 0x0100_0000;
/// `AA_MAY_GETOPT`.
pub const GETOPT: u32 = 0x0200_0000;

/// The bit of a state that tells the match to go on when the state does not have the
/// permissions, `AA_CONT_MATCH`.
const CONT_MATCH: u32 = 0x0800_0000;

/// `NET_PERMS_MASK`.
const PERMS_MASK: u32 = SEND
    | RECEIVE
    | CREATE
    | SHUTDOWN
    | BIND
    | LISTEN
    | CONNECT
    | ACCEPT
    | perm::SETATTR
    | GETATTR
    | SETOPT
    | GETOPT;

/// The names of the bits of a network permission, `net_mask_names` of Linux.
const MASK_NAMES: [&str; 32] = [
    "unknown", "send", "receive", "unknown", "create", "shutdown", "connect", "unknown", "setattr",
    "getattr", "setcred", "getcred", "chmod", "chown", "chgrp", "lock", "mmap", "mprot", "unknown",
    "unknown", "accept", "bind", "listen", "unknown", "setopt", "getopt", "unknown", "unknown",
    "unknown", "unknown", "unknown", "unknown",
];

/// `AF_MAX`.
const AF_MAX: u32 = 46;
/// `SOCK_MAX`.
const SOCK_MAX: u32 = 11;

/// The name of the address family `family` in a record, `address_family_names` of Linux. The
/// list has no name for 12, which was `AF_DECnet`.
fn family_name(family: u32) -> Option<&'static str> {
    if family == 12 {
        return None;
    }
    let index = if family > 12 { family - 1 } else { family };
    crate::features::AF_MASK.split(' ').nth(index as usize)
}

/// The name of the socket type `kind` in a record, `sock_type_names` of Linux.
fn type_name(kind: u32) -> Option<&'static str> {
    match kind {
        1 => Some("stream"),
        2 => Some("dgram"),
        3 => Some("raw"),
        4 => Some("rdm"),
        5 => Some("seqpacket"),
        6 => Some("dccp"),
        10 => Some("packet"),
        _ => None,
    }
}

/// The names of the bits of `mask` in quotes, `aa_audit_perm_mask` of Linux.
fn mask_text(mask: u32) -> String {
    let names: alloc::vec::Vec<&str> =
        (0..32).filter(|i| mask & PERMS_MASK & (1 << i) != 0).map(|i| MASK_NAMES[i]).collect();
    format!("\"{}\"", names.join(" "))
}

/// The fields of a record of the class `net` after `comm`, `audit_net_cb` of Linux.
fn tail(family: u32, kind: u32, protocol: u32, request: u32, denied: u32) -> String {
    let mut s = String::new();
    match family_name(family) {
        Some(n) => s.push_str(&format!(" family=\"{n}\"")),
        None => s.push_str(&format!(" family=\"unknown({family})\"")),
    }
    match type_name(kind) {
        Some(n) => s.push_str(&format!(" sock_type=\"{n}\"")),
        None => s.push_str(&format!(" sock_type=\"unknown({kind})\"")),
    }
    s.push_str(&format!(" protocol={protocol}"));
    if request & PERMS_MASK != 0 {
        s.push_str(" requested=");
        s.push_str(&mask_text(request));
        if denied & PERMS_MASK != 0 {
            s.push_str(" denied=");
            s.push_str(&mask_text(denied));
        }
    }
    s
}

/// `AF_UNSPEC`.
const AF_UNSPEC: u16 = 0;
/// `AF_INET`.
const AF_INET: u32 = 2;
/// `AF_INET6`.
const AF_INET6: u32 = 10;
/// `SOCK_STREAM`.
const SOCK_STREAM: u32 = 1;
/// `IPPROTO_TCP`.
const IPPROTO_TCP: u32 = 6;
/// `IPPROTO_MPTCP`.
const IPPROTO_MPTCP: u32 = 262;
/// `MSG_FASTOPEN`.
const MSG_FASTOPEN: u32 = 0x2000_0000;
/// The size of `struct sockaddr_in`.
const SIN_LEN: usize = 16;
/// `SIN6_LEN_RFC2133`: the size of `struct sockaddr_in6` without the scope.
const SIN6_LEN: usize = 24;
/// The first port that does not need `CAP_NET_BIND_SERVICE`. The bind of rukernel uses the
/// default of `net.ipv4.ip_unprivileged_port_start` too.
const PROT_SOCK: u16 = 1024;

/// A local address, `ADDR_LOCAL` of `enum addr_type` of af_inet.c.
const ADDR_LOCAL: u8 = 0;
/// A local port that needs `CAP_NET_BIND_SERVICE`, `ADDR_LOCAL_PRIV`.
const ADDR_LOCAL_PRIV: u8 = 1;
/// The address of the peer, `ADDR_REMOTE`.
const ADDR_REMOTE: u8 = 2;

/// The command of a match for a peer address, `CMD_ADDR` of `enum cmd_type` of af_inet.c.
const CMD_ADDR: u8 = 1;
/// The command of a match for `listen`, `CMD_LISTEN`.
const CMD_LISTEN: u8 = 2;
/// The command of a match for a socket option, `CMD_OPT`.
const CMD_OPT: u8 = 4;

/// An address for a match, `struct match_addr` of af_inet.c.
#[derive(Clone)]
struct Addr {
    /// `ADDR_*`.
    kind: u8,
    /// The port in network byte order.
    port: [u8; 2],
    /// The 4 bytes of an IPv4 address, the 16 bytes of an IPv6 address, or none.
    ip: Vec<u8>,
}

impl Addr {
    /// An address that is not there.
    const fn none(kind: u8) -> Self {
        Addr { kind, port: [0; 2], ip: Vec::new() }
    }
}

/// The family of the socket address `addr`, or `None` if it is too short.
fn sa_family(addr: &[u8]) -> Option<u16> {
    addr.get(..2).map(|b| u16::from_ne_bytes([b[0], b[1]]))
}

/// The port and the address of `addr` as an address of `family`.
///
/// # Errors
///
/// Gives `EAFNOSUPPORT` for a family that is not IPv4 or IPv6, and `EINVAL` if `addr` is
/// too short.
fn inet_addr(addr: &[u8], family: u32, kind: u8) -> Result<Addr> {
    let (len, ip) = match family {
        AF_INET => (SIN_LEN, 4..8),
        AF_INET6 => (SIN6_LEN, 8..24),
        _ => return Err(Errno::EAFNOSUPPORT),
    };
    if addr.len() < len {
        return Err(Errno::EINVAL);
    }
    Ok(Addr { kind, port: [addr[2], addr[3]], ip: addr[ip].to_vec() })
}

/// `map_addr` of af_inet.c: an address that is too short to have a family is none.
fn map_addr(addr: Option<&[u8]>, kind: u8) -> Result<Addr> {
    match addr.and_then(|a| sa_family(a).map(|f| (a, f))) {
        Some((a, family)) => inet_addr(a, u32::from(family), kind),
        None => Ok(Addr::none(kind)),
    }
}

/// `bind_map_addr` of af_inet.c: the address of a bind on a socket of the family `family`.
fn bind_map_addr(family: u32, addr: &[u8]) -> Result<Addr> {
    let sa = sa_family(addr).ok_or(Errno::EINVAL)?;
    let sa = if sa == AF_UNSPEC {
        if family == AF_INET6 {
            // As `inet6_bind_sk` and `__inet6_bind`.
            return Err(if addr.len() < SIN6_LEN { Errno::EINVAL } else { Errno::EAFNOSUPPORT });
        }
        // `__inet_bind` takes `AF_UNSPEC` only with `INADDR_ANY`.
        if addr.get(4..8).is_some_and(|a| a != [0; 4]) {
            return Err(Errno::EAFNOSUPPORT);
        }
        AF_INET
    } else {
        u32::from(sa)
    };
    inet_addr(addr, sa, ADDR_LOCAL)
}

/// `map_sock_addr` of af_inet.c: the local address of `sock`.
fn local(sock: &Sock<'_>) -> Result<Addr> {
    match sock.names {
        Some(n) => map_addr(Some(&n.name()), ADDR_LOCAL),
        None => Ok(Addr::none(ADDR_LOCAL)),
    }
}

/// The state after `bytes` from `state`, `aa_dfa_match_len` of Linux.
fn walk(pdb: &Pdb, state: State, bytes: &[u8]) -> State {
    pdb.dfa.as_ref().map_or(NOMATCH, |d| d.match_bytes(state, bytes))
}

/// `early_match` of af_inet.c: the permissions of `state`, or `None` if they do not have
/// `request` and the state tells the match to go on.
fn early_match(pdb: &Pdb, state: State, request: u32) -> Option<Perms> {
    let p = label::lookup(pdb, state);
    (p.allow & request == request || p.allow & CONT_MATCH == 0).then_some(p)
}

/// `match_addr` of af_inet.c: the kind, the port, the length and the bytes of the address,
/// then the null transition before the label.
fn match_addr(pdb: &Pdb, state: State, a: &Addr) -> State {
    let len = match a.ip.len() {
        0 => 0,
        4 => 1,
        _ => 2,
    };
    let state = walk(pdb, state, &[a.kind]);
    let state = walk(pdb, state, &a.port);
    let state = walk(pdb, state, &[len]);
    let state = walk(pdb, state, &a.ip);
    walk(pdb, state, &[0])
}

/// `match_addr_label` of af_inet.c. The label of the peer is not matched: the match goes
/// over it with the null transition.
fn match_addr_label(pdb: &Pdb, state: State, request: u32, a: &Addr) -> (State, Option<Perms>) {
    let state = match_addr(pdb, state, a);
    match early_match(pdb, state, request) {
        Some(p) => (state, Some(p)),
        None => (walk(pdb, state, &[0]), None),
    }
}

/// `match_to_prot` of af_inet.c: the type, then the protocol, each as 16 bits in network
/// byte order.
fn match_to_prot(
    pdb: &Pdb,
    state: State,
    request: u32,
    kind: u32,
    protocol: u32,
) -> (State, Option<Perms>) {
    let state = walk(pdb, state, &(kind as u16).to_be_bytes());
    match early_match(pdb, state, request) {
        Some(p) => (state, Some(p)),
        None => (walk(pdb, state, &(protocol as u16).to_be_bytes()), None),
    }
}

/// `match_to_sk` of af_inet.c: the type and the protocol of `sock`, then the address `a`.
fn match_to_sk(
    pdb: &Pdb,
    state: State,
    request: u32,
    sock: &Sock<'_>,
    a: &Addr,
) -> (State, Option<Perms>) {
    let (state, p) = match_to_prot(pdb, state, request, sock.kind, sock.protocol);
    if p.is_some() || state == NOMATCH {
        return (state, p);
    }
    match_addr_label(pdb, state, request, a)
}

/// `match_to_cmd` of af_inet.c: `match_to_sk`, then the command `cmd`.
fn match_to_cmd(
    pdb: &Pdb,
    state: State,
    request: u32,
    sock: &Sock<'_>,
    cmd: u8,
    a: &Addr,
) -> (State, Option<Perms>) {
    let (state, p) = match_to_sk(pdb, state, request, sock, a);
    if p.is_none() && state != NOMATCH {
        return (walk(pdb, state, &[cmd]), None);
    }
    (state, p)
}

/// The fields of a check for the record.
struct Req<'x> {
    /// The name of the operation.
    op: &'x str,
    /// The requested permissions.
    request: u32,
    /// The family, the type and the protocol of the socket.
    family: u32,
    kind: u32,
    protocol: u32,
}

/// `do_perms` of af_inet.c: the check of the permissions of `state`, or of `perms` when the
/// match stopped early.
fn do_perms(p: &Profile, pdb: &Pdb, state: State, perms: Option<Perms>, r: &Req<'_>) -> Result<()> {
    let mut perms = match perms {
        Some(x) if state == NOMATCH => x,
        _ => label::lookup(pdb, state),
    };
    label::apply_modes(p, &mut perms);
    label::check_perms(p, &perms, r.request, r.op, "net", |q, d| {
        tail(r.family, r.kind, r.protocol, q, d)
    })
}

/// The check of a socket of the family and the type of `r` for the profile `p`,
/// `aa_profile_af_perm` of net.c. The match has only the family and the type.
fn profile_af_perm(p: &Profile, r: &Req<'_>) -> Result<()> {
    if p.mode == Mode::Unconfined || r.family >= AF_MAX || r.kind >= SOCK_MAX {
        return Ok(());
    }
    let Some((pdb, start)) = label::mediates(p, class::NET) else { return Ok(()) };
    // The family and the type, each as 16 bits in network byte order.
    let mut key = [0u8; 4];
    key[..2].copy_from_slice(&(r.family as u16).to_be_bytes());
    key[2..].copy_from_slice(&(r.kind as u16).to_be_bytes());
    let state = walk(pdb, start, &key);
    do_perms(p, pdb, state, None, r)
}

/// The check of `r` for each confined profile of the label of the task with `cred`,
/// `aa_af_perm` and `aa_label_sk_perm` of net.c.
fn af_perm(cred: &Cred, r: &Req<'_>) -> Result<()> {
    if domain::label_id(cred) == 0 {
        return Ok(());
    }
    let mut result = Ok(());
    for p in domain::label_of(cred).iter() {
        if let Err(e) = profile_af_perm(p, r) {
            result = Err(e);
        }
    }
    result
}

/// The operation of a check on an IPv4 or an IPv6 socket, with its addresses.
enum Op {
    /// `profile_create_perm`.
    Create,
    /// `profile_sk_perm`, `profile_bind_perm` and `profile_accept_perm`: the local address.
    Sock(Addr),
    /// `profile_remote_perm`: the address of the peer and the local address.
    Remote(Addr, Addr),
    /// `profile_listen_perm`: the local address and the backlog.
    Listen(Addr, i32),
    /// `profile_opt_perm`: the local address, the level and the name of the option.
    Opt(Addr, i32, i32),
}

/// The check of `r` on the IPv4 or IPv6 socket `sock` for the profile `p`, the
/// `profile_*_perm` functions of af_inet.c. A profile with no rule for the family has the
/// check of `aa_profile_af_perm`.
fn inet_profile_perm(p: &Profile, r: &Req<'_>, sock: Option<&Sock<'_>>, op: &Op) -> Result<()> {
    if p.mode == Mode::Unconfined {
        return Ok(());
    }
    // `RULE_MEDIATES_AF` of Ubuntu: the network rules, then the family.
    let Some((pdb, start)) =
        label::mediates(p, class::NET).or_else(|| label::mediates(p, class::NET_COMPAT))
    else {
        return profile_af_perm(p, r);
    };
    let state = walk(pdb, start, &(r.family as u16).to_be_bytes());
    if state == NOMATCH {
        return profile_af_perm(p, r);
    }
    let (mut state, mut perms) = match (op, sock) {
        (Op::Create, _) | (_, None) => match_to_prot(pdb, state, r.request, r.kind, r.protocol),
        (Op::Sock(a), Some(s)) => match_to_sk(pdb, state, r.request, s, a),
        (Op::Remote(remote, _), Some(s)) => {
            match_to_cmd(pdb, state, r.request, s, CMD_ADDR, remote)
        }
        (Op::Listen(a, _), Some(s)) => match_to_cmd(pdb, state, r.request, s, CMD_LISTEN, a),
        (Op::Opt(a, ..), Some(s)) => match_to_cmd(pdb, state, r.request, s, CMD_OPT, a),
    };
    if state != NOMATCH && perms.is_none() {
        match op {
            // The local address, if the rule names a pair of addresses.
            Op::Remote(_, a) => (state, perms) = match_addr_label(pdb, state, r.request, a),
            Op::Listen(_, backlog) => state = walk(pdb, state, &(*backlog as u16).to_be_bytes()),
            Op::Opt(_, level, name) => {
                state = walk(pdb, state, &(*level as u16).to_be_bytes());
                state = walk(pdb, state, &(*name as u16).to_be_bytes());
            }
            _ => {}
        }
    }
    do_perms(p, pdb, state, perms, r)
}

/// The check of `r` on an IPv4 or IPv6 socket for each profile of the label of the current
/// task, `label_sk_has_perm2` of af_inet.c. Only a label that has network rules reads the
/// addresses with `map`, and an error of `map` comes before the check.
fn inet_perm(r: &Req<'_>, sock: Option<&Sock<'_>>, map: impl FnOnce() -> Result<Op>) -> Result<()> {
    let cred = rk_vfs::cred::current();
    if domain::label_id(&cred) == 0 {
        return Ok(());
    }
    let label = domain::label_of(&cred);
    if !label.iter().any(|p| p.mode != Mode::Unconfined && label::mediates(p, class::NET).is_some())
    {
        return Ok(());
    }
    let op = map()?;
    let mut result = Ok(());
    for p in label.iter() {
        if let Err(e) = inet_profile_perm(p, r, sock, &op) {
            result = Err(e);
        }
    }
    result
}

/// The socket is an IPv4 or an IPv6 socket, with the checks of af_inet.c.
fn is_inet(family: u32) -> bool {
    family == AF_INET || family == AF_INET6
}

/// The fields of a check of `request` on `sock` for the record.
fn req<'x>(op: &'x str, request: u32, sock: &Sock<'_>) -> Req<'x> {
    Req { op, request, family: sock.family, kind: sock.kind, protocol: sock.protocol }
}

/// `apparmor_socket_create` of the Ubuntu kernel: the current task makes a socket. A socket
/// of the kernel is not mediated.
///
/// # Errors
///
/// Gives `EACCES` if a profile of the task does not allow `create` for the family, the type
/// and the protocol.
pub fn create(family: u32, kind: u32, protocol: u32, kern: bool) -> Result<()> {
    if kern {
        return Ok(());
    }
    let r = Req { op: "create", request: CREATE, family, kind, protocol };
    if is_inet(family) {
        return inet_perm(&r, None, || Ok(Op::Create));
    }
    af_perm(&rk_vfs::cred::current(), &r)
}

/// `aa_sock_perm` of the Ubuntu kernel: the current task does the operation `op` on `sock`,
/// as `getsockname`, `getpeername` and `shutdown`.
///
/// # Errors
///
/// Gives `EACCES` if a profile of the task does not allow `request` on the socket.
pub fn sk_perm(op: &str, request: u32, sock: &Sock<'_>) -> Result<()> {
    let r = req(op, request, sock);
    if is_inet(sock.family) {
        return inet_perm(&r, Some(sock), || Ok(Op::Sock(local(sock)?)));
    }
    af_perm(&rk_vfs::cred::current(), &r)
}

/// `apparmor_socket_bind` of the Ubuntu kernel. A port below 1024 is matched as a port that
/// needs `CAP_NET_BIND_SERVICE`.
///
/// # Errors
///
/// Gives `EACCES` if a profile of the task does not allow the bind to `addr`, and `EINVAL` or
/// `EAFNOSUPPORT` for an address that the bind of Linux does not take.
pub fn bind(sock: &Sock<'_>, addr: &[u8]) -> Result<()> {
    let r = req("bind", BIND, sock);
    if !is_inet(sock.family) {
        return af_perm(&rk_vfs::cred::current(), &r);
    }
    inet_perm(&r, Some(sock), || {
        let mut a = bind_map_addr(sock.family, addr)?;
        let port = u16::from_be_bytes(a.port);
        if port != 0 && port < PROT_SOCK {
            a.kind = ADDR_LOCAL_PRIV;
        }
        Ok(Op::Sock(a))
    })
}

/// `apparmor_socket_connect` of the Ubuntu kernel. A connect to `AF_UNSPEC` disconnects the
/// socket, and is not mediated.
///
/// # Errors
///
/// Gives `EACCES` if a profile of the task does not allow the connect to `addr`, and `EINVAL`
/// for an address with no family.
pub fn connect(sock: &Sock<'_>, addr: &[u8]) -> Result<()> {
    let r = req("connect", CONNECT, sock);
    if !is_inet(sock.family) {
        return af_perm(&rk_vfs::cred::current(), &r);
    }
    match sa_family(addr) {
        Some(AF_UNSPEC) => return Ok(()),
        None => return Err(Errno::EINVAL),
        Some(_) => {}
    }
    inet_perm(&r, Some(sock), || {
        let laddr = local(sock)?;
        Ok(Op::Remote(map_addr(Some(addr), ADDR_REMOTE)?, laddr))
    })
}

/// `apparmor_socket_listen` of the Ubuntu kernel.
///
/// # Errors
///
/// Gives `EACCES` if a profile of the task does not allow the listen.
pub fn listen(sock: &Sock<'_>, backlog: i32) -> Result<()> {
    let r = req("listen", LISTEN, sock);
    if !is_inet(sock.family) {
        return af_perm(&rk_vfs::cred::current(), &r);
    }
    inet_perm(&r, Some(sock), || Ok(Op::Listen(local(sock)?, backlog)))
}

/// `apparmor_socket_accept` of the Ubuntu kernel.
///
/// # Errors
///
/// Gives `EACCES` if a profile of the task does not allow the accept.
pub fn accept(sock: &Sock<'_>) -> Result<()> {
    sk_perm("accept", ACCEPT, sock)
}

/// `aa_sock_msg_perm` of the Ubuntu kernel: a send to `addr` or a receive on `sock`.
fn msg_perm(op: &str, request: u32, sock: &Sock<'_>, addr: Option<&[u8]>) -> Result<()> {
    let r = req(op, request, sock);
    if !is_inet(sock.family) {
        return af_perm(&rk_vfs::cred::current(), &r);
    }
    inet_perm(&r, Some(sock), || {
        let laddr = local(sock)?;
        Ok(Op::Remote(map_addr(addr, ADDR_REMOTE)?, laddr))
    })
}

/// `apparmor_socket_sendmsg` of the Ubuntu kernel: a send to `addr`. A TCP fast open with an
/// address does a connect too, and needs `connect` for the family and the type.
///
/// # Errors
///
/// Gives `EACCES` if a profile of the task does not allow the send.
pub fn sendmsg(sock: &Sock<'_>, addr: Option<&[u8]>, flags: u32) -> Result<()> {
    msg_perm("sendmsg", SEND, sock, addr)?;
    if flags & MSG_FASTOPEN != 0
        && addr.is_some()
        && is_inet(sock.family)
        && sock.kind == SOCK_STREAM
        && matches!(sock.protocol, IPPROTO_TCP | IPPROTO_MPTCP)
    {
        return af_perm(&rk_vfs::cred::current(), &req("connect", CONNECT, sock));
    }
    Ok(())
}

/// `apparmor_socket_recvmsg` of the Ubuntu kernel. The receive has no address of the peer
/// yet.
///
/// # Errors
///
/// Gives `EACCES` if a profile of the task does not allow the receive.
pub fn recvmsg(sock: &Sock<'_>) -> Result<()> {
    msg_perm("recvmsg", RECEIVE, sock, None)
}

/// `aa_sock_opt_perm` of the Ubuntu kernel: `getsockopt` or `setsockopt` of the option `name`
/// at the level `level`.
///
/// # Errors
///
/// Gives `EACCES` if a profile of the task does not allow `request` for the option.
pub fn opt_perm(op: &str, request: u32, sock: &Sock<'_>, level: i32, name: i32) -> Result<()> {
    let r = req(op, request, sock);
    if !is_inet(sock.family) {
        return af_perm(&rk_vfs::cred::current(), &r);
    }
    inet_perm(&r, Some(sock), || Ok(Op::Opt(local(sock)?, level, name)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_has_the_names_of_linux() {
        assert_eq!(family_name(2), Some("inet"));
        assert_eq!(family_name(10), Some("inet6"));
        assert_eq!(family_name(12), None);
        assert_eq!(family_name(16), Some("netlink"));
        assert_eq!(family_name(17), Some("packet"));
        assert_eq!(family_name(45), Some("mctp"));
        assert_eq!(
            tail(2, 1, 0, CREATE, CREATE),
            " family=\"inet\" sock_type=\"stream\" protocol=0 requested=\"create\" \
             denied=\"create\""
        );
        assert_eq!(mask_text(BIND | LISTEN | SEND), "\"send bind listen\"");
        assert_eq!(
            tail(12, 7, 1, 0, 0),
            " family=\"unknown(12)\" sock_type=\"unknown(7)\" protocol=1"
        );
    }

    #[test]
    fn the_addresses_are_read_as_af_inet_reads_them() {
        let mut a4 = [0u8; 16];
        a4[..2].copy_from_slice(&2u16.to_ne_bytes());
        a4[2..4].copy_from_slice(&80u16.to_be_bytes());
        a4[4..8].copy_from_slice(&[127, 0, 0, 1]);
        let a = bind_map_addr(AF_INET, &a4).unwrap();
        assert_eq!((a.kind, a.port, a.ip.as_slice()), (ADDR_LOCAL, [0, 80], &[127, 0, 0, 1][..]));
        assert_eq!(bind_map_addr(AF_INET, &a4[..15]).err(), Some(Errno::EINVAL));
        assert_eq!(bind_map_addr(AF_INET, &a4[..1]).err(), Some(Errno::EINVAL));
        let mut unspec = a4;
        unspec[..2].copy_from_slice(&0u16.to_ne_bytes());
        assert_eq!(bind_map_addr(AF_INET, &unspec).err(), Some(Errno::EAFNOSUPPORT));
        unspec[4..8].fill(0);
        assert_eq!(bind_map_addr(AF_INET, &unspec).map(|a| a.ip).ok(), Some(alloc::vec![0; 4]));
        assert_eq!(bind_map_addr(AF_INET6, &unspec).err(), Some(Errno::EINVAL));
        let mut a6 = [0u8; 28];
        a6[..2].copy_from_slice(&10u16.to_ne_bytes());
        a6[23] = 1;
        let a = map_addr(Some(&a6), ADDR_REMOTE).unwrap();
        assert_eq!((a.kind, a.ip.len(), a.ip[15]), (ADDR_REMOTE, 16, 1));
        assert!(
            map_addr(None, ADDR_REMOTE).is_ok_and(|a| a.ip.is_empty() && a.kind == ADDR_REMOTE)
        );
        assert!(map_addr(Some(&[1]), ADDR_LOCAL).is_ok_and(|a| a.ip.is_empty()));
        assert_eq!(
            map_addr(Some(&1u16.to_ne_bytes()), ADDR_REMOTE).err(),
            Some(Errno::EAFNOSUPPORT)
        );
    }
}
