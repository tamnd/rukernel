//! The mediation of the Unix sockets, as af_unix.c of the Ubuntu kernel that the reference runs.
//!
//! A `unix` rule of a profile names the type and the protocol of the socket, its address, the
//! operation, and the address and the label of the peer. The DFA matches them in turn, after the
//! family. A socket with a path name has the checks of the file rules on its socket file. A
//! socket has the label of the task that made it, and a connected socket also has the label of
//! its peer for `SO_PEERSEC`. A denial gives `EACCES` and a record of the class `net` with the
//! addresses of the sockets:
//!
//! ```text
//! apparmor="DENIED" operation="connect" class="net" profile="P" pid=PID comm="COMM"
//!     family="unix" sock_type="stream" protocol=0 requested="send receive connect"
//!     denied="send receive connect" addr=none peer_addr="@name" peer="unconfined"
//! ```

use crate::dfa::{NOMATCH, State};
use crate::domain::{self, Label};
use crate::file;
use crate::label;
use crate::net::{self, Req};
use crate::policy::{Mode, Profile};
use crate::unpack::{Pdb, class, perm};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use rk_abi::Errno;
use rk_vfs::inode::Result;
use rk_vfs::security::{Sock, id};

/// `AF_UNIX`.
pub const AF_UNIX: u32 = 1;

/// The size of the part of AppArmor in the blob of a socket, `struct aa_sk_ctx` of Linux: the
/// label of the socket and the label of its peer.
pub const SOCK_BLOB: usize = 16;

/// The byte offset of the label of the socket in its part of the blob. A label is the number
/// of the label of a task plus 1, and 0 is no label.
const LABEL: usize = 0;
/// The byte offset of the label of the peer, as [`LABEL`].
const PEER: usize = 8;

/// `AA_MAY_CHGRP`.
const CHGRP: u32 = 0x4000;
/// `AA_MAY_MPROT`.
const MPROT: u32 = 0x2_0000;

/// The permissions of a socket that the file rules check on its socket file, `NET_FS_PERMS`.
const NET_FS_PERMS: u32 = net::SEND
    | net::RECEIVE
    | net::CREATE
    | net::SHUTDOWN
    | net::CONNECT
    | perm::RENAME
    | perm::SETATTR
    | net::GETATTR
    | perm::CHMOD
    | perm::CHOWN
    | CHGRP
    | perm::LOCK
    | MPROT;

/// The permissions that need the peer, `NET_PEER_MASK`.
const PEER_MASK: u32 = net::SEND | net::RECEIVE | net::CONNECT | net::ACCEPT;

/// The command of a match for the address of the peer, `CMD_ADDR` of af_unix.c.
const CMD_ADDR: u8 = 1;
/// The command of a match for `listen`, `CMD_LISTEN`.
const CMD_LISTEN: u8 = 2;
/// The command of a match for a socket option, `CMD_OPT`.
const CMD_OPT: u8 = 4;

/// The byte offset of the part of AppArmor in the blob of a socket, or `None` if the module is
/// not active.
fn sock_offset() -> Option<usize> {
    rk_vfs::security::modules()
        .iter()
        .find(|m| m.info.id.id == id::APPARMOR)
        .map(|m| m.offsets.sock)
}

/// The word at the byte offset `slot` of the part of AppArmor in the blob of `sock`.
fn load(sock: &Sock<'_>, slot: usize) -> u64 {
    sock_offset().map_or(0, |off| sock.security.load(off + slot))
}

/// Writes the word at the byte offset `slot` of the part of AppArmor in the blob of `sock`.
fn store(sock: &Sock<'_>, slot: usize, value: u64) {
    if let Some(off) = sock_offset() {
        sock.security.store(off + slot, value);
    }
}

/// The newest label of the word `v` of the blob of a socket. `None` is no label.
fn word_label(v: u64) -> Option<Label> {
    v.checked_sub(1).map(domain::label_by_id)
}

/// The label of `sock`, `aa_sock(sk)->label` of Linux. A socket with no label is
/// `unconfined`.
fn sock_label(sock: &Sock<'_>) -> Label {
    word_label(load(sock, LABEL)).unwrap_or_default()
}

/// The label of the current task. No profile is `unconfined`.
fn current_label() -> Label {
    domain::label_of(&rk_vfs::cred::current())
}

/// `apparmor_socket_post_create` of Linux: the socket gets the label of the task that made
/// it. A socket of the kernel has no label.
pub fn post_create(sock: &Sock<'_>, kern: bool) {
    if !kern {
        store(sock, LABEL, domain::label_id(&rk_vfs::cred::current()) + 1);
    }
}

/// The address of `sock`, `unix_sk(sk)->addr` of Linux, or `None` for a socket with no name.
fn sk_addr(sock: &Sock<'_>) -> Option<Vec<u8>> {
    sock.names.map(|n| n.name()).filter(|a| a.len() > 2)
}

/// The socket has a path name, `UNIX_FS` of Linux.
fn is_fs(sock: &Sock<'_>) -> bool {
    sk_addr(sock).is_some_and(|a| a[2] != 0)
}

/// The address `addr` is a path name, `unix_addr_fs` of Linux.
fn addr_fs(addr: &[u8]) -> bool {
    addr.len() > 2 && addr[2] != 0
}

/// The text of the Unix address `addr` in a record with the name `key`, `audit_unix_addr` of
/// Linux. An abstract name has a `@` before it.
fn addr_text(s: &mut String, key: &str, addr: Option<&[u8]>) {
    let path = addr.and_then(|a| a.get(2..)).filter(|p| !p.is_empty());
    match path {
        None => {
            let _ = write!(s, " {key}=none");
        }
        Some(p) if p[0] != 0 => {
            let _ = write!(s, " {key}=");
            let end = p.iter().position(|&c| c == 0).unwrap_or(p.len());
            crate::audit::untrusted(s, &p[..end]);
        }
        Some(p) => {
            let name = &p[1..];
            let _ = write!(s, " {key}=\"@");
            if name.iter().any(|&c| c == b'"' || !(0x21..=0x7e).contains(&c)) {
                for c in name {
                    let _ = write!(s, "{c:02X}");
                }
            } else {
                s.push_str(core::str::from_utf8(name).unwrap_or_default());
            }
            s.push('"');
        }
    }
}

/// The parts of a check for the record, `struct apparmor_audit_data` of Linux.
struct Ad<'x> {
    /// The name of the operation.
    op: &'static str,
    /// The type and the protocol of the socket.
    kind: u32,
    protocol: u32,
    /// The socket, or `None` for a new socket.
    sock: Option<&'x Sock<'x>>,
    /// The address of a bind, `ad->net.addr`.
    addr: Option<&'x [u8]>,
    /// The peer, `ad->net.peer_sk`.
    peer_sk: Option<&'x Sock<'x>>,
}

impl<'x> Ad<'x> {
    /// The parts of a check of `op` on `sock`.
    fn of(op: &'static str, sock: &'x Sock<'x>) -> Self {
        Self {
            op,
            kind: sock.kind,
            protocol: sock.protocol,
            sock: Some(sock),
            addr: None,
            peer_sk: None,
        }
    }

    /// The fields of a Unix socket at the end of a record with `request`, and the label of the
    /// peer `peer`, as `audit_net_cb` of Linux.
    fn fields(&self, request: u32, peer: Option<&str>) -> String {
        let mut s = String::new();
        match self.addr {
            Some(a) if request & !PEER_MASK != 0 => addr_text(&mut s, "addr", Some(a)),
            _ => addr_text(&mut s, "addr", self.sock.and_then(sk_addr).as_deref()),
        }
        if request & PEER_MASK != 0 {
            match self.addr {
                Some(a) => addr_text(&mut s, "peer_addr", Some(a)),
                None => addr_text(&mut s, "peer_addr", self.peer_sk.and_then(sk_addr).as_deref()),
            }
        }
        if let Some(p) = peer {
            s.push_str(" peer=");
            s.push_str(p);
        }
        s
    }
}

/// The check of the permissions of `state` against `request`, `do_perms` of af_unix.c. `peer`
/// is the text of the label of the peer for the record.
fn do_perms(
    p: &Profile,
    pdb: &Pdb,
    state: State,
    request: u32,
    ad: &Ad<'_>,
    peer: Option<&str>,
) -> Result<()> {
    let extra = |q: u32| ad.fields(q, peer);
    let r = Req {
        op: ad.op,
        request,
        family: AF_UNIX,
        kind: ad.kind,
        protocol: ad.protocol,
        extra: Some(&extra),
    };
    net::do_perms(p, pdb, state, None, &r)
}

/// The check of a profile with no rule for Unix sockets, `aa_profile_af_perm` of Linux: the
/// match has only the family and the type.
fn af_perm(p: &Profile, request: u32, ad: &Ad<'_>) -> Result<()> {
    let extra = |q: u32| ad.fields(q, None);
    let r = Req {
        op: ad.op,
        request,
        family: AF_UNIX,
        kind: ad.kind,
        protocol: ad.protocol,
        extra: Some(&extra),
    };
    net::profile_af_perm(p, &r)
}

/// The check `f` for each profile of `l` that is not unconfined, `fn_for_each_confined` of
/// Linux. The check does not stop at the first denial, and gives the last error.
fn each_confined(l: &[Arc<Profile>], mut f: impl FnMut(&Profile) -> Result<()>) -> Result<()> {
    let mut result = Ok(());
    for p in l.iter().filter(|p| p.mode != Mode::Unconfined) {
        if let Err(e) = f(p) {
            result = Err(e);
        }
    }
    result
}

/// `match_to_prot` of af_unix.c: the type, then the protocol, each as 16 bits in network byte
/// order.
fn match_to_prot(pdb: &Pdb, state: State, kind: u32, protocol: u32) -> State {
    let mut key = [0u8; 4];
    key[..2].copy_from_slice(&(kind as u16).to_be_bytes());
    key[2..].copy_from_slice(&(protocol as u16).to_be_bytes());
    net::walk(pdb, state, &key)
}

/// `match_addr` of af_unix.c: the bytes of `sun_path` of the address, or 1 for a socket with
/// no name, then the null transition.
fn match_addr(pdb: &Pdb, state: State, addr: Option<&[u8]>) -> State {
    let state = match addr {
        Some(a) => net::walk(pdb, state, a.get(2..).unwrap_or_default()),
        None => net::walk(pdb, state, &[1]),
    };
    net::walk(pdb, state, &[0])
}

/// `match_to_local` of af_unix.c: the type and the protocol, the address, then the null
/// transition of the local label.
fn match_to_local(pdb: &Pdb, state: State, kind: u32, protocol: u32, addr: Option<&[u8]>) -> State {
    let state = match_to_prot(pdb, state, kind, protocol);
    if state == NOMATCH {
        return state;
    }
    let state = match_addr(pdb, state, addr);
    if state == NOMATCH {
        return state;
    }
    net::walk(pdb, state, &[0])
}

/// `match_to_sk` of af_unix.c: [`match_to_local`] with the address of `sock`.
fn match_to_sk(pdb: &Pdb, state: State, sock: &Sock<'_>) -> State {
    match_to_local(pdb, state, sock.kind, sock.protocol, sk_addr(sock).as_deref())
}

/// `match_to_cmd` of af_unix.c: [`match_to_sk`], then the command `cmd`.
fn match_to_cmd(pdb: &Pdb, state: State, sock: &Sock<'_>, cmd: u8) -> State {
    let state = match_to_sk(pdb, state, sock);
    if state == NOMATCH {
        return state;
    }
    net::walk(pdb, state, &[cmd])
}

/// `match_to_peer` of af_unix.c: [`match_to_cmd`] with `CMD_ADDR`, then the address of the
/// peer.
fn match_to_peer(pdb: &Pdb, state: State, sock: &Sock<'_>, peer: Option<&[u8]>) -> State {
    let state = match_to_cmd(pdb, state, sock, CMD_ADDR);
    if state == NOMATCH {
        return state;
    }
    match_addr(pdb, state, peer)
}

/// The check of the file rules of the label `l` on the socket file of `sock`, `unix_fs_perm`
/// of af_unix.c. Only a label with file rules has the check.
fn fs_perm(op: &'static str, request: u32, l: &[Arc<Profile>], sock: &Sock<'_>) -> Result<()> {
    if !l.iter().any(|p| p.mode != Mode::Unconfined && label::mediates(p, class::FILE).is_some()) {
        return Ok(());
    }
    let Some(at) = sock.names.and_then(|n| n.path()) else { return Ok(()) };
    let fsuid = rk_vfs::cred::current().fsuid;
    file::label_path_perm(op, l, &at, request & NET_FS_PERMS, fsuid)
}

/// The check of `request` on `sock` for the profile `p`, `profile_sk_perm` of af_unix.c.
fn profile_sk_perm(p: &Profile, request: u32, sock: &Sock<'_>, ad: &Ad<'_>) -> Result<()> {
    match net::mediates_af(p, AF_UNIX) {
        Some((pdb, state)) => do_perms(p, pdb, match_to_sk(pdb, state, sock), request, ad, None),
        None => af_perm(p, request, ad),
    }
}

/// The check of `request` on the socket `sock` with no path name for each confined profile of
/// `l`, `aa_unix_label_sk_perm` of af_unix.c.
fn label_sk_perm(
    l: &[Arc<Profile>],
    op: &'static str,
    request: u32,
    sock: &Sock<'_>,
) -> Result<()> {
    let ad = Ad::of(op, sock);
    each_confined(l, |p| profile_sk_perm(p, request, sock, &ad))
}

/// The check of `request` on `sock` for the label `l`, `unix_label_sock_perm` of af_unix.c.
/// A socket with a path name has the check of the file rules.
fn label_sock_perm(
    l: &[Arc<Profile>],
    op: &'static str,
    request: u32,
    sock: &Sock<'_>,
) -> Result<()> {
    if l.is_empty() {
        return Ok(());
    }
    if is_fs(sock) {
        return fs_perm(op, request, l, sock);
    }
    label_sk_perm(l, op, request, sock)
}

/// The check of `request` of the profile `p` against the label of the peer with the name
/// `name`, `match_label` of af_unix.c.
fn match_label(
    p: &Profile,
    pdb: &Pdb,
    name: &str,
    peer: &[Arc<Profile>],
    state: State,
    request: u32,
    ad: &Ad<'_>,
) -> Result<()> {
    let state = if state == NOMATCH { state } else { net::walk(pdb, state, name.as_bytes()) };
    let text = label::peer_text(peer, p);
    do_perms(p, pdb, state, request, ad, Some(&text))
}

/// The check of `request` of the profile `p` on `sock` against the peer `peer` with the label
/// `peer_label`, `profile_peer_perm` of af_unix.c. Each profile of the label of the peer must
/// match.
fn profile_peer_perm(
    p: &Profile,
    request: u32,
    sock: &Sock<'_>,
    peer: &Sock<'_>,
    peer_label: &[Arc<Profile>],
    ad: &Ad<'_>,
) -> Result<()> {
    let Some((pdb, state)) = net::mediates_af(p, AF_UNIX) else {
        return af_perm(p, request, ad);
    };
    let state = match_to_peer(pdb, state, sock, sk_addr(peer).as_deref());
    if peer_label.is_empty() {
        return match_label(p, pdb, "unconfined", &[], state, request, ad);
    }
    // Only the profiles in the namespace of the label, as `fn_for_each_in_ns` of Linux.
    let ns = peer_label.last().and_then(|q| q.ns.as_deref());
    let mut result = Ok(());
    for q in peer_label.iter().filter(|q| q.ns.as_deref() == ns) {
        if let Err(e) = match_label(p, pdb, &q.name, core::slice::from_ref(q), state, request, ad) {
            result = Err(e);
        }
    }
    result
}

/// The check of `request` of the label `l` on `sock` with the peer `peer`, `aa_unix_peer_perm`
/// of af_unix.c. `peer_label` is the label of the peer, or `None` for the label of the socket
/// `peer`. A socket with a path name has the check of the file rules.
fn peer_perm(
    l: &[Arc<Profile>],
    op: &'static str,
    request: u32,
    sock: &Sock<'_>,
    peer: &Sock<'_>,
    peer_label: Option<&[Arc<Profile>]>,
) -> Result<()> {
    if is_fs(peer) {
        return fs_perm(op, request, l, peer);
    }
    if is_fs(sock) {
        return fs_perm(op, request, l, sock);
    }
    if l.is_empty() {
        return Ok(());
    }
    let own;
    let peer_label = match peer_label {
        Some(pl) => pl,
        None => {
            own = sock_label(peer);
            &own
        }
    };
    let ad = Ad { peer_sk: Some(peer), ..Ad::of(op, sock) };
    each_confined(l, |p| profile_peer_perm(p, request, sock, peer, peer_label, &ad))
}

/// `aa_unix_create_perm` of af_unix.c: the current task makes a Unix socket. Only a label with
/// network rules has the check.
///
/// # Errors
///
/// Gives `EACCES` if a profile of the task does not allow `create` for the type and the
/// protocol.
pub fn create(kind: u32, protocol: u32) -> Result<()> {
    let l = current_label();
    if !l.iter().any(|p| p.mode != Mode::Unconfined && label::mediates(p, class::NET).is_some()) {
        return Ok(());
    }
    let ad = Ad { op: "create", kind, protocol, sock: None, addr: None, peer_sk: None };
    each_confined(&l, |p| match net::mediates_af(p, AF_UNIX) {
        Some((pdb, state)) => {
            let state = match_to_prot(pdb, state, kind, protocol);
            do_perms(p, pdb, state, net::CREATE, &ad, None)
        }
        None => af_perm(p, net::CREATE, &ad),
    })
}

/// `aa_unix_bind_perm` of af_unix.c: the bind of `sock` to `addr`. A bind to a path name has
/// the checks of the file rules when it makes the socket file.
///
/// # Errors
///
/// Gives `EACCES` if a profile of the task does not allow the bind.
pub fn bind(sock: &Sock<'_>, addr: &[u8]) -> Result<()> {
    let l = current_label();
    if l.is_empty() || addr_fs(addr) {
        return Ok(());
    }
    let ad = Ad::of("bind", sock);
    let with_addr = Ad { addr: Some(addr), ..Ad::of("bind", sock) };
    each_confined(&l, |p| match net::mediates_af(p, AF_UNIX) {
        Some((pdb, state)) => {
            let state = match_to_local(pdb, state, sock.kind, sock.protocol, Some(addr));
            do_perms(p, pdb, state, net::BIND, &with_addr, None)
        }
        None => af_perm(p, net::BIND, &ad),
    })
}

/// `aa_unix_listen_perm` of af_unix.c. A socket with a path name has no check.
///
/// # Errors
///
/// Gives `EACCES` if a profile of the task does not allow the listen with the backlog
/// `backlog`.
pub fn listen(sock: &Sock<'_>, backlog: i32) -> Result<()> {
    let l = current_label();
    if l.is_empty() || is_fs(sock) {
        return Ok(());
    }
    let ad = Ad::of("listen", sock);
    each_confined(&l, |p| match net::mediates_af(p, AF_UNIX) {
        Some((pdb, state)) => {
            let mut state = match_to_cmd(pdb, state, sock, CMD_LISTEN);
            if state != NOMATCH {
                state = net::walk(pdb, state, &(backlog as u16).to_be_bytes());
            }
            do_perms(p, pdb, state, net::LISTEN, &ad, None)
        }
        None => af_perm(p, net::LISTEN, &ad),
    })
}

/// `aa_unix_accept_perm` of af_unix.c. A socket with a path name has no check.
///
/// # Errors
///
/// Gives `EACCES` if a profile of the task does not allow the accept.
pub fn accept(sock: &Sock<'_>) -> Result<()> {
    let l = current_label();
    if l.is_empty() || is_fs(sock) {
        return Ok(());
    }
    label_sk_perm(&l, "accept", net::ACCEPT, sock)
}

/// `aa_unix_opt_perm` of af_unix.c: `getsockopt` or `setsockopt` of the option `name`. The
/// match has no level. A socket with a path name has no check.
///
/// # Errors
///
/// Gives `EACCES` if a profile of the task does not allow `request` for the option.
pub fn opt_perm(op: &'static str, request: u32, sock: &Sock<'_>, name: i32) -> Result<()> {
    let l = current_label();
    if l.is_empty() || is_fs(sock) {
        return Ok(());
    }
    let ad = Ad::of(op, sock);
    each_confined(&l, |p| match net::mediates_af(p, AF_UNIX) {
        Some((pdb, state)) => {
            let mut state = match_to_cmd(pdb, state, sock, CMD_OPT);
            if state != NOMATCH {
                state = net::walk(pdb, state, &(name as u16).to_be_bytes());
            }
            do_perms(p, pdb, state, request, &ad, None)
        }
        None => af_perm(p, request, &ad),
    })
}

/// `aa_unix_sock_perm` of af_unix.c: `getsockname`, `getpeername` and `shutdown`.
///
/// # Errors
///
/// Gives `EACCES` if a profile of the task does not allow `request` on the socket.
pub fn sock_perm(op: &'static str, request: u32, sock: &Sock<'_>) -> Result<()> {
    label_sock_perm(&current_label(), op, request, sock)
}

/// `apparmor_unix_stream_connect` of Linux: `sock` connects to the listener `other`, and `new`
/// is the socket of the connection for the listener. The task must be able to connect to the
/// listener, and the label of the listener must be able to take the connection. Then the
/// sockets get the labels of their peers.
///
/// # Errors
///
/// Gives `EACCES` if a profile of the task or of the listener does not allow the connection.
pub fn stream_connect(sock: &Sock<'_>, other: &Sock<'_>, new: &Sock<'_>) -> Result<()> {
    let l = current_label();
    let mut result =
        peer_perm(&l, "connect", net::CONNECT | net::SEND | net::RECEIVE, sock, other, None);
    if !is_fs(other) {
        let request = net::ACCEPT | net::SEND | net::RECEIVE;
        if let Err(e) = peer_perm(&sock_label(other), "connect", request, other, sock, Some(&l)) {
            result = Err(e);
        }
    }
    result?;
    if load(new, LABEL) == 0 {
        store(new, LABEL, load(other, LABEL));
    }
    // The labels of the peers for `SO_PEERSEC`.
    store(new, PEER, load(sock, LABEL));
    store(sock, PEER, load(other, LABEL));
    Ok(())
}

/// `apparmor_unix_may_send` of Linux: the datagram socket `sock` connects or sends to `peer`.
/// The task must be able to send to the peer, and the label of the peer must be able to
/// receive from the task.
///
/// # Errors
///
/// Gives `EACCES` if a profile of the task or of the peer does not allow the send.
pub fn may_send(sock: &Sock<'_>, peer: &Sock<'_>) -> Result<()> {
    let l = current_label();
    let send = peer_perm(&l, "sendmsg", net::SEND, sock, peer, None);
    let receive = peer_perm(&sock_label(peer), "sendmsg", net::RECEIVE, peer, sock, Some(&l));
    receive.and(send)
}

/// `apparmor_socket_getpeersec_stream` of Linux: the label of the peer of `sock` with its mode,
/// as the current task sees it. A Unix socket from `socketpair` has the label of the other
/// socket of the pair.
///
/// # Errors
///
/// Gives `ENOPROTOOPT` if the socket has no peer with a label.
pub fn getpeersec(sock: &Sock<'_>) -> Result<Vec<u8>> {
    let mut peer = word_label(load(sock, PEER));
    if peer.is_none() && sock.family == AF_UNIX {
        if let Some(n) = sock.names {
            n.with_peer(&mut |other| peer = word_label(load(other, LABEL)));
        }
    }
    let peer = peer.ok_or(Errno::ENOPROTOOPT)?;
    let view = domain::profile_of(&rk_vfs::cred::current());
    Ok(domain::label_text(&peer, view.as_deref()).into_bytes())
}

/// `aa_unix_file_perm` of af_unix.c: a read or a write of the socket file of `sock` by the
/// label `l`. A socket with no peer has the check of the socket. A connected socket has the
/// checks of the peer, in the two directions.
///
/// # Errors
///
/// Gives `EACCES` if a profile does not allow the access.
pub fn file_perm(
    l: &[Arc<Profile>],
    op: &'static str,
    request: u32,
    sock: &Sock<'_>,
) -> Result<()> {
    let sk_req = request & !PEER_MASK;
    let mut result = Ok(());
    let connected = sock.names.is_some_and(|n| {
        n.with_peer(&mut |peer| {
            result = if is_fs(sock) {
                fs_perm(op, request, l, sock)
            } else if is_fs(peer) {
                fs_perm(op, request, l, peer)
            } else {
                let mut error = if sk_req != 0 && !l.is_empty() {
                    label_sk_perm(l, op, sk_req, sock)
                } else {
                    Ok(())
                };
                let rw = perm::READ | perm::WRITE;
                let mine = peer_perm(l, op, rw, sock, peer, None);
                let theirs = peer_perm(&sock_label(peer), op, rw, peer, sock, Some(l));
                if let Err(e) = theirs.and(mine) {
                    error = Err(e);
                }
                error
            };
        })
    });
    if !connected && sk_req != 0 {
        return label_sock_perm(l, op, sk_req, sock);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_has_the_unix_addresses_of_linux() {
        let mut s = String::new();
        addr_text(&mut s, "addr", None);
        addr_text(&mut s, "addr", Some(&[1, 0]));
        addr_text(&mut s, "peer_addr", Some(b"\x01\x00/tmp/s\x00"));
        addr_text(&mut s, "addr", Some(b"\x01\x00\x00name"));
        addr_text(&mut s, "addr", Some(b"\x01\x00\x00a b"));
        assert_eq!(s, " addr=none addr=none peer_addr=\"/tmp/s\" addr=\"@name\" addr=\"@612062\"");
        assert!(addr_fs(b"\x01\x00/x"));
        assert!(!addr_fs(b"\x01\x00\x00x"));
        assert!(!addr_fs(b"\x01\x00"));
        assert_eq!(NET_FS_PERMS & (net::ACCEPT | net::BIND | net::LISTEN), 0);
        assert_eq!(PEER_MASK & net::GETATTR, 0);
    }
}
