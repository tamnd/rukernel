//! The protocol `NETLINK_AUDIT`, as kernel/audit.c of Linux.
//!
//! auditd and auditctl use a socket of this protocol to read and to change the state of the
//! audit system with `AUDIT_GET` and `AUDIT_SET`. A process with `CAP_AUDIT_WRITE` sends the
//! user messages (`AUDIT_USER`, `AUDIT_FIRST_USER_MSG` to `AUDIT_LAST_USER_MSG` and
//! `AUDIT_FIRST_USER_MSG2` to `AUDIT_LAST_USER_MSG2`), and the kernel makes a record of each.
//!
//! A record goes to the socket of auditd if auditd is registered, else to the kernel log as
//! `audit: type=N ...`. A copy goes to the sockets in the group `AUDIT_NLGRP_READLOG` too. The
//! kernel has no audit rules: `AUDIT_LIST_RULES` gives an empty list, and the other changes of
//! the rules give `EOPNOTSUPP`.

use super::msg::{self, HDRLEN, Header};
use super::{F_CAP_ACK, F_EXT_ACK, NetlinkSocket, broadcast};
use crate::ns;
use alloc::format;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicU32, Ordering};
use rk_abi::Errno;
use rk_abi::native::netlink::{NETLINK_AUDIT, NLM_F_ACK, NLM_F_MULTI, NLMSG_DONE};
use rk_frame::sync::SpinLock;
use rk_vfs::cred::{self, cap};
use rk_vfs::inode::Result;
use rk_vfs::user_ns;

/// The number of groups of the protocol, `AUDIT_NLGRP_MAX`.
pub const NGROUPS: u32 = 1;

/// The group that gets a copy of each record, `AUDIT_NLGRP_READLOG`.
const NLGRP_READLOG: u32 = 1;

// The types of the messages, as include/uapi/linux/audit.h of Linux.
const GET: u16 = 1000;
const SET: u16 = 1001;
const LIST: u16 = 1002;
const ADD: u16 = 1003;
const DEL: u16 = 1004;
const USER: u16 = 1005;
const SIGNAL_INFO: u16 = 1010;
const ADD_RULE: u16 = 1011;
const DEL_RULE: u16 = 1012;
const LIST_RULES: u16 = 1013;
const TRIM: u16 = 1014;
const MAKE_EQUIV: u16 = 1015;
const TTY_GET: u16 = 1016;
const TTY_SET: u16 = 1017;
const SET_FEATURE: u16 = 1018;
const GET_FEATURE: u16 = 1019;
const FIRST_USER_MSG: u16 = 1100;
const USER_AVC: u16 = 1107;
const USER_TTY: u16 = 1124;
const LAST_USER_MSG: u16 = 1199;
const FIRST_USER_MSG2: u16 = 2100;
const LAST_USER_MSG2: u16 = 2999;
const CONFIG_CHANGE: u16 = 1305;

// The bits of `audit_status.mask`, `AUDIT_STATUS_*`.
const STATUS_ENABLED: u32 = 0x01;
const STATUS_FAILURE: u32 = 0x02;
const STATUS_PID: u32 = 0x04;
const STATUS_RATE_LIMIT: u32 = 0x08;
const STATUS_BACKLOG_LIMIT: u32 = 0x10;
const STATUS_BACKLOG_WAIT_TIME: u32 = 0x20;
const STATUS_LOST: u32 = 0x40;
const STATUS_BACKLOG_WAIT_TIME_ACTUAL: u32 = 0x80;

/// The features of `audit_status.feature_bitmap`, `AUDIT_FEATURE_BITMAP_ALL`.
const FEATURE_BITMAP_ALL: u32 = 0x7f;

/// The value of `enabled` that locks the configuration, `AUDIT_LOCKED`.
const LOCKED: u32 = 2;

/// The size of `struct audit_status`: 11 fields of 32 bits.
const STATUS_SIZE: usize = 44;

/// The most bytes of the text of a user message, `AUDIT_MESSAGE_TEXT_MAX`.
const MESSAGE_TEXT_MAX: usize = 8560;

/// The ID that is not set, `AUDIT_UNSET` and `(u32)-1`.
const UNSET: u32 = u32::MAX;

/// The facts of the current process that a record shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Task {
    /// The ID of the process in the first PID namespace, `task_tgid_nr`.
    pub pid: i32,
    /// The real user ID.
    pub uid: u32,
    /// The login user ID, `AUDIT_UNSET` when it is not set.
    pub auid: u32,
    /// The audit session ID, `AUDIT_UNSET` when it is not set.
    pub ses: u32,
    /// The process is in the first PID namespace.
    pub init_pid_ns: bool,
}

static TASK_SOURCE: SpinLock<Option<fn() -> Task>> = SpinLock::new(None);

/// Sets the function that gives the facts of the current process. The process layer calls
/// this one time at boot.
pub fn set_task_source(f: fn() -> Task) {
    *TASK_SOURCE.lock() = Some(f);
}

fn task() -> Task {
    let source = *TASK_SOURCE.lock();
    source.map_or_else(
        || Task {
            pid: crate::current_cred().pid,
            uid: cred::current().uid,
            auid: UNSET,
            ses: UNSET,
            init_pid_ns: true,
        },
        |f| f(),
    )
}

/// The registered audit daemon, as `struct auditd_connection` of Linux.
struct Auditd {
    pid: i32,
    sock: Weak<NetlinkSocket>,
}

static AUDITD: SpinLock<Option<Auditd>> = SpinLock::new(None);

/// The state of the audit system, as the globals of kernel/audit.c of Linux.
struct State {
    enabled: u32,
    failure: u32,
    rate_limit: u32,
    backlog_limit: u32,
    backlog_wait_time: u32,
}

/// The default `backlog_wait_time`, `AUDIT_BACKLOG_WAIT_TIME`: 60 seconds in ticks.
const WAIT_TIME: u32 = (60 * HZ) as u32;

/// The ticks of the timer each second. The host has no timer.
#[cfg(target_os = "none")]
const HZ: u64 = rk_frame::time::HZ;
#[cfg(not(target_os = "none"))]
const HZ: u64 = 100;

/// The real time in nanoseconds. The host has no clock.
fn realtime_ns() -> u64 {
    #[cfg(target_os = "none")]
    let ns = rk_frame::time::realtime_ns();
    #[cfg(not(target_os = "none"))]
    let ns = 0;
    ns
}

/// Puts a line in the kernel log with the level `KERN_NOTICE`. The host has no kernel log.
fn printk(line: &str) {
    #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
    rk_frame::console::log_emit(5, line.as_bytes());
    #[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
    let _ = line;
}

static STATE: SpinLock<State> = SpinLock::new(State {
    enabled: 0,
    failure: 1,
    rate_limit: 0,
    backlog_limit: 64,
    backlog_wait_time: WAIT_TIME,
});

/// The records that did not go to auditd, `audit_lost`.
static LOST: AtomicU32 = AtomicU32::new(0);

/// The serial number of the last record, as `audit_serial` of Linux.
static SERIAL: AtomicU32 = AtomicU32::new(0);

/// The process ID and the socket of auditd, as `auditd_conn`. A socket that was closed resets
/// the connection, as `auditd_reset` of Linux after `netlink_unicast` failed.
fn auditd() -> Option<(i32, Arc<NetlinkSocket>)> {
    let mut a = AUDITD.lock();
    let d = a.as_ref()?;
    match d.sock.upgrade() {
        Some(sock) => Some((d.pid, sock)),
        None => {
            *a = None;
            None
        }
    }
}

/// The process ID of auditd, or 0.
fn auditd_pid() -> i32 {
    auditd().map_or(0, |(pid, _)| pid)
}

/// Sends a record of the type `ty` with the text `text`, as `audit_log_start`,
/// `audit_log_end` and `kauditd_thread` of Linux. The text starts with the time and the serial
/// number, `audit(SEC.MSEC:SERIAL): `.
fn log(ty: u16, text: &str) {
    let ns = realtime_ns();
    let serial = SERIAL.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    let body = format!(
        "audit({}.{:03}:{serial}): {text}",
        ns / 1_000_000_000,
        ns % 1_000_000_000 / 1_000_000
    );
    let mut record = Header { len: 0, ty, flags: 0, seq: 0, pid: 0 }.bytes().to_vec();
    record.extend_from_slice(body.as_bytes());
    // The copy for the group has the full length in `nlmsg_len`, as
    // `kauditd_send_multicast_skb` of Linux.
    let full = record.len() as u32;
    record[0..4].copy_from_slice(&full.to_ne_bytes());
    {
        let _in = ns::enter(&ns::init_ns());
        broadcast(NETLINK_AUDIT, None, &record, 0, 0, NLGRP_READLOG);
    }
    match auditd() {
        Some((_, sock)) => {
            // The record for auditd has the length of the text in `nlmsg_len`, as
            // `audit_log_end` of Linux. auditd reads the record in this way.
            record[0..4].copy_from_slice(&(body.len() as u32).to_ne_bytes());
            if !sock.queue(record, 0, 0) {
                LOST.fetch_add(1, Ordering::Relaxed);
            }
        }
        None => {
            let line = format!("audit: type={ty} {body}\n");
            printk(&line);
        }
    }
}

/// Sends a `CONFIG_CHANGE` record, as `audit_log_config_change` of Linux.
fn log_config_change(name: &str, new: u32, old: u32, res: bool) {
    let t = task();
    let res = u8::from(res);
    log(
        CONFIG_CHANGE,
        &format!("op=set {name}={new} old={old} auid={} ses={} res={res}", t.auid, t.ses),
    );
}

/// Changes a value of the state, as `audit_do_config_change` of Linux. The change makes a
/// record if audit is on, and a locked state gives `EPERM`.
fn config_change(
    s: &mut State,
    name: &str,
    field: fn(&mut State) -> &mut u32,
    new: u32,
) -> Result<()> {
    let old = *field(s);
    let allow = s.enabled != LOCKED;
    if s.enabled != 0 {
        log_config_change(name, new, old, allow);
    }
    if !allow {
        return Err(Errno::EPERM);
    }
    *field(s) = new;
    Ok(())
}

/// Checks the type of a message and the rights of the sender, as `audit_netlink_ok` of Linux.
fn netlink_ok(ty: u16) -> Result<()> {
    let c = cred::current();
    if !Arc::ptr_eq(&c.user_ns, user_ns::init()) {
        return Err(Errno::ECONNREFUSED);
    }
    match ty {
        LIST | ADD | DEL => Err(Errno::EOPNOTSUPP),
        GET | SET | GET_FEATURE | SET_FEATURE | LIST_RULES | ADD_RULE | DEL_RULE | SIGNAL_INFO
        | TTY_GET | TTY_SET | TRIM | MAKE_EQUIV => {
            if !task().init_pid_ns || !c.capable(cap::AUDIT_CONTROL) {
                return Err(Errno::EPERM);
            }
            Ok(())
        }
        USER | FIRST_USER_MSG..=LAST_USER_MSG | FIRST_USER_MSG2..=LAST_USER_MSG2 => {
            if c.capable(cap::AUDIT_WRITE) { Ok(()) } else { Err(Errno::EPERM) }
        }
        _ => Err(Errno::EINVAL),
    }
}

/// Sends a reply to the sender, as `audit_send_reply` of Linux. The reply has the port ID 0
/// and the sequence number of the request.
fn reply(sock: &NetlinkSocket, h: Header, ty: u16, flags: u16, payload: &[u8]) {
    let mut b = msg::Builder::new(ty, flags, h.seq, 0);
    b.fixed(payload);
    sock.deliver(b.finish(), 0, 0);
}

/// The bytes of a list of 32-bit fields.
fn words(fields: &[u32]) -> Vec<u8> {
    fields.iter().flat_map(|f| f.to_ne_bytes()).collect()
}

/// The bytes of `struct audit_status`, as the case `AUDIT_GET` of `audit_receive_msg`.
fn status() -> Vec<u8> {
    let pid = auditd_pid() as u32;
    let s = STATE.lock();
    let lost = LOST.load(Ordering::Relaxed);
    let b = words(&[
        0,
        s.enabled,
        s.failure,
        pid,
        s.rate_limit,
        s.backlog_limit,
        lost,
        0,
        FEATURE_BITMAP_ALL,
        s.backlog_wait_time,
        0,
    ]);
    debug_assert_eq!(b.len(), STATUS_SIZE);
    b
}

/// Runs `AUDIT_SET`, as the case `AUDIT_SET` of `audit_receive_msg` of Linux. Gives the
/// number of the lost records if the mask has `AUDIT_STATUS_LOST`.
fn set(sock: &NetlinkSocket, h: Header, data: &[u8]) -> Result<u32> {
    let mut raw = [0u8; STATUS_SIZE];
    let n = data.len().min(STATUS_SIZE);
    raw[..n].copy_from_slice(&data[..n]);
    let field =
        |i: usize| u32::from_ne_bytes([raw[i * 4], raw[i * 4 + 1], raw[i * 4 + 2], raw[i * 4 + 3]]);
    let mask = field(0);
    let mut s = STATE.lock();
    if mask & STATUS_ENABLED != 0 {
        let v = field(1);
        if v > LOCKED {
            return Err(Errno::EINVAL);
        }
        config_change(&mut s, "audit_enabled", |s| &mut s.enabled, v)?;
    }
    if mask & STATUS_FAILURE != 0 {
        let v = field(2);
        if v > 2 {
            return Err(Errno::EINVAL);
        }
        config_change(&mut s, "audit_failure", |s| &mut s.failure, v)?;
    }
    if mask & STATUS_PID != 0 {
        let new = field(3) as i32;
        let me = task().pid;
        if new != 0 && new != me {
            return Err(Errno::EINVAL);
        }
        let old = auditd_pid();
        if old != 0 {
            // A live auditd stays, and only auditd can stop itself.
            if new != 0 {
                log_config_change("audit_pid", new as u32, old as u32, false);
                return Err(Errno::EEXIST);
            }
            if me != old {
                log_config_change("audit_pid", new as u32, old as u32, false);
                return Err(Errno::EACCES);
            }
        }
        // The record of a new auditd goes to it, and the record of the end goes to the old
        // one, as Linux does.
        if new != 0 {
            *AUDITD.lock() = Some(Auditd { pid: new, sock: sock.me.clone() });
        }
        if s.enabled != 0 {
            log_config_change("audit_pid", new as u32, old as u32, true);
        }
        if new == 0 {
            *AUDITD.lock() = None;
        }
    }
    if mask & STATUS_RATE_LIMIT != 0 {
        config_change(&mut s, "audit_rate_limit", |s| &mut s.rate_limit, field(4))?;
    }
    if mask & STATUS_BACKLOG_LIMIT != 0 {
        config_change(&mut s, "audit_backlog_limit", |s| &mut s.backlog_limit, field(5))?;
    }
    if mask & STATUS_BACKLOG_WAIT_TIME != 0 {
        let v = field(9);
        if (h.len as usize) < STATUS_SIZE || v > 10 * WAIT_TIME {
            return Err(Errno::EINVAL);
        }
        config_change(&mut s, "audit_backlog_wait_time", |s| &mut s.backlog_wait_time, v)?;
    }
    drop(s);
    if mask & STATUS_LOST != 0 {
        let lost = LOST.swap(0, Ordering::Relaxed);
        log_config_change("lost", 0, lost, true);
        return Ok(lost);
    }
    if mask & STATUS_BACKLOG_WAIT_TIME_ACTUAL != 0 {
        log_config_change("backlog_wait_time_actual", 0, 0, true);
    }
    Ok(0)
}

/// Tells if a string needs the hex form in a record, as `audit_string_contains_control`.
fn has_control(b: &[u8]) -> bool {
    b.iter().any(|&c| c == b'"' || !(0x21..=0x7e).contains(&c))
}

/// Writes a string from a process: in quotes, or in hex if it has a control character, a
/// space or a quote, as `audit_log_n_untrustedstring` of Linux.
fn untrusted(out: &mut String, b: &[u8]) {
    if has_control(b) {
        for c in b {
            let _ = write!(out, "{c:02X}");
        }
    } else {
        out.push('"');
        out.extend(b.iter().map(|&c| char::from(c)));
        out.push('"');
    }
}

/// Makes the record of a user message, as the user cases of `audit_receive_msg` and
/// `audit_log_user_recv_msg` of Linux.
fn user_msg(ty: u16, data: &[u8]) -> Result<()> {
    if STATE.lock().enabled == 0 && ty != USER_AVC {
        return Ok(());
    }
    // A message must have at least one character to print.
    if data.len() < 2 {
        return Err(Errno::EINVAL);
    }
    let t = task();
    let mut text = format!("pid={} uid={} auid={} ses={}", t.pid, t.uid, t.auid, t.ses);
    if ty == USER_TTY {
        text.push_str(" data=");
        let d = data.strip_suffix(&[0]).unwrap_or(data);
        untrusted(&mut text, d);
    } else {
        // The last byte becomes the end of the string.
        let d = &data[..data.len() - 1];
        let end = d.iter().position(|&c| c == 0).unwrap_or(d.len()).min(MESSAGE_TEXT_MAX);
        text.push_str(" msg='");
        text.push_str(&String::from_utf8_lossy(&d[..end]));
        text.push('\'');
    }
    log(ty, &text);
    Ok(())
}

/// Runs one message, as `audit_receive_msg` of Linux. A positive result goes in the ack as
/// the error.
fn receive_msg(sock: &NetlinkSocket, h: Header, m: &[u8]) -> Result<u32> {
    netlink_ok(h.ty)?;
    let data = m.get(HDRLEN..).unwrap_or(&[]);
    match h.ty {
        GET => reply(sock, h, GET, 0, &status()),
        SET => return set(sock, h, data),
        GET_FEATURE => reply(sock, h, GET_FEATURE, 0, &words(&[1, 0, 0, 0])),
        // There are no rules: the list has only its end.
        LIST_RULES => reply(sock, h, NLMSG_DONE as u16, NLM_F_MULTI as u16, &[]),
        // No signal went to auditd: no user and no process.
        SIGNAL_INFO => reply(sock, h, SIGNAL_INFO, 0, &words(&[UNSET, 0])),
        // The TTY input of the process is not audited.
        TTY_GET => reply(sock, h, TTY_GET, 0, &words(&[0, 0])),
        ADD_RULE | DEL_RULE | TRIM | MAKE_EQUIV | SET_FEATURE | TTY_SET => {
            return Err(Errno::EOPNOTSUPP);
        }
        _ => user_msg(h.ty, data)?,
    }
    Ok(0)
}

/// Runs each message that a process sends, as `audit_receive` of Linux. The kernel sends an
/// ack for a message with `NLM_F_ACK`, for an error, and for a positive result.
pub(super) fn rcv(sock: &NetlinkSocket, data: &[u8]) {
    let portid = sock.portid();
    for m in msg::messages(data) {
        let Some(h) = Header::parse(m) else { break };
        let err = match receive_msg(sock, h, m) {
            Ok(n) => n as i32,
            Err(e) => -i32::from(e.get()),
        };
        if h.flags & NLM_F_ACK as u16 != 0 || err != 0 {
            let flags = sock.state.lock().flags;
            let cap_ack = flags & F_CAP_ACK != 0;
            let ext = msg::ExtAck::default();
            let ext = (flags & F_EXT_ACK != 0).then_some(&ext);
            sock.deliver(msg::ack_ext(m, err, portid, cap_ack, ext), 0, 0);
        }
    }
}

/// Checks a group for `bind`, as `audit_multicast_bind` of Linux: the reader of the log needs
/// `CAP_AUDIT_READ`.
pub(super) fn bind(_group: u32) -> Result<()> {
    if cred::current().capable(cap::AUDIT_READ) { Ok(()) } else { Err(Errno::EPERM) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::SOCK_RAW;
    use crate::netlink::sockaddr;
    use crate::{Message, NoPaths, Socket};

    /// The tests change the global state, so they run one at a time.
    static SERIAL_TESTS: SpinLock<()> = SpinLock::new(());

    fn test_task() -> Task {
        Task { pid: 4242, uid: 0, auid: 1000, ses: 3, init_pid_ns: true }
    }

    fn socket(groups: u32) -> Arc<NetlinkSocket> {
        let s = NetlinkSocket::new(SOCK_RAW, NETLINK_AUDIT).unwrap();
        s.bind(&NoPaths, &sockaddr(0, groups)).unwrap();
        s
    }

    fn send(s: &NetlinkSocket, ty: u16, flags: u16, payload: &[u8]) {
        let mut b = msg::Builder::new(ty, flags | 1, 7, 0);
        b.fixed(payload);
        let m = Message { data: b.finish(), ..Message::default() };
        s.send(&NoPaths, m, 0, true).unwrap();
    }

    fn recv_all(s: &NetlinkSocket) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Ok(r) = s.recv(65536, 0, true) {
            out.push(r.data);
        }
        out
    }

    fn ty(m: &[u8]) -> u16 {
        Header::parse(m).unwrap().ty
    }

    fn err(m: &[u8]) -> i32 {
        assert_eq!(ty(m), rk_abi::native::netlink::NLMSG_ERROR as u16);
        i32::from_ne_bytes(m[16..20].try_into().unwrap())
    }

    fn set_msg(mask: u32, index: usize, value: u32) -> Vec<u8> {
        let mut f = [0u32; 11];
        f[0] = mask;
        f[index] = value;
        words(&f)
    }

    #[test]
    fn get_gives_the_status_and_set_changes_it() {
        let _serial = SERIAL_TESTS.lock();
        set_task_source(test_task);
        let s = socket(0);
        send(&s, GET, NLM_F_ACK as u16, &[]);
        let got = recv_all(&s);
        assert_eq!(got.len(), 2);
        assert_eq!(ty(&got[0]), GET);
        assert_eq!(got[0].len(), HDRLEN + STATUS_SIZE);
        let field =
            |i: usize| u32::from_ne_bytes(got[0][16 + i * 4..20 + i * 4].try_into().unwrap());
        assert_eq!(
            (field(2), field(5), field(8), field(9)),
            (1, 64, FEATURE_BITMAP_ALL, WAIT_TIME)
        );
        assert_eq!(err(&got[1]), 0);

        // A bad value gives EINVAL, and the old types give EOPNOTSUPP.
        send(&s, SET, 0, &set_msg(STATUS_ENABLED, 1, 3));
        assert_eq!(err(&recv_all(&s)[0]), -i32::from(Errno::EINVAL.get()));
        send(&s, LIST, 0, &[]);
        assert_eq!(err(&recv_all(&s)[0]), -i32::from(Errno::EOPNOTSUPP.get()));
        send(&s, 999, 0, &[]);
        assert_eq!(err(&recv_all(&s)[0]), -i32::from(Errno::EINVAL.get()));

        send(&s, SET, NLM_F_ACK as u16, &set_msg(STATUS_BACKLOG_LIMIT, 5, 128));
        assert_eq!(err(&recv_all(&s)[0]), 0);
        assert_eq!(STATE.lock().backlog_limit, 128);
        STATE.lock().backlog_limit = 64;

        // No rules: the list has only its end.
        send(&s, LIST_RULES, 0, &[]);
        let got = recv_all(&s);
        assert_eq!(got.len(), 1);
        assert_eq!(ty(&got[0]), NLMSG_DONE as u16);
    }

    #[test]
    fn the_records_go_to_the_group_and_to_auditd() {
        let _serial = SERIAL_TESTS.lock();
        set_task_source(test_task);
        let reader = socket(1);
        let s = socket(0);
        send(&s, SET, 0, &set_msg(STATUS_ENABLED, 1, 1));
        assert!(recv_all(&s).is_empty());

        send(&s, 1100, 0, b"hello\0");
        let got = recv_all(&reader);
        let m = got.last().unwrap();
        assert_eq!(ty(m), 1100);
        assert_eq!(Header::parse(m).unwrap().len as usize, m.len());
        let text = core::str::from_utf8(&m[HDRLEN..]).unwrap();
        assert!(text.starts_with("audit("));
        assert!(text.ends_with("): pid=4242 uid=0 auid=1000 ses=3 msg='hello'"), "{text}");
        send(&s, 1100, 0, b"");
        assert_eq!(err(&recv_all(&s)[0]), -i32::from(Errno::EINVAL.get()));

        // auditd registers with its own process ID, and the records go to it.
        send(&s, SET, 0, &set_msg(STATUS_PID, 3, 99));
        assert_eq!(err(&recv_all(&s)[0]), -i32::from(Errno::EINVAL.get()));
        send(&s, SET, 0, &set_msg(STATUS_PID, 3, 4242));
        let got = recv_all(&s);
        assert_eq!(got.len(), 1);
        assert_eq!(ty(&got[0]), CONFIG_CHANGE);
        let text = core::str::from_utf8(&got[0][HDRLEN..]).unwrap();
        assert!(text.ends_with("op=set audit_pid=4242 old=0 auid=1000 ses=3 res=1"), "{text}");
        assert_eq!(Header::parse(&got[0]).unwrap().len as usize, got[0].len() - HDRLEN);
        let other = socket(0);
        send(&other, SET, 0, &set_msg(STATUS_PID, 3, 4242));
        assert_eq!(err(&recv_all(&other)[0]), -i32::from(Errno::EEXIST.get()));
        recv_all(&s);
        send(&other, USER_TTY, 0, b"ls -l -\0");
        let got = recv_all(&s);
        let text = core::str::from_utf8(&got[0][HDRLEN..]).unwrap();
        assert!(text.ends_with(" data=6C73202D6C202D"), "{text}");

        // A closed auditd goes away.
        drop(s);
        assert_eq!(auditd_pid(), 0);
        STATE.lock().enabled = 0;
        recv_all(&reader);
        send(&other, 1100, 0, b"off\0");
        assert!(recv_all(&reader).is_empty());
    }
}
