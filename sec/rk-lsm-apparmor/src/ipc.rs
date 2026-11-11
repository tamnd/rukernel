//! The mediation of the signals, as ipc.c of Linux.
//!
//! The rules of the sender must allow it to send the signal to the label of the target, and
//! the rules of the target must allow it to receive the signal from the label of the sender. A
//! denial gives `EACCES` and a record of the class `signal`:
//!
//! ```text
//! apparmor="DENIED" operation="signal" class="signal" profile="P" pid=PID comm="COMM"
//!     requested_mask="send" denied_mask="send" signal=kill peer="unconfined"
//! ```

use crate::domain::{self, Label};
use crate::label;
use crate::policy::{Mode, Profile};
use crate::unpack::{class, perm};
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use rk_vfs::cred::Cred;
use rk_vfs::inode::Result;

/// `MAXMAPPED_SIG`: the number of the test of existence, the signal 0.
const EXISTS: u32 = 35;
/// `SIGRT_BASE`: the number of `SIGRTMIN` in the rules.
const RT_BASE: u32 = 128;
/// `SIGRTMIN` and `SIGRTMAX` of the kernel.
const RTMIN: u32 = 32;
const RTMAX: u32 = 64;

/// The names of the signals in a record, `sig_names` of Linux. The index is the number of the
/// signal in the rules.
const NAMES: [&str; 36] = [
    "unknown", "hup", "int", "quit", "ill", "trap", "abrt", "bus", "fpe", "kill", "usr1", "segv",
    "usr2", "pipe", "alrm", "term", "stkflt", "chld", "cont", "stop", "stp", "ttin", "ttou", "urg",
    "xcpu", "xfsz", "vtalrm", "prof", "winch", "io", "pwr", "sys", "emt", "lost", "unused",
    "exists",
];

/// The number of the signal `sig` in the rules, `map_signal_num` of Linux. The numbers of the
/// signals of x86_64 and aarch64 are the numbers of the rules. 0 is an unknown signal.
fn map_signal(sig: u32) -> u32 {
    match sig {
        0 => EXISTS,
        1..RTMIN => sig,
        RTMIN..=RTMAX => sig - RTMIN + RT_BASE,
        _ => 0,
    }
}

/// The name of a permission of a signal in a record, `audit_signal_mask` of Linux.
fn mask_text(mask: u32) -> &'static str {
    if mask & perm::READ != 0 {
        "receive"
    } else if mask & perm::WRITE != 0 {
        "send"
    } else {
        ""
    }
}

/// The fields of a record of a signal after `comm`, `audit_signal_cb` of Linux.
fn tail(
    request: u32,
    denied: u32,
    sig: u32,
    mapped: u32,
    peer: &[Arc<Profile>],
    p: &Profile,
) -> String {
    let mut s = String::new();
    let mask = perm::READ | perm::WRITE;
    if request & mask != 0 {
        s.push_str(&format!(" requested_mask=\"{}\"", mask_text(request)));
        if denied & mask != 0 {
            s.push_str(&format!(" denied_mask=\"{}\"", mask_text(denied)));
        }
    }
    match mapped {
        // As on Linux, this field has no space before it.
        0 => s.push_str(&format!("signal=unknown({sig})")),
        m if (m as usize) < NAMES.len() => s.push_str(&format!(" signal={}", NAMES[m as usize])),
        m => s.push_str(&format!(" signal=rtmin+{}", m - RT_BASE)),
    }
    s.push_str(" peer=");
    s.push_str(&label::peer_text(peer, p));
    s
}

/// The check of the signal `sig` for the profile `p` with the label `peer` of the other task,
/// `profile_signal_perm` of Linux. `request` is `MAY_WRITE` for the sender and `MAY_READ` for
/// the target.
fn profile_signal_perm(p: &Profile, peer: &[Arc<Profile>], request: u32, sig: u32) -> Result<()> {
    if p.mode == Mode::Unconfined {
        return Ok(());
    }
    let Some((pdb, start)) = label::mediates(p, class::SIGNAL) else { return Ok(()) };
    let mapped = map_signal(sig);
    let Some(d) = pdb.dfa.as_ref() else { return Ok(()) };
    // The number of a signal of the rules is less than 256.
    let state = d.next(start, mapped as u8);
    let mut perms = label::label_match(p, pdb, peer, state, request);
    label::apply_modes(p, &mut perms);
    label::check_perms(p, &perms, request, "signal", "signal", |r, dn| {
        tail(r, dn, sig, mapped, peer, p)
    })
}

/// The error of the last profile of `l` that denies, as `fn_for_each` of Linux.
fn for_each(l: &Label, mut f: impl FnMut(&Profile) -> Result<()>) -> Result<()> {
    let mut result = Ok(());
    for p in l {
        if let Err(e) = f(p) {
            result = Err(e);
        }
    }
    result
}

/// `apparmor_task_kill` and `aa_may_signal` of Linux: the task with `cred` sends the signal
/// `sig` to the task with `tcred`.
///
/// # Errors
///
/// Gives `EACCES` if the rules of the sender or of the target do not allow the signal, except in
/// complain mode.
pub fn task_kill(cred: &Cred, tcred: &Cred, sig: u32) -> Result<()> {
    let (sid, tid) = (domain::label_id(cred), domain::label_id(tcred));
    if sid == 0 && tid == 0 {
        return Ok(());
    }
    let (sender, target) = (domain::label_of(cred), domain::label_of(tcred));
    let send = for_each(&sender, |p| profile_signal_perm(p, &target, perm::WRITE, sig));
    let receive = for_each(&target, |p| profile_signal_perm(p, &sender, perm::READ, sig));
    // As `xcheck` of Linux: the error of the target comes first.
    match receive {
        Err(e) => Err(e),
        Ok(()) => send,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signal_has_the_number_and_the_name_of_linux() {
        assert_eq!(map_signal(0), EXISTS);
        assert_eq!(NAMES[map_signal(9) as usize], "kill");
        assert_eq!(NAMES[map_signal(20) as usize], "stp");
        assert_eq!(NAMES[map_signal(0) as usize], "exists");
        assert_eq!(map_signal(34), RT_BASE + 2);
        assert_eq!(map_signal(65), 0);
    }
}
