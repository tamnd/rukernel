//! The host name and the NIS domain name of the system, for `uname`, `sethostname`,
//! `setdomainname` and /proc/sys/kernel.
//!
//! Each thread is in a UTS namespace, which has its own names, as kernel/utsname.c of Linux. A
//! name has at most `NAME_MAX` bytes, as the fields of `struct new_utsname` have 65 bytes with the
//! null byte.
//!
//! A change of a name is an event of `poll` on /proc/sys/kernel/hostname or
//! /proc/sys/kernel/domainname, as `uts_proc_notify` of Linux. The events are global, so a change
//! in any namespace is an event.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use rk_frame::sync::{Once, SpinLock};
use rk_vfs::user_ns::{self, UserNs};
use rk_vfs::wait::WaitQueue;

/// The most bytes of a name, `__NEW_UTS_LEN`.
pub const NAME_MAX: usize = 64;

/// A name of `struct new_utsname`: the bytes and a null byte at the end.
pub type Field = [u8; NAME_MAX + 1];

/// Makes a field from `s`. Gives `None` if `s` is longer than `NAME_MAX`.
pub const fn field(s: &[u8]) -> Option<Field> {
    if s.len() > NAME_MAX {
        return None;
    }
    let mut f = [0u8; NAME_MAX + 1];
    let mut i = 0;
    while i < s.len() {
        f[i] = s[i];
        i += 1;
    }
    Some(f)
}

/// The bytes of a field before the first null byte.
pub fn bytes(f: &Field) -> &[u8] {
    let n = f.iter().position(|&b| b == 0).unwrap_or(NAME_MAX);
    &f[..n]
}

/// The name of the host at boot, as Linux has with no `CONFIG_DEFAULT_HOSTNAME`.
const DEFAULT: Field = match field(b"(none)") {
    Some(f) => f,
    None => [0; NAME_MAX + 1],
};

/// A UTS namespace: a host name and a NIS domain name, as `struct uts_namespace` of Linux.
pub struct UtsNs {
    /// The ID of the namespace for nsfs. The first namespace has the ID 0.
    id: u32,
    /// The host name and the NIS domain name.
    names: SpinLock<(Field, Field)>,
    /// The user namespace that owns the namespace, `user_ns` of Linux.
    user_ns: Arc<UserNs>,
}

/// A name with an event of `poll`, as `enum uts_proc` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Name {
    /// The host name, `UTS_PROC_HOSTNAME`.
    Host,
    /// The NIS domain name, `UTS_PROC_DOMAINNAME`.
    Domain,
}

/// The count of the changes of each name, the `event` of `hostname_poll` and `domainname_poll`
/// of Linux.
static EVENTS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// The waits of `poll` for a change of a name.
static POLL: WaitQueue = WaitQueue::new();

/// The count of the changes of `name`.
pub fn event(name: Name) -> u64 {
    EVENTS[name as usize].load(Ordering::Relaxed)
}

/// The queue that a change of a name wakes.
pub fn poll_queue() -> &'static WaitQueue {
    &POLL
}

/// Counts a change of `name` and wakes the waits, as `uts_proc_notify` of Linux.
fn notify(name: Name) {
    EVENTS[name as usize].fetch_add(1, Ordering::Relaxed);
    POLL.wake_all();
}

/// The UTS namespaces other than the first one, for `by_id`.
static LIVE: SpinLock<Vec<Weak<UtsNs>>> = SpinLock::new(Vec::new());

/// The next ID for a UTS namespace.
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

/// The first UTS namespace, `init_uts_ns` of Linux.
pub fn init_ns() -> Arc<UtsNs> {
    static INIT: Once<Arc<UtsNs>> = Once::new();
    INIT.call_once(|| {
        Arc::new(UtsNs {
            id: 0,
            names: SpinLock::new((DEFAULT, DEFAULT)),
            user_ns: user_ns::init().clone(),
        })
    })
    .clone()
}

/// The UTS namespace with the ID `id`, while it exists.
pub fn by_id(id: u32) -> Option<Arc<UtsNs>> {
    if id == 0 {
        return Some(init_ns());
    }
    LIVE.lock().iter().filter_map(Weak::upgrade).find(|ns| ns.id == id)
}

impl UtsNs {
    /// The ID of the namespace.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Tells if this is the first namespace.
    pub fn is_init(&self) -> bool {
        self.id == 0
    }

    /// Makes a new namespace with a copy of the names of this one, which the user namespace
    /// `owner` owns, as `clone_uts_ns` of Linux.
    pub fn copy(&self, owner: Arc<UserNs>) -> Arc<UtsNs> {
        let names = *self.names.lock();
        let ns = Arc::new(UtsNs {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            names: SpinLock::new(names),
            user_ns: owner,
        });
        let mut live = LIVE.lock();
        live.retain(|w| w.strong_count() > 0);
        live.push(Arc::downgrade(&ns));
        ns
    }

    /// The user namespace that owns the namespace.
    pub fn user_ns(&self) -> &Arc<UserNs> {
        &self.user_ns
    }

    /// The host name.
    pub fn hostname(&self) -> Field {
        self.names.lock().0
    }

    /// The NIS domain name.
    pub fn domainname(&self) -> Field {
        self.names.lock().1
    }

    /// Sets the host name. Gives `false` if `name` is longer than `NAME_MAX`.
    pub fn set_hostname(&self, name: &[u8]) -> bool {
        let Some(f) = field(name) else { return false };
        self.names.lock().0 = f;
        notify(Name::Host);
        true
    }

    /// Sets the NIS domain name. Gives `false` if `name` is longer than `NAME_MAX`.
    pub fn set_domainname(&self, name: &[u8]) -> bool {
        let Some(f) = field(name) else { return false };
        self.names.lock().1 = f;
        notify(Name::Domain);
        true
    }
}

/// The UTS namespace of the current thread, or the first one for a kernel task.
#[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn current() -> Arc<UtsNs> {
    crate::process::current_thread().map_or_else(init_ns, |t| t.uts_ns())
}

/// The UTS namespace of the current thread: the tests on the host have only the first one.
#[cfg(not(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn current() -> Arc<UtsNs> {
    init_ns()
}

/// The host name of the namespace of the current thread.
pub fn hostname() -> Field {
    current().hostname()
}

/// The NIS domain name of the namespace of the current thread.
pub fn domainname() -> Field {
    current().domainname()
}

/// Sets the host name of the namespace of the current thread. Gives `false` if `name` is longer
/// than `NAME_MAX`.
pub fn set_hostname(name: &[u8]) -> bool {
    current().set_hostname(name)
}

/// Sets the NIS domain name of the namespace of the current thread. Gives `false` if `name` is
/// longer than `NAME_MAX`.
pub fn set_domainname(name: &[u8]) -> bool {
    current().set_domainname(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_field_has_a_null_byte() {
        let f = field(b"abc").unwrap();
        assert_eq!(bytes(&f), b"abc");
        assert_eq!(f[3..], [0; 62]);
        assert!(field(&[b'a'; 64]).is_some());
        assert!(field(&[b'a'; 65]).is_none());
        assert_eq!(bytes(&field(&[b'a'; 64]).unwrap()).len(), 64);
    }

    #[test]
    fn a_set_name_comes_back() {
        assert!(set_domainname(b"example.org"));
        assert_eq!(bytes(&domainname()), b"example.org");
        assert!(!set_domainname(&[b'x'; 65]));
        assert_eq!(bytes(&domainname()), b"example.org");
    }

    #[test]
    fn a_change_is_an_event() {
        let ns = init_ns().copy(user_ns::init().clone());
        let (host, domain) = (event(Name::Host), event(Name::Domain));
        assert!(ns.set_hostname(b"h"));
        assert!(event(Name::Host) > host);
        assert!(!ns.set_domainname(&[b'x'; 65]));
        assert!(ns.set_domainname(b"d"));
        assert!(event(Name::Domain) > domain);
    }

    #[test]
    fn a_new_namespace_has_a_copy_of_the_names() {
        let parent = init_ns().copy(user_ns::init().clone());
        assert!(parent.set_hostname(b"parent"));
        let child = parent.copy(user_ns::init().clone());
        assert_ne!(child.id(), parent.id());
        assert!(!child.is_init());
        assert_eq!(bytes(&child.hostname()), b"parent");
        assert!(child.set_hostname(b"child"));
        assert_eq!(bytes(&child.hostname()), b"child");
        assert_eq!(bytes(&parent.hostname()), b"parent");
        assert!(by_id(child.id()).is_some_and(|ns| Arc::ptr_eq(&ns, &child)));
        let id = child.id();
        drop(child);
        assert!(by_id(id).is_none());
        assert!(by_id(0).is_some_and(|ns| ns.is_init()));
    }
}
