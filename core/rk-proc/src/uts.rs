//! The host name and the NIS domain name of the system, for `uname`, `sethostname`,
//! `setdomainname` and /proc/sys/kernel.
//!
//! The kernel has no UTS namespace, so each process sees the same names. A name has at most
//! `NAME_MAX` bytes, as the fields of `struct new_utsname` have 65 bytes with the null byte.

use rk_frame::sync::SpinLock;

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

static HOSTNAME: SpinLock<Field> = SpinLock::new(DEFAULT);
static DOMAINNAME: SpinLock<Field> = SpinLock::new(DEFAULT);

/// The host name.
pub fn hostname() -> Field {
    *HOSTNAME.lock()
}

/// The NIS domain name.
pub fn domainname() -> Field {
    *DOMAINNAME.lock()
}

/// Sets the host name. Gives `false` if `name` is longer than `NAME_MAX`.
pub fn set_hostname(name: &[u8]) -> bool {
    field(name).map(|f| *HOSTNAME.lock() = f).is_some()
}

/// Sets the NIS domain name. Gives `false` if `name` is longer than `NAME_MAX`.
pub fn set_domainname(name: &[u8]) -> bool {
    field(name).map(|f| *DOMAINNAME.lock() = f).is_some()
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
}
