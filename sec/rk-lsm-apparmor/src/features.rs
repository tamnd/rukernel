//! The features of the kernel, the directory `features` of the files of AppArmor, as
//! `aa_sfs_entry_features` of security/apparmor/apparmorfs.c of Linux.
//!
//! The policy compiler reads these files and makes a policy that the kernel can unpack. The list
//! is the list of Linux 6.8 without the parts of Ubuntu. It does not have `compressed_load`, so
//! the compiler does not compress the policy.

use alloc::format;
use alloc::vec::Vec;

/// The value of a feature file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    /// `yes` or `no`, as `AA_SFS_FILE_BOOLEAN`.
    Bool(bool),
    /// A text, as `AA_SFS_FILE_STRING`.
    Str(&'static str),
    /// A number in hex, as `AA_SFS_FILE_U64`.
    U64(u64),
}

impl Value {
    /// The text of the file, with a new line, as `aa_sfs_seq_show` of Linux.
    pub fn text(self) -> Vec<u8> {
        match self {
            Self::Bool(b) => format!("{}\n", if b { "yes" } else { "no" }),
            Self::Str(s) => format!("{s}\n"),
            Self::U64(v) => format!("{v:#08x}\n"),
        }
        .into_bytes()
    }
}

/// The capabilities, `AA_SFS_CAPS_MASK`.
const CAPS_MASK: &str = "chown dac_override dac_read_search fowner fsetid kill setgid setuid \
setpcap linux_immutable net_bind_service net_broadcast net_admin net_raw ipc_lock ipc_owner \
sys_module sys_rawio sys_chroot sys_ptrace sys_pacct sys_admin sys_boot sys_nice sys_resource \
sys_time sys_tty_config mknod lease audit_write audit_control setfcap mac_override mac_admin \
syslog wake_alarm block_suspend audit_read perfmon bpf checkpoint_restore";

/// The address families, `AA_SFS_AF_MASK`.
const AF_MASK: &str = "unspec unix inet ax25 ipx appletalk netrom bridge atmpvc x25 inet6 rose \
netbeui security key netlink packet ash econet atmsvc rds sna irda pppox wanpipe llc ib mpls can \
tipc bluetooth iucv rxrpc isdn phonet ieee802154 caif alg nfc vsock kcm qipcrtr smc xdp mctp";

/// The resource limits, `AA_SFS_RLIMIT_MASK`.
const RLIMIT_MASK: &str = "cpu fsize data stack core rss nproc nofile memlock as locks \
sigpending msgqueue nice rtprio rttime";

/// The signals, `AA_SFS_SIG_MASK`.
const SIG_MASK: &str = "hup int quit ill trap abrt bus fpe kill usr1 segv usr2 pipe alrm term \
stkflt chld cont stop stp ttin ttou urg xcpu xfsz vtalrm prof winch io pwr sys emt lost";

/// The columns of the permission table of a policy, `PERMS32STR`.
const PERMS32: &str =
    "allow deny subtree cond kill complain prompt audit quiet hide xindex tag label";

/// The feature files, each with its path below `features`.
pub const FILES: &[(&str, Value)] = &[
    ("capability", Value::U64(0xff_ffff)),
    ("caps/extended", Value::Bool(true)),
    ("caps/mask", Value::Str(CAPS_MASK)),
    ("dbus/mask", Value::Str("acquire send receive")),
    ("domain/attach_conditions/xattr", Value::Bool(true)),
    ("domain/change_hat", Value::Bool(true)),
    ("domain/change_hatv", Value::Bool(true)),
    ("domain/change_onexec", Value::Bool(true)),
    ("domain/change_profile", Value::Bool(true)),
    ("domain/computed_longest_left", Value::Bool(true)),
    ("domain/disconnected.path", Value::Bool(true)),
    ("domain/fix_binfmt_elf_mmap", Value::Bool(true)),
    ("domain/kill.signal", Value::Bool(true)),
    ("domain/post_nnp_subset", Value::Bool(true)),
    ("domain/stack", Value::Bool(true)),
    ("domain/unconfined_allowed_children", Value::Bool(true)),
    ("domain/version", Value::Str("1.2")),
    ("file/mask", Value::Str("create read write exec append mmap_exec link lock")),
    ("io_uring/mask", Value::Str("sqpoll override_creds")),
    ("mount/mask", Value::Str("mount umount pivot_root")),
    ("mount/move_mount", Value::Str("detached")),
    ("namespaces/mask", Value::Str("userns_create")),
    ("namespaces/pivot_root", Value::Bool(false)),
    ("namespaces/profile", Value::Bool(true)),
    ("network_v8/af_inet", Value::Bool(true)),
    ("network_v8/af_mask", Value::Str(AF_MASK)),
    ("network_v8/tcp-fast-open", Value::Bool(true)),
    ("policy/outofband", Value::U64(1)),
    ("policy/permstable32", Value::Str(PERMS32)),
    ("policy/permstable32_version", Value::U64(3)),
    ("policy/set_load", Value::Bool(true)),
    ("policy/unconfined_restrictions/change_profile", Value::Bool(true)),
    ("policy/versions/v5", Value::Bool(true)),
    ("policy/versions/v6", Value::Bool(true)),
    ("policy/versions/v7", Value::Bool(true)),
    ("policy/versions/v8", Value::Bool(true)),
    ("policy/versions/v9", Value::Bool(true)),
    ("ptrace/mask", Value::Str("read trace")),
    ("query/label/data", Value::Bool(true)),
    ("query/label/multi_transaction", Value::Bool(true)),
    ("query/label/perms", Value::Str("allow deny audit quiet")),
    ("rlimit/mask", Value::Str(RLIMIT_MASK)),
    ("signal/mask", Value::Str(SIG_MASK)),
];

/// The value of the feature file at `path`.
pub fn get(path: &str) -> Option<Value> {
    FILES.iter().find(|f| f.0 == path).map(|f| f.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_files_have_the_text_of_linux() {
        assert_eq!(get("capability").unwrap().text(), b"0xffffff\n");
        assert_eq!(get("policy/outofband").unwrap().text(), b"0x000001\n");
        assert_eq!(get("policy/permstable32_version").unwrap().text(), b"0x000003\n");
        assert_eq!(get("domain/stack").unwrap().text(), b"yes\n");
        assert_eq!(get("namespaces/pivot_root").unwrap().text(), b"no\n");
        assert_eq!(get("domain/version").unwrap().text(), b"1.2\n");
        assert!(
            CAPS_MASK.starts_with("chown dac_override ")
                && CAPS_MASK.ends_with(" bpf checkpoint_restore")
        );
        assert_eq!(CAPS_MASK.split(' ').count(), 41);
        assert_eq!(AF_MASK.split(' ').count(), 45);
        assert_eq!(get("domain"), None);
    }
}
