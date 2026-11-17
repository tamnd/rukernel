//! The classes and the permissions of the kernel, as security/selinux/include/classmap.h of
//! Linux.
//!
//! The kernel gives each class the value of its place in [`CLASSES`] plus 1, and each
//! permission the bit of its place in the list of its class. A policy can give other values
//! to the same names. The load of a policy makes a map from the values of the kernel to the
//! values of the policy, as `selinux_set_mapping` of Linux.

/// Gives the list of the permissions of a class. The first word can name a common list of
/// Linux: `file_sock`, `file`, `sock`, `ipc`, `cap` or `cap2`.
macro_rules! perms {
    (file_sock $(, $p:literal)*) => {
        &[
            "ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom",
            "relabelto", "append", "map" $(, $p)*
        ]
    };
    (file $(, $p:literal)*) => {
        perms!(
            file_sock, "unlink", "link", "rename", "execute", "quotaon", "mounton",
            "audit_access", "open", "execmod", "watch", "watch_mount", "watch_sb",
            "watch_with_perm", "watch_reads", "watch_mountns" $(, $p)*
        )
    };
    (sock $(, $p:literal)*) => {
        perms!(
            file_sock, "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown",
            "recvfrom", "sendto", "name_bind" $(, $p)*
        )
    };
    (ipc $(, $p:literal)*) => {
        &[
            "create", "destroy", "getattr", "setattr", "read", "write", "associate",
            "unix_read", "unix_write" $(, $p)*
        ]
    };
    (cap) => {
        &[
            "chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid",
            "setuid", "setpcap", "linux_immutable", "net_bind_service", "net_broadcast",
            "net_admin", "net_raw", "ipc_lock", "ipc_owner", "sys_module", "sys_rawio",
            "sys_chroot", "sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice",
            "sys_resource", "sys_time", "sys_tty_config", "mknod", "lease", "audit_write",
            "audit_control", "setfcap"
        ]
    };
    (cap2) => {
        &[
            "mac_override", "mac_admin", "syslog", "wake_alarm", "block_suspend", "audit_read",
            "perfmon", "bpf", "checkpoint_restore"
        ]
    };
    ($($p:literal),*) => {
        &[$($p),*]
    };
}

/// The classes of the kernel and their permissions, `secclass_map` of Linux, in the same
/// order.
#[rustfmt::skip]
pub static CLASSES: [(&str, &[&str]); 97] = [
    ("security", perms!(
        "compute_av", "compute_create", "compute_member", "check_context", "load_policy",
        "compute_relabel", "compute_user", "setenforce", "setbool", "setsecparam",
        "setcheckreqprot", "read_policy", "validate_trans"
    )),
    ("process", perms!(
        "fork", "transition", "sigchld", "sigkill", "sigstop", "signull", "signal", "ptrace",
        "getsched", "setsched", "getsession", "getpgid", "setpgid", "getcap", "setcap", "share",
        "getattr", "setexec", "setfscreate", "noatsecure", "siginh", "setrlimit", "rlimitinh",
        "dyntransition", "setcurrent", "execmem", "execstack", "execheap", "setkeycreate",
        "setsockcreate", "getrlimit"
    )),
    ("process2", perms!("nnp_transition", "nosuid_transition")),
    ("system", perms!(
        "ipc_info", "syslog_read", "syslog_mod", "syslog_console", "module_request", "module_load",
        "firmware_load", "kexec_image_load", "kexec_initramfs_load", "policy_load",
        "x509_certificate_load"
    )),
    ("capability", perms!(cap)),
    ("filesystem", perms!(
        "mount", "remount", "unmount", "getattr", "relabelfrom", "relabelto", "associate",
        "quotamod", "quotaget", "watch"
    )),
    ("file", perms!(file, "execute_no_trans", "entrypoint")),
    ("dir", perms!(file, "add_name", "remove_name", "reparent", "search", "rmdir")),
    ("fd", perms!("use")),
    ("lnk_file", perms!(file)),
    ("chr_file", perms!(file)),
    ("blk_file", perms!(file)),
    ("sock_file", perms!(file)),
    ("fifo_file", perms!(file)),
    ("socket", perms!(sock)),
    ("tcp_socket", perms!(sock, "node_bind", "name_connect")),
    ("udp_socket", perms!(sock, "node_bind")),
    ("rawip_socket", perms!(sock, "node_bind")),
    ("node", perms!("recvfrom", "sendto")),
    ("netif", perms!("ingress", "egress")),
    ("netlink_socket", perms!(sock)),
    ("packet_socket", perms!(sock)),
    ("key_socket", perms!(sock)),
    ("unix_stream_socket", perms!(sock, "connectto")),
    ("unix_dgram_socket", perms!(sock)),
    ("sem", perms!(ipc)),
    ("msg", perms!("send", "receive")),
    ("msgq", perms!(ipc, "enqueue")),
    ("shm", perms!(ipc, "lock")),
    ("ipc", perms!(ipc)),
    ("netlink_route_socket", perms!(sock, "nlmsg_read", "nlmsg_write", "nlmsg")),
    ("netlink_tcpdiag_socket", perms!(sock, "nlmsg_read", "nlmsg_write", "nlmsg")),
    ("netlink_nflog_socket", perms!(sock)),
    ("netlink_xfrm_socket", perms!(sock, "nlmsg_read", "nlmsg_write", "nlmsg")),
    ("netlink_selinux_socket", perms!(sock)),
    ("netlink_iscsi_socket", perms!(sock)),
    ("netlink_audit_socket", perms!(
        sock, "nlmsg_read", "nlmsg_write", "nlmsg_relay", "nlmsg_readpriv", "nlmsg_tty_audit",
        "nlmsg"
    )),
    ("netlink_fib_lookup_socket", perms!(sock)),
    ("netlink_connector_socket", perms!(sock)),
    ("netlink_netfilter_socket", perms!(sock)),
    ("netlink_dnrt_socket", perms!(sock)),
    ("association", perms!("sendto", "recvfrom", "setcontext", "polmatch")),
    ("netlink_kobject_uevent_socket", perms!(sock)),
    ("netlink_generic_socket", perms!(sock)),
    ("netlink_scsitransport_socket", perms!(sock)),
    ("netlink_rdma_socket", perms!(sock)),
    ("netlink_crypto_socket", perms!(sock)),
    ("appletalk_socket", perms!(sock)),
    ("packet", perms!("send", "recv", "relabelto", "forward_in", "forward_out")),
    ("key", perms!("view", "read", "write", "search", "link", "setattr", "create")),
    ("memprotect", perms!("mmap_zero")),
    ("peer", perms!("recv")),
    ("capability2", perms!(cap2)),
    ("kernel_service", perms!("use_as_override", "create_files_as")),
    ("tun_socket", perms!(sock, "attach_queue")),
    ("binder", perms!("impersonate", "call", "set_context_mgr", "transfer")),
    ("cap_userns", perms!(cap)),
    ("cap2_userns", perms!(cap2)),
    ("sctp_socket", perms!(sock, "node_bind", "name_connect", "association")),
    ("icmp_socket", perms!(sock, "node_bind")),
    ("ax25_socket", perms!(sock)),
    ("ipx_socket", perms!(sock)),
    ("netrom_socket", perms!(sock)),
    ("atmpvc_socket", perms!(sock)),
    ("x25_socket", perms!(sock)),
    ("rose_socket", perms!(sock)),
    ("decnet_socket", perms!(sock)),
    ("atmsvc_socket", perms!(sock)),
    ("rds_socket", perms!(sock)),
    ("irda_socket", perms!(sock)),
    ("pppox_socket", perms!(sock)),
    ("llc_socket", perms!(sock)),
    ("can_socket", perms!(sock)),
    ("tipc_socket", perms!(sock)),
    ("bluetooth_socket", perms!(sock)),
    ("iucv_socket", perms!(sock)),
    ("rxrpc_socket", perms!(sock)),
    ("isdn_socket", perms!(sock)),
    ("phonet_socket", perms!(sock)),
    ("ieee802154_socket", perms!(sock)),
    ("caif_socket", perms!(sock)),
    ("alg_socket", perms!(sock)),
    ("nfc_socket", perms!(sock)),
    ("vsock_socket", perms!(sock)),
    ("kcm_socket", perms!(sock)),
    ("qipcrtr_socket", perms!(sock)),
    ("smc_socket", perms!(sock)),
    ("infiniband_pkey", perms!("access")),
    ("infiniband_endport", perms!("manage_subnet")),
    ("bpf", perms!(
        "map_create", "map_read", "map_write", "prog_load", "prog_run", "map_create_as",
        "prog_load_as"
    )),
    ("xdp_socket", perms!(sock)),
    ("mctp_socket", perms!(sock)),
    ("perf_event", perms!("open", "cpu", "kernel", "tracepoint", "read", "write")),
    ("anon_inode", perms!(file)),
    ("io_uring", perms!("override_creds", "sqpoll", "cmd", "allowed")),
    ("user_namespace", perms!("create")),
    ("memfd_file", perms!(file, "execute_no_trans", "entrypoint")),
];

/// The values of the classes that the kernel checks, `SECCLASS_*` of Linux.
pub mod class {
    /// `security`.
    pub const SECURITY: u16 = 1;
    /// `process`.
    pub const PROCESS: u16 = 2;
    /// `process2`.
    pub const PROCESS2: u16 = 3;
    /// `system`.
    pub const SYSTEM: u16 = 4;
    /// `capability`.
    pub const CAPABILITY: u16 = 5;
    /// `filesystem`.
    pub const FILESYSTEM: u16 = 6;
    /// `file`.
    pub const FILE: u16 = 7;
    /// `dir`.
    pub const DIR: u16 = 8;
    /// `fd`.
    pub const FD: u16 = 9;
    /// `lnk_file`.
    pub const LNK_FILE: u16 = 10;
    /// `chr_file`.
    pub const CHR_FILE: u16 = 11;
    /// `blk_file`.
    pub const BLK_FILE: u16 = 12;
    /// `sock_file`.
    pub const SOCK_FILE: u16 = 13;
    /// `fifo_file`.
    pub const FIFO_FILE: u16 = 14;
    /// `key`.
    pub const KEY: u16 = 50;
}

/// The permissions of the class `process`, `PROCESS__*` of Linux.
pub mod process {
    /// `transition`.
    pub const TRANSITION: u32 = 1 << 1;
    /// `ptrace`.
    pub const PTRACE: u32 = 1 << 7;
    /// `getattr`.
    pub const GETATTR: u32 = 1 << 16;
    /// `setexec`.
    pub const SETEXEC: u32 = 1 << 17;
    /// `setfscreate`.
    pub const SETFSCREATE: u32 = 1 << 18;
    /// `noatsecure`.
    pub const NOATSECURE: u32 = 1 << 19;
    /// `dyntransition`.
    pub const DYNTRANSITION: u32 = 1 << 23;
    /// `setcurrent`.
    pub const SETCURRENT: u32 = 1 << 24;
    /// `setkeycreate`.
    pub const SETKEYCREATE: u32 = 1 << 28;
    /// `setsockcreate`.
    pub const SETSOCKCREATE: u32 = 1 << 29;
}

/// The permissions of the class `process2`, `PROCESS2__*` of Linux.
pub mod process2 {
    /// `nnp_transition`.
    pub const NNP_TRANSITION: u32 = 1 << 0;
    /// `nosuid_transition`.
    pub const NOSUID_TRANSITION: u32 = 1 << 1;
}

/// The permissions of the class `file`, `FILE__*` of Linux.
pub mod file {
    /// `execute_no_trans`.
    pub const EXECUTE_NO_TRANS: u32 = 1 << 26;
    /// `entrypoint`.
    pub const ENTRYPOINT: u32 = 1 << 27;
}

/// The permissions of the class `key`, `KEY__*` of Linux.
pub mod key {
    /// `create`.
    pub const CREATE: u32 = 1 << 6;
}

/// The permissions of the class `security`, `SECURITY__*` of Linux.
pub mod security {
    /// `compute_av`.
    pub const COMPUTE_AV: u32 = 1 << 0;
    /// `compute_create`.
    pub const COMPUTE_CREATE: u32 = 1 << 1;
    /// `compute_member`.
    pub const COMPUTE_MEMBER: u32 = 1 << 2;
    /// `check_context`.
    pub const CHECK_CONTEXT: u32 = 1 << 3;
    /// `load_policy`.
    pub const LOAD_POLICY: u32 = 1 << 4;
    /// `compute_relabel`.
    pub const COMPUTE_RELABEL: u32 = 1 << 5;
    /// `compute_user`.
    pub const COMPUTE_USER: u32 = 1 << 6;
    /// `setenforce`.
    pub const SETENFORCE: u32 = 1 << 7;
    /// `setbool`.
    pub const SETBOOL: u32 = 1 << 8;
    /// `setsecparam`.
    pub const SETSECPARAM: u32 = 1 << 9;
    /// `setcheckreqprot`.
    pub const SETCHECKREQPROT: u32 = 1 << 10;
    /// `read_policy`.
    pub const READ_POLICY: u32 = 1 << 11;
    /// `validate_trans`.
    pub const VALIDATE_TRANS: u32 = 1 << 12;
}

/// The name of the class `tclass` of the kernel.
pub fn name(tclass: u16) -> Option<&'static str> {
    CLASSES.get(usize::from(tclass).checked_sub(1)?).map(|c| c.0)
}

/// The value of the class of the kernel with the name `name`.
pub fn value(name: &str) -> Option<u16> {
    CLASSES.iter().position(|c| c.0 == name).map(|i| i as u16 + 1)
}

/// Tells if the class `tclass` of the kernel is a class of sockets, as
/// `security_is_socket_class` of Linux. The name of each class of sockets ends with `socket`,
/// and no other name does.
pub fn is_socket(tclass: u16) -> bool {
    name(tclass).is_some_and(|n| n.ends_with("socket"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_classes_have_the_values_and_the_permissions_of_linux() {
        assert_eq!(name(class::SECURITY), Some("security"));
        assert_eq!(name(class::PROCESS), Some("process"));
        assert_eq!(name(class::FIFO_FILE), Some("fifo_file"));
        assert_eq!(value("memfd_file"), Some(97));
        assert_eq!(name(0), None);
        let file = CLASSES[usize::from(class::FILE) - 1].1;
        assert_eq!(file.len(), 28);
        assert_eq!(file[11], "unlink");
        assert_eq!(file[26], "execute_no_trans");
        let tcp = CLASSES[15].1;
        assert_eq!(tcp.len(), 23);
        assert_eq!(tcp[21], "node_bind");
        assert_eq!(CLASSES[0].1[7], "setenforce");
        assert_eq!(1 << 7, security::SETENFORCE);
        assert_eq!(CLASSES[4].1.len(), 32);
        assert!(is_socket(16) && is_socket(15) && !is_socket(class::FILE));
        assert!(!is_socket(value("association").unwrap()));
        assert!(CLASSES.iter().all(|c| c.1.len() <= 32));
        let bit = |tclass: u16, perm: &str| {
            let perms = CLASSES[usize::from(tclass) - 1].1;
            1u32 << perms.iter().position(|&p| p == perm).unwrap()
        };
        assert_eq!(name(class::PROCESS2), Some("process2"));
        assert_eq!(value("key"), Some(class::KEY));
        for (perm, v) in [
            ("transition", process::TRANSITION),
            ("ptrace", process::PTRACE),
            ("getattr", process::GETATTR),
            ("setexec", process::SETEXEC),
            ("setfscreate", process::SETFSCREATE),
            ("noatsecure", process::NOATSECURE),
            ("dyntransition", process::DYNTRANSITION),
            ("setcurrent", process::SETCURRENT),
            ("setkeycreate", process::SETKEYCREATE),
            ("setsockcreate", process::SETSOCKCREATE),
        ] {
            assert_eq!(bit(class::PROCESS, perm), v, "{perm}");
        }
        assert_eq!(bit(class::PROCESS2, "nosuid_transition"), process2::NOSUID_TRANSITION);
        assert_eq!(bit(class::FILE, "execute_no_trans"), file::EXECUTE_NO_TRANS);
        assert_eq!(bit(class::FILE, "entrypoint"), file::ENTRYPOINT);
        assert_eq!(bit(class::KEY, "create"), key::CREATE);
    }
}
