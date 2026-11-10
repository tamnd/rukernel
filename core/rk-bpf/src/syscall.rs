//! The `bpf(2)` system call, kernel/bpf/syscall.c of Linux.
//!
//! The call has the command, `union bpf_attr` and its size, and with `BPF_COMMON_ATTRS` also
//! `struct bpf_common_attr` and its size. The caller gives the memory and the files of the
//! process through [`Env`].

use crate::UNPRIVILEGED_BPF_DISABLED;
use crate::attr::{
    BPF_ATTR_SIZE, BPF_COMMON_ATTR_SIZE, BpfAttr, bpf_check_uarg_tail_zero, common, get_id, info,
    last_field, link_create, link_update, map_create, map_elem, obj, prog_attach, prog_load,
};
use crate::cgroup::{
    Anchor, AttachArgs, BPF_F_QUERY_EFFECTIVE, CgId, CgroupEnv, cgroup_bpf_attach,
    cgroup_bpf_detach, cgroup_bpf_link_attach, cgroup_bpf_query, query,
};
use crate::file::{BpfMapFile, bpf_map_of};
use crate::idr::{ID_MAX, Idr};
use crate::inode::BpfObj;
use crate::insn::{BPF_COMPLEXITY_LIMIT_INSNS, BPF_MAXINSNS, INSN_SIZE, decode};
use crate::link::{
    BPF_LINK_INFO_SIZE, BpfLink, BpfLinkFile, LINK_IDR, bpf_link_by_id, bpf_link_of,
};
use crate::map::{
    BpfMap, MAP_IDR, MapAttr, MapEnv, bpf_map_publish_id, bpf_map_type_known, bpf_obj_name_cpy,
    map_alloc, map_alloc_check,
};
use crate::prog::prog_flags::*;
use crate::prog::prog_type::*;
use crate::prog::{
    BpfProg, BpfProgFile, PROG_IDR, bpf_prog_alloc_id, bpf_prog_calc_tag, bpf_prog_of,
    bpf_prog_publish_id,
};
use crate::uapi::attach_flags::*;
use crate::uapi::attach_type::*;
use crate::uapi::cmd::*;
use crate::uapi::elem::{BPF_F_CPU, BPF_F_LOCK};
use crate::uapi::flags::{
    BPF_F_NUMA_NODE, BPF_F_PATH_FD, BPF_F_RDONLY, BPF_F_TOKEN_FD, BPF_F_WRONLY, BPF_F_ZERO_SEED,
};
use crate::uapi::map_type::*;
use crate::uapi::{BPF_TAG_SIZE, CAP_BPF};
use crate::verifier::{BPF_LOG_FIXED, BPF_LOG_MASK, BpfVerifierLog, VerifierOpts, bpf_check};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use rk_abi::Errno;
use rk_abi::native::at::AT_FDCWD;
use rk_abi::native::open::{O_RDONLY, O_RDWR, O_WRONLY};
use rk_vfs::cred::may;
use rk_vfs::file::File;

/// The result of the call.
pub type Result<T> = core::result::Result<T, Errno>;

/// `CAP_SYS_ADMIN`.
const CAP_SYS_ADMIN: u32 = 21;

/// `CAP_NET_ADMIN`.
const CAP_NET_ADMIN: u32 = 12;

/// `CAP_PERFMON`.
const CAP_PERFMON: u32 = 38;

/// `BPF_MAP_TYPE_STRUCT_OPS`, `BPF_MAP_TYPE_BLOOM_FILTER`, `BPF_MAP_TYPE_ARENA` and
/// `BPF_MAP_TYPE_RHASH`, which the checks of `map_create_alloc` name.
const BPF_MAP_TYPE_STRUCT_OPS: u32 = 26;
const BPF_MAP_TYPE_BLOOM_FILTER: u32 = 30;
const BPF_MAP_TYPE_ARENA: u32 = 33;
const BPF_MAP_TYPE_RHASH: u32 = 34;

/// `SHA256_DIGEST_SIZE`, the size of `excl_prog_hash`.
const SHA256_DIGEST_SIZE: u32 = 32;

/// What the system call needs of the process and the machine.
pub trait Env {
    /// Copies the user memory at `addr` to `buf`. A bad address gives `EFAULT`.
    fn copy_from_user(&self, addr: u64, buf: &mut [u8]) -> Result<()>;
    /// Copies `buf` to the user memory at `addr`. A bad address gives `EFAULT`.
    fn copy_to_user(&self, addr: u64, buf: &[u8]) -> Result<()>;
    /// Tells if the caller has the capability `cap`.
    fn capable(&self, cap: u32) -> bool;
    /// The number of possible CPUs and the CPU of the caller.
    fn map_env(&self) -> MapEnv;
    /// The bytes of memory that a new map can take.
    fn avail_mem(&self) -> u64;
    /// Gives the file a descriptor with `FD_CLOEXEC`.
    fn fd_install(&self, file: Arc<File>) -> Result<i32>;
    /// The file of the descriptor `fd`. A bad descriptor gives `EBADF`.
    fn fdget(&self, fd: i32) -> Result<Arc<File>>;
    /// Makes the file of the user path `pathname` in the directory `path_fd` that pins `obj`, as
    /// `bpf_obj_do_pin` of Linux. The file has the mode 0600 after the umask. A directory that is
    /// not on bpffs gives `EPERM`.
    fn obj_pin(&self, path_fd: i32, pathname: u64, obj: BpfObj) -> Result<()>;
    /// The object of the file of the user path `pathname` in the directory `path_fd`, as
    /// `bpf_obj_do_get` of Linux. The walk follows symbolic links, and the caller must have the
    /// access `mask` to the file. A file that is not a pinned object gives `EACCES`.
    fn obj_get(&self, path_fd: i32, pathname: u64, mask: u32) -> Result<BpfObj>;
    /// The nanoseconds after the boot, `ktime_get_boottime_ns` of Linux.
    fn boot_ns(&self) -> u64;
    /// The real user ID of the caller.
    fn uid(&self) -> u32;
    /// The cgroup of the cgroup2 directory `fd`, `cgroup_get_from_fd` of Linux. Another file
    /// gives `EBADF`.
    fn cgroup_get_from_fd(&self, fd: u32) -> Result<CgId>;
    /// The parent of a cgroup, or `None` for the root.
    fn cgroup_parent(&self, id: CgId) -> Option<CgId>;
    /// The ID of a cgroup that a program sees: the inode number of its directory.
    fn cgroup_id(&self, id: CgId) -> u64;
}

/// The cgroups of an [`Env`], for the cgroup programs.
struct EnvCgroups<'a>(&'a dyn Env);

impl CgroupEnv for EnvCgroups<'_> {
    fn cgroup_parent(&self, id: CgId) -> Option<CgId> {
        self.0.cgroup_parent(id)
    }

    fn cgroup_id(&self, id: CgId) -> u64 {
        self.0.cgroup_id(id)
    }
}

/// `bpf_net_capable` of Linux.
fn bpf_net_capable(env: &dyn Env) -> bool {
    env.capable(CAP_NET_ADMIN) || env.capable(CAP_SYS_ADMIN)
}

/// `bpf_capable` of Linux.
fn bpf_capable(env: &dyn Env) -> bool {
    env.capable(CAP_BPF) || env.capable(CAP_SYS_ADMIN)
}

/// Copies `size` bytes at `uaddr` that the kernel knows, of the `expected` bytes, and checks that
/// the bytes after them are zero.
fn copy_uarg(env: &dyn Env, uaddr: u64, size: u32, expected: usize, out: &mut [u8]) -> Result<()> {
    let size = size as usize;
    let n = bpf_check_uarg_tail_zero(expected, size, |rest| {
        env.copy_from_user(uaddr.wrapping_add(expected as u64), rest)
    })?;
    let n = n.min(out.len());
    env.copy_from_user(uaddr, &mut out[..n])
}

/// The entry of `bpf(2)`, `__sys_bpf` of Linux.
pub fn sys_bpf(
    env: &dyn Env,
    cmd: u32,
    uattr: u64,
    size: u32,
    uattr_common: u64,
    size_common: u32,
) -> Result<i64> {
    let mut attr = BpfAttr::zeroed();
    copy_uarg(env, uattr, size, BPF_ATTR_SIZE, &mut attr.0)?;
    let mut cmd = cmd;
    // `struct bpf_common_attr` has the log of the verifier. The map commands of rukernel do not
    // write a log, so for them the attributes are only checked.
    let mut common = BpfAttr::zeroed();
    let mut size_common = size_common;
    if cmd & BPF_COMMON_ATTRS != 0 {
        copy_uarg(env, uattr_common, size_common, BPF_COMMON_ATTR_SIZE, &mut common.0[..24])?;
        cmd &= !BPF_COMMON_ATTRS;
    } else {
        size_common = 0;
    }
    match cmd {
        BPF_PROG_LOAD => {
            let true_size_at = if size as usize >= prog_load::LOG_TRUE_SIZE + 4 {
                Some(uattr + prog_load::LOG_TRUE_SIZE as u64)
            } else {
                None
            };
            let log = bpf_log_attr_init(&attr, true_size_at, &common, uattr_common, size_common)?;
            bpf_prog_load(env, &attr, &log)
        }
        BPF_MAP_CREATE => map_create(env, &attr),
        BPF_MAP_LOOKUP_ELEM => map_lookup_elem(env, &attr),
        BPF_MAP_UPDATE_ELEM => map_update_elem(env, &attr),
        BPF_MAP_DELETE_ELEM => map_delete_elem(env, &attr),
        BPF_MAP_GET_NEXT_KEY => map_get_next_key(env, &attr),
        BPF_MAP_FREEZE => map_freeze(env, &attr),
        BPF_OBJ_PIN => bpf_obj_pin(env, &attr),
        BPF_OBJ_GET => bpf_obj_get(env, &attr),
        BPF_PROG_GET_NEXT_ID => bpf_obj_get_next_id(env, &attr, uattr, &PROG_IDR),
        BPF_MAP_GET_NEXT_ID => bpf_obj_get_next_id(env, &attr, uattr, &MAP_IDR),
        BPF_LINK_GET_NEXT_ID => bpf_obj_get_next_id(env, &attr, uattr, &LINK_IDR),
        BPF_PROG_GET_FD_BY_ID => bpf_prog_get_fd_by_id(env, &attr),
        BPF_MAP_GET_FD_BY_ID => bpf_map_get_fd_by_id(env, &attr),
        BPF_LINK_GET_FD_BY_ID => bpf_link_get_fd_by_id(env, &attr),
        BPF_OBJ_GET_INFO_BY_FD => bpf_obj_get_info_by_fd(env, &attr, uattr),
        BPF_PROG_ATTACH => bpf_prog_attach(env, &attr),
        BPF_PROG_DETACH => bpf_prog_detach(env, &attr),
        BPF_PROG_QUERY => bpf_prog_query(env, &attr, uattr, size),
        BPF_LINK_CREATE => link_create_cmd(env, &attr),
        BPF_LINK_UPDATE => link_update_cmd(env, &attr),
        BPF_LINK_DETACH => link_detach(env, &attr),
        _ => Err(Errno::EINVAL),
    }
}

/// Where the verifier writes its log, `struct bpf_log_attr` of Linux.
#[derive(Debug, Default)]
struct BpfLogAttr {
    /// The buffer of the program, or 0.
    ubuf: u64,
    /// The size of the buffer.
    size: u32,
    /// The log level.
    level: u32,
    /// The address of `log_true_size`, if the program gave it.
    true_size_at: Option<u64>,
}

/// `bpf_verifier_log_attr_valid` of Linux.
fn bpf_verifier_log_attr_valid(level: u32, ubuf: u64, size: u32) -> bool {
    // The buffer and its size are both set or both not set.
    if (ubuf == 0) != (size == 0) {
        return false;
    }
    // A buffer needs a log level.
    if ubuf != 0 && level == 0 {
        return false;
    }
    if level & !BPF_LOG_MASK != 0 {
        return false;
    }
    size <= u32::MAX >> 2
}

/// Finds the log of the verifier in `union bpf_attr` or in `struct bpf_common_attr`, as
/// `bpf_log_attr_init` of Linux. When both have a log, they must be the same.
fn bpf_log_attr_init(
    attr: &BpfAttr,
    true_size_at: Option<u64>,
    common_attr: &BpfAttr,
    uattr_common: u64,
    size_common: u32,
) -> Result<BpfLogAttr> {
    let ubuf = attr.u64(prog_load::LOG_BUF);
    let size = attr.u32(prog_load::LOG_SIZE);
    let level = attr.u32(prog_load::LOG_LEVEL);
    let ubuf_common = common_attr.u64(common::LOG_BUF);
    let size_c = common_attr.u32(common::LOG_SIZE);
    let level_c = common_attr.u32(common::LOG_LEVEL);
    if !bpf_verifier_log_attr_valid(level_c, ubuf_common, size_c)
        || !bpf_verifier_log_attr_valid(level, ubuf, size)
    {
        return Err(Errno::EINVAL);
    }
    if ubuf != 0 && ubuf_common != 0 && (ubuf != ubuf_common || size != size_c || level != level_c)
    {
        return Err(Errno::EINVAL);
    }
    if ubuf == 0 && ubuf_common != 0 {
        let at = (size_common as usize >= common::LOG_TRUE_SIZE + 4)
            .then(|| uattr_common + common::LOG_TRUE_SIZE as u64);
        return Ok(BpfLogAttr {
            ubuf: ubuf_common,
            size: size_c,
            level: level_c,
            true_size_at: at,
        });
    }
    Ok(BpfLogAttr { ubuf, size, level, true_size_at })
}

/// Copies the log to the buffer of the program and writes `log_true_size`, as
/// `bpf_log_attr_finalize` and `bpf_vlog_finalize` of Linux. A log that does not fit gives
/// `ENOSPC`. Without `BPF_LOG_FIXED` the buffer has the end of the log.
fn bpf_log_attr_finalize(env: &dyn Env, attr: &BpfLogAttr, log: &BpfVerifierLog) -> Result<()> {
    let text = log.text.as_bytes();
    let true_size = if log.level == 0 || text.is_empty() { 0 } else { text.len() as u32 + 1 };
    let mut err = Ok(());
    if log.level != 0 && attr.ubuf != 0 {
        let cap = attr.size as usize - 1;
        let part = if text.len() <= cap {
            text
        } else if log.level & BPF_LOG_FIXED != 0 {
            &text[..cap]
        } else {
            &text[text.len() - cap..]
        };
        let mut out = Vec::new();
        out.try_reserve_exact(part.len() + 1).map_err(|_| Errno::ENOMEM)?;
        out.extend_from_slice(part);
        out.push(0);
        if env.copy_to_user(attr.ubuf, &out).is_err() {
            err = Err(Errno::EFAULT);
        } else if true_size > attr.size {
            err = Err(Errno::ENOSPC);
        }
    }
    if let Some(at) = attr.true_size_at {
        env.copy_to_user(at, &true_size.to_ne_bytes()).map_err(|_| Errno::EFAULT)?;
    }
    err
}

/// Copies a string of at most `max` bytes from the program, as `strncpy_from_user` of Linux.
/// The copy stops at the first zero byte, so a short string at the end of the memory works.
fn strncpy_from_user(env: &dyn Env, addr: u64, max: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = addr;
    while out.len() < max {
        // Do not read past the page of `at`.
        let in_page = 4096 - (at % 4096) as usize;
        let mut chunk = alloc::vec![0u8; in_page.min(max - out.len())];
        env.copy_from_user(at, &mut chunk)?;
        if let Some(n) = chunk.iter().position(|&b| b == 0) {
            out.extend_from_slice(&chunk[..n]);
            return Ok(out);
        }
        out.extend_from_slice(&chunk);
        at += chunk.len() as u64;
    }
    Ok(out)
}

/// `license_is_gpl_compatible` of Linux.
fn license_is_gpl_compatible(license: &[u8]) -> bool {
    matches!(
        license,
        b"GPL"
            | b"GPL v2"
            | b"GPL and additional rights"
            | b"Dual BSD/GPL"
            | b"Dual MIT/GPL"
            | b"Dual MPL/GPL"
    )
}

/// `BPF_PROG_LOAD`: `bpf_prog_load` of Linux.
fn bpf_prog_load(env: &dyn Env, attr: &BpfAttr, log_attr: &BpfLogAttr) -> Result<i64> {
    use prog_load::*;
    if attr.check_attr(last_field::BPF_PROG_LOAD) {
        return Err(Errno::EINVAL);
    }
    let prog_flags = attr.u32(PROG_FLAGS);
    let allowed = BPF_F_STRICT_ALIGNMENT
        | BPF_F_ANY_ALIGNMENT
        | BPF_F_TEST_STATE_FREQ
        | BPF_F_SLEEPABLE
        | BPF_F_TEST_RND_HI32
        | BPF_F_XDP_HAS_FRAGS
        | BPF_F_XDP_DEV_BOUND_ONLY
        | BPF_F_TEST_REG_INVARIANTS
        | BPF_F_TOKEN_FD;
    if prog_flags & !allowed != 0 {
        return Err(Errno::EINVAL);
    }
    if prog_flags & BPF_F_TOKEN_FD != 0 {
        return Err(no_object_fd(env, attr.u32(PROG_TOKEN_FD)));
    }
    let prog_type = attr.u32(PROG_TYPE);
    let bpf_cap = bpf_capable(env);
    if UNPRIVILEGED_BPF_DISABLED.load(Ordering::Relaxed) != 0 && !bpf_cap {
        return Err(Errno::EPERM);
    }
    let insn_cnt = attr.u32(INSN_CNT);
    let limit = if bpf_cap { BPF_COMPLEXITY_LIMIT_INSNS } else { BPF_MAXINSNS };
    if insn_cnt == 0 || insn_cnt > limit {
        return Err(Errno::E2BIG);
    }
    if prog_type != BPF_PROG_TYPE_SOCKET_FILTER && prog_type != BPF_PROG_TYPE_CGROUP_SKB && !bpf_cap
    {
        return Err(Errno::EPERM);
    }
    if is_net_admin_prog_type(prog_type) && !env.capable(CAP_NET_ADMIN) {
        return Err(Errno::EPERM);
    }
    // rukernel has no BTF, so a program cannot name a function to attach to.
    if attr.u32(ATTACH_PROG_FD) != 0 || attr.u32(ATTACH_BTF_ID) != 0 {
        return Err(Errno::EINVAL);
    }
    // `bpf_prog_load_fixup_attach_type`.
    let mut expected_attach_type = attr.u32(EXPECTED_ATTACH_TYPE);
    if prog_type == BPF_PROG_TYPE_CGROUP_SOCK && expected_attach_type == 0 {
        expected_attach_type = BPF_CGROUP_INET_SOCK_CREATE;
    }
    bpf_prog_load_check_attach(prog_type, expected_attach_type)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(insn_cnt as usize * INSN_SIZE).map_err(|_| Errno::ENOMEM)?;
    bytes.resize(insn_cnt as usize * INSN_SIZE, 0);
    env.copy_from_user(attr.u64(INSNS), &mut bytes).map_err(|_| Errno::EFAULT)?;
    let license = strncpy_from_user(env, attr.u64(LICENSE), 127).map_err(|_| Errno::EFAULT)?;
    let gpl_compatible = license_is_gpl_compatible(&license);
    if !crate::verifier::prog_type_known(prog_type) {
        return Err(Errno::EINVAL);
    }
    // rukernel cannot give a program to a network device.
    if attr.u32(PROG_IFINDEX) != 0 {
        return Err(Errno::EINVAL);
    }
    let name = bpf_obj_name_cpy(&attr.0[PROG_NAME..PROG_NAME + 16])?;

    let mut log = BpfVerifierLog::new(log_attr.level);
    let opts = VerifierOpts {
        prog_type,
        expected_attach_type,
        bpf_capable: bpf_cap,
        allow_ptr_leaks: env.capable(CAP_PERFMON) || env.capable(CAP_SYS_ADMIN),
    };
    let map_by_fd = |fd: i32| -> Result<Arc<BpfMap>> {
        let file = env.fdget(fd)?;
        bpf_map_of(&file).ok_or(Errno::EINVAL)
    };
    // `fd_array`: the descriptors of the maps that a load gives by index.
    let fd_array_addr = attr.u64(FD_ARRAY);
    let fd_at = |idx: u32| -> Result<i32> {
        let mut b = [0u8; 4];
        let addr = fd_array_addr.wrapping_add(u64::from(idx) * 4);
        env.copy_from_user(addr, &mut b).map_err(|_| Errno::EFAULT)?;
        Ok(i32::from_ne_bytes(b))
    };
    let fd_array: Option<&dyn Fn(u32) -> Result<i32>> =
        if fd_array_addr == 0 { None } else { Some(&fd_at) };
    let r = bpf_check(decode(&bytes), &opts, &map_by_fd, fd_array, &mut log);
    // The error of the log comes before the error of the verifier.
    bpf_log_attr_finalize(env, log_attr, &log)?;
    let v = r?;
    // `bpf_check_tail_call` of Linux: a program can only use the program arrays of its type.
    if v.used_maps.iter().filter_map(|m| m.ops.as_prog_array()).any(|a| !a.compatible(prog_type)) {
        return Err(Errno::EINVAL);
    }
    let tag = bpf_prog_calc_tag(&v.insns);
    let prog = BpfProg {
        prog_type,
        expected_attach_type,
        insns: v.insns,
        used_maps: v.used_maps,
        id: bpf_prog_alloc_id(),
        name,
        tag,
        gpl_compatible,
        verified_insns: v.insn_processed,
        run_cnt: core::sync::atomic::AtomicU64::new(0),
        load_time: env.boot_ns(),
        uid: env.uid(),
        enforce_expected_attach_type: v.enforce_expected_attach_type,
    };
    let prog = Arc::new(prog);
    bpf_prog_publish_id(&prog);
    bpf_prog_new_fd(env, prog)
}

/// The program types that need `CAP_NET_ADMIN`, a part of `is_net_admin_prog_type` of Linux.
fn is_net_admin_prog_type(prog_type: u32) -> bool {
    matches!(
        prog_type,
        BPF_PROG_TYPE_CGROUP_DEVICE | BPF_PROG_TYPE_CGROUP_SOCK | BPF_PROG_TYPE_CGROUP_SOCK_ADDR
    )
}

/// Checks the expected attach type of a new program, `bpf_prog_load_check_attach` of Linux.
fn bpf_prog_load_check_attach(prog_type: u32, expected_attach_type: u32) -> Result<()> {
    let ok = match prog_type {
        BPF_PROG_TYPE_CGROUP_SOCK => matches!(
            expected_attach_type,
            BPF_CGROUP_INET_SOCK_CREATE
                | BPF_CGROUP_INET_SOCK_RELEASE
                | BPF_CGROUP_INET4_POST_BIND
                | BPF_CGROUP_INET6_POST_BIND
        ),
        BPF_PROG_TYPE_CGROUP_SKB => {
            matches!(expected_attach_type, BPF_CGROUP_INET_INGRESS | BPF_CGROUP_INET_EGRESS)
        }
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR => {
            attach_type_to_prog_type(expected_attach_type) == BPF_PROG_TYPE_CGROUP_SOCK_ADDR
        }
        _ => true,
    };
    if ok { Ok(()) } else { Err(Errno::EINVAL) }
}

/// The flags of the file of a new map, `bpf_get_file_flag` of Linux.
fn bpf_get_file_flag(flags: u32) -> Result<u32> {
    if flags & BPF_F_RDONLY != 0 && flags & BPF_F_WRONLY != 0 {
        return Err(Errno::EINVAL);
    }
    if flags & BPF_F_RDONLY != 0 {
        return Ok(O_RDONLY);
    }
    if flags & BPF_F_WRONLY != 0 {
        return Ok(O_WRONLY);
    }
    Ok(O_RDWR)
}

/// A descriptor that is not a BTF object or a token gives `EINVAL`, as `btf_get_by_fd` and
/// `bpf_token_get_from_fd` of Linux. rukernel has no such objects yet.
fn no_object_fd(env: &dyn Env, fd: u32) -> Errno {
    match env.fdget(fd as i32) {
        Ok(_) => Errno::EINVAL,
        Err(e) => e,
    }
}

/// `BPF_MAP_CREATE`: `map_create` and `map_create_alloc` of Linux.
fn map_create(env: &dyn Env, attr: &BpfAttr) -> Result<i64> {
    use map_create::*;
    if attr.check_attr(last_field::BPF_MAP_CREATE) {
        return Err(Errno::EINVAL);
    }
    // Clear `BPF_F_TOKEN_FD`, so the checks of the types do not see an unknown flag.
    let raw_flags = attr.u32(MAP_FLAGS);
    let token_flag = raw_flags & BPF_F_TOKEN_FD != 0;
    let a = MapAttr {
        map_type: attr.u32(MAP_TYPE),
        key_size: attr.u32(KEY_SIZE),
        value_size: attr.u32(VALUE_SIZE),
        max_entries: attr.u32(MAX_ENTRIES),
        map_flags: raw_flags & !BPF_F_TOKEN_FD,
        numa_node: attr.u32(NUMA_NODE),
    };
    let btf_key_type_id = attr.u32(BTF_KEY_TYPE_ID);
    let btf_value_type_id = attr.u32(BTF_VALUE_TYPE_ID);
    let btf_vmlinux_value_type_id = attr.u32(BTF_VMLINUX_VALUE_TYPE_ID);
    if btf_vmlinux_value_type_id != 0 {
        if a.map_type != BPF_MAP_TYPE_STRUCT_OPS || btf_key_type_id != 0 || btf_value_type_id != 0 {
            return Err(Errno::EINVAL);
        }
    } else if btf_key_type_id != 0 && btf_value_type_id == 0 {
        return Err(Errno::EINVAL);
    }
    if !matches!(a.map_type, BPF_MAP_TYPE_BLOOM_FILTER | BPF_MAP_TYPE_ARENA | BPF_MAP_TYPE_RHASH)
        && attr.u64(MAP_EXTRA) != 0
    {
        return Err(Errno::EINVAL);
    }
    // rukernel has one memory node, node 0.
    if a.map_flags & BPF_F_NUMA_NODE != 0 && a.numa_node != 0 {
        return Err(Errno::EINVAL);
    }
    if a.map_type > LAST || !bpf_map_type_known(a.map_type) {
        return Err(Errno::EINVAL);
    }
    if matches!(a.map_type, BPF_MAP_TYPE_HASH | BPF_MAP_TYPE_PERCPU_HASH)
        && a.map_flags & BPF_F_ZERO_SEED != 0
        && !env.capable(CAP_SYS_ADMIN)
    {
        // As `htab_map_alloc_check` of Linux: against a local DoS.
        return Err(Errno::EPERM);
    }
    map_alloc_check(&a)?;
    // rukernel cannot give a map to a network device.
    if attr.u32(MAP_IFINDEX) != 0 {
        return Err(Errno::EINVAL);
    }
    if token_flag {
        return Err(no_object_fd(env, attr.u32(MAP_TOKEN_FD)));
    }
    // `unprivileged_bpf_disabled` stops the maps of a process without `CAP_BPF`. The checks of
    // the capabilities of the types come after it.
    if UNPRIVILEGED_BPF_DISABLED.load(Ordering::Relaxed) != 0 && !bpf_capable(env) {
        return Err(Errno::EPERM);
    }
    if a.map_type == BPF_MAP_TYPE_LPM_TRIE && !bpf_capable(env) {
        return Err(Errno::EPERM);
    }
    let menv = env.map_env();
    let ops = map_alloc(&a, menv.nr_cpus, env.avail_mem())?;
    let name = bpf_obj_name_cpy(&attr.0[MAP_NAME..MAP_NAME + 16])?;
    if btf_key_type_id != 0 || btf_value_type_id != 0 || btf_vmlinux_value_type_id != 0 {
        return Err(no_object_fd(env, attr.u32(BTF_FD)));
    }
    let hash = attr.u64(EXCL_PROG_HASH);
    let hash_size = attr.u32(EXCL_PROG_HASH_SIZE);
    if hash != 0 {
        if hash_size != SHA256_DIGEST_SIZE {
            return Err(Errno::EINVAL);
        }
        // rukernel has no programs yet, so the hash only must be readable.
        let mut sha = [0u8; SHA256_DIGEST_SIZE as usize];
        env.copy_from_user(hash, &mut sha)?;
    } else if hash_size != 0 {
        return Err(Errno::EINVAL);
    }
    let f_flags = bpf_get_file_flag(a.map_flags)?;
    let map = Arc::new(BpfMap::new(&a, name, menv.nr_cpus, ops));
    bpf_map_publish_id(&map);
    bpf_map_new_fd(env, map, f_flags)
}

/// The map of a descriptor, `__bpf_map_get` of Linux.
fn bpf_map_get(env: &dyn Env, attr: &BpfAttr) -> Result<(Arc<BpfMap>, Arc<File>)> {
    let file = env.fdget(attr.u32(map_elem::MAP_FD) as i32)?;
    let map = bpf_map_of(&file).ok_or(Errno::EINVAL)?;
    Ok((map, file))
}

/// Tells if the system calls can read and write the map through the file, `map_get_sys_perms`
/// of Linux. A frozen map cannot be written.
fn map_get_sys_perms(map: &BpfMap, file: &File) -> (bool, bool) {
    let flags = file.flags();
    (flags.readable(), flags.writable() && !map.frozen.load(Ordering::Acquire))
}

/// A buffer of `n` zero bytes.
fn kvzalloc(n: usize) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Errno::ENOMEM)?;
    v.resize(n, 0);
    Ok(v)
}

/// Copies the key of a call, `__bpf_copy_key` of Linux.
fn bpf_copy_key(env: &dyn Env, ukey: u64, key_size: u32) -> Result<Vec<u8>> {
    if key_size != 0 {
        let mut key = kvzalloc(key_size as usize)?;
        env.copy_from_user(ukey, &mut key)?;
        return Ok(key);
    }
    if ukey != 0 {
        return Err(Errno::EINVAL);
    }
    Ok(Vec::new())
}

/// The count of the system calls that write a map, `bpf_map_write_active_inc` and
/// `bpf_map_write_active_dec` of Linux.
struct WriteActive<'a>(&'a BpfMap);

impl<'a> WriteActive<'a> {
    fn new(map: &'a BpfMap) -> Self {
        map.writecnt.fetch_add(1, Ordering::AcqRel);
        Self(map)
    }
}

impl Drop for WriteActive<'_> {
    fn drop(&mut self) {
        self.0.writecnt.fetch_sub(1, Ordering::AcqRel);
    }
}

/// `BPF_MAP_LOOKUP_ELEM`: `map_lookup_elem` of Linux.
fn map_lookup_elem(env: &dyn Env, attr: &BpfAttr) -> Result<i64> {
    if attr.check_attr(last_field::BPF_MAP_LOOKUP_ELEM) {
        return Err(Errno::EINVAL);
    }
    let (map, file) = bpf_map_get(env, attr)?;
    if !map_get_sys_perms(&map, &file).0 {
        return Err(Errno::EPERM);
    }
    let flags = attr.u64(map_elem::FLAGS);
    map.check_op_flags(flags, BPF_F_LOCK | BPF_F_CPU)?;
    let key = bpf_copy_key(env, attr.u64(map_elem::KEY), map.key_size)?;
    let mut value = kvzalloc(map.bpf_map_value_size(flags))?;
    map.bpf_map_copy_value(&key, &mut value, flags)?;
    env.copy_to_user(attr.u64(map_elem::VALUE), &value)?;
    Ok(0)
}

/// `BPF_MAP_UPDATE_ELEM`: `map_update_elem` of Linux.
fn map_update_elem(env: &dyn Env, attr: &BpfAttr) -> Result<i64> {
    if attr.check_attr(last_field::BPF_MAP_UPDATE_ELEM) {
        return Err(Errno::EINVAL);
    }
    let (map, file) = bpf_map_get(env, attr)?;
    let _active = WriteActive::new(&map);
    if !map_get_sys_perms(&map, &file).1 {
        return Err(Errno::EPERM);
    }
    let flags = attr.u64(map_elem::FLAGS);
    map.check_op_flags(flags, !0)?;
    let key = bpf_copy_key(env, attr.u64(map_elem::KEY), map.key_size)?;
    let mut value = kvzalloc(map.bpf_map_value_size(flags))?;
    env.copy_from_user(attr.u64(map_elem::VALUE), &mut value)?;
    if let Some(progs) = map.ops.as_prog_array() {
        // `bpf_fd_array_map_update_elem` of Linux: the value is the descriptor of a program.
        progs.fd_update(&key, &value, flags, &|ufd| bpf_prog_get(env, ufd))?;
    } else {
        map.bpf_map_update_value(&key, &value, flags, env.map_env())?;
    }
    Ok(0)
}

/// `BPF_MAP_DELETE_ELEM`: `map_delete_elem` of Linux.
fn map_delete_elem(env: &dyn Env, attr: &BpfAttr) -> Result<i64> {
    if attr.check_attr(last_field::BPF_MAP_DELETE_ELEM) {
        return Err(Errno::EINVAL);
    }
    let (map, file) = bpf_map_get(env, attr)?;
    let _active = WriteActive::new(&map);
    if !map_get_sys_perms(&map, &file).1 {
        return Err(Errno::EPERM);
    }
    let key = bpf_copy_key(env, attr.u64(map_elem::KEY), map.key_size)?;
    map.ops.map_delete_elem(&key)?;
    Ok(0)
}

/// `BPF_MAP_GET_NEXT_KEY`: `map_get_next_key` of Linux. Without a key the call gives the first
/// key.
fn map_get_next_key(env: &dyn Env, attr: &BpfAttr) -> Result<i64> {
    if attr.check_attr(last_field::BPF_MAP_GET_NEXT_KEY) {
        return Err(Errno::EINVAL);
    }
    let (map, file) = bpf_map_get(env, attr)?;
    if !map_get_sys_perms(&map, &file).0 {
        return Err(Errno::EPERM);
    }
    let ukey = attr.u64(map_elem::KEY);
    let key = if ukey != 0 { Some(bpf_copy_key(env, ukey, map.key_size)?) } else { None };
    let mut next_key = kvzalloc(map.key_size as usize)?;
    map.ops.map_get_next_key(key.as_deref(), &mut next_key)?;
    env.copy_to_user(attr.u64(map_elem::VALUE), &next_key)?;
    Ok(0)
}

/// `BPF_MAP_FREEZE`: `map_freeze` of Linux. The system calls cannot change a frozen map, and
/// the programs still can.
fn map_freeze(env: &dyn Env, attr: &BpfAttr) -> Result<i64> {
    if attr.check_attr(last_field::BPF_MAP_FREEZE) {
        return Err(Errno::EINVAL);
    }
    let (map, file) = bpf_map_get(env, attr)?;
    if !map_get_sys_perms(&map, &file).1 {
        return Err(Errno::EPERM);
    }
    let _guard = map.freeze_mutex.lock();
    if map.writecnt.load(Ordering::Acquire) != 0 || map.frozen.load(Ordering::Acquire) {
        return Err(Errno::EBUSY);
    }
    map.frozen.store(true, Ordering::Release);
    Ok(0)
}

/// The kind of access of the flags of a file, `ACC_MODE` of Linux: `MAY_READ` and `MAY_WRITE`.
fn acc_mode(f_flags: u32) -> u32 {
    match f_flags & 3 {
        O_RDONLY => may::READ,
        O_WRONLY => may::WRITE,
        _ => may::READ | may::WRITE,
    }
}

/// The directory of `pathname` for `BPF_OBJ_PIN` and `BPF_OBJ_GET`: `path_fd` with
/// `BPF_F_PATH_FD`, or else the current directory. A `path_fd` without the flag gives `EINVAL`.
fn obj_path_fd(attr: &BpfAttr) -> Result<i32> {
    let path_fd = attr.u32(obj::PATH_FD) as i32;
    if attr.u32(obj::FILE_FLAGS) & BPF_F_PATH_FD != 0 {
        Ok(path_fd)
    } else if path_fd != 0 {
        Err(Errno::EINVAL)
    } else {
        Ok(AT_FDCWD)
    }
}

/// The map, the program or the link of a descriptor, `bpf_fd_probe_obj` of Linux. A descriptor
/// of another file gives `EINVAL`.
fn bpf_fd_probe_obj(env: &dyn Env, fd: u32) -> Result<BpfObj> {
    let file = env.fdget(fd as i32)?;
    if let Some(map) = bpf_map_of(&file) {
        return Ok(BpfObj::Map(map));
    }
    if let Some(link) = bpf_link_of(&file) {
        return Ok(BpfObj::Link(link));
    }
    bpf_prog_of(&file).map(BpfObj::Prog).ok_or(Errno::EINVAL)
}

/// `BPF_OBJ_PIN`, `bpf_obj_pin` and `bpf_obj_pin_user` of Linux.
fn bpf_obj_pin(env: &dyn Env, attr: &BpfAttr) -> Result<i64> {
    if attr.check_attr(last_field::BPF_OBJ) || attr.u32(obj::FILE_FLAGS) & !BPF_F_PATH_FD != 0 {
        return Err(Errno::EINVAL);
    }
    let path_fd = obj_path_fd(attr)?;
    let obj = bpf_fd_probe_obj(env, attr.u32(obj::BPF_FD))?;
    env.obj_pin(path_fd, attr.u64(obj::PATHNAME), obj)?;
    Ok(0)
}

/// `BPF_OBJ_GET`, `bpf_obj_get` and `bpf_obj_get_user` of Linux. A program and a link need a
/// file that can be read and written.
fn bpf_obj_get(env: &dyn Env, attr: &BpfAttr) -> Result<i64> {
    let flags = attr.u32(obj::FILE_FLAGS);
    if attr.check_attr(last_field::BPF_OBJ)
        || attr.u32(obj::BPF_FD) != 0
        || flags & !(BPF_F_RDONLY | BPF_F_WRONLY | BPF_F_PATH_FD) != 0
    {
        return Err(Errno::EINVAL);
    }
    let path_fd = obj_path_fd(attr)?;
    let f_flags = bpf_get_file_flag(flags)?;
    match env.obj_get(path_fd, attr.u64(obj::PATHNAME), acc_mode(f_flags))? {
        BpfObj::Prog(_) | BpfObj::Link(_) if f_flags != O_RDWR => Err(Errno::EINVAL),
        BpfObj::Prog(prog) => bpf_prog_new_fd(env, prog),
        BpfObj::Link(link) => bpf_link_new_fd(env, link),
        BpfObj::Map(map) => bpf_map_new_fd(env, map, f_flags),
    }
}

/// A new descriptor of a program, `bpf_prog_new_fd` of Linux.
fn bpf_prog_new_fd(env: &dyn Env, prog: Arc<BpfProg>) -> Result<i64> {
    let file = File::with_ops(Arc::new(BpfProgFile { prog }), None, O_RDWR);
    env.fd_install(file).map(i64::from)
}

/// A new descriptor of a map with the flags `f_flags`, `bpf_map_new_fd` of Linux.
fn bpf_map_new_fd(env: &dyn Env, map: Arc<BpfMap>, f_flags: u32) -> Result<i64> {
    let file = File::with_ops(Arc::new(BpfMapFile::new(map)), None, f_flags);
    env.fd_install(file).map(i64::from)
}

/// A new descriptor of a link, `bpf_link_new_fd` of Linux.
fn bpf_link_new_fd(env: &dyn Env, link: Arc<BpfLink>) -> Result<i64> {
    let file = File::with_ops(Arc::new(BpfLinkFile { link }), None, O_RDWR);
    env.fd_install(file).map(i64::from)
}

/// `BPF_PROG_GET_NEXT_ID`, `BPF_MAP_GET_NEXT_ID` and `BPF_LINK_GET_NEXT_ID`:
/// `bpf_obj_get_next_id` of Linux. Writes the first ID after `start_id` to `next_id`.
fn bpf_obj_get_next_id<T>(env: &dyn Env, attr: &BpfAttr, uattr: u64, idr: &Idr<T>) -> Result<i64> {
    let start = attr.u32(get_id::START_ID);
    if attr.check_attr(last_field::BPF_OBJ_GET_NEXT_ID) || start >= ID_MAX {
        return Err(Errno::EINVAL);
    }
    if !env.capable(CAP_SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    let next = idr.get_next(start).ok_or(Errno::ENOENT)?;
    env.copy_to_user(uattr + get_id::NEXT_ID as u64, &next.to_ne_bytes())?;
    Ok(0)
}

/// `BPF_PROG_GET_FD_BY_ID`: `bpf_prog_get_fd_by_id` of Linux.
fn bpf_prog_get_fd_by_id(env: &dyn Env, attr: &BpfAttr) -> Result<i64> {
    if attr.check_attr(last_field::BPF_PROG_GET_FD_BY_ID) {
        return Err(Errno::EINVAL);
    }
    if !env.capable(CAP_SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    let id = attr.u32(get_id::START_ID);
    let prog = if id == 0 { None } else { PROG_IDR.find(id) };
    bpf_prog_new_fd(env, prog.ok_or(Errno::ENOENT)?)
}

/// `BPF_MAP_GET_FD_BY_ID`: `bpf_map_get_fd_by_id` of Linux. `open_flags` can have
/// `BPF_F_RDONLY` or `BPF_F_WRONLY`.
fn bpf_map_get_fd_by_id(env: &dyn Env, attr: &BpfAttr) -> Result<i64> {
    let open_flags = attr.u32(get_id::OPEN_FLAGS);
    if attr.check_attr(last_field::BPF_MAP_GET_FD_BY_ID)
        || open_flags & !(BPF_F_RDONLY | BPF_F_WRONLY) != 0
    {
        return Err(Errno::EINVAL);
    }
    if !env.capable(CAP_SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    let f_flags = bpf_get_file_flag(open_flags)?;
    let map = MAP_IDR.find(attr.u32(get_id::START_ID)).ok_or(Errno::ENOENT)?;
    bpf_map_new_fd(env, map, f_flags)
}

/// `BPF_LINK_GET_FD_BY_ID`: `bpf_link_get_fd_by_id` of Linux.
fn bpf_link_get_fd_by_id(env: &dyn Env, attr: &BpfAttr) -> Result<i64> {
    if attr.check_attr(last_field::BPF_LINK_GET_FD_BY_ID) {
        return Err(Errno::EINVAL);
    }
    if !env.capable(CAP_SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    let link = bpf_link_by_id(attr.u32(get_id::START_ID))?;
    bpf_link_new_fd(env, link)
}

/// The size of `struct bpf_prog_info` of Linux 7.3.
const BPF_PROG_INFO_SIZE: usize = 232;

/// The size of `struct bpf_map_info` of Linux 7.3.
const BPF_MAP_INFO_SIZE: usize = 104;

/// The offsets in `struct bpf_prog_info`.
mod prog_info {
    pub(super) const TYPE: usize = 0;
    pub(super) const ID: usize = 4;
    pub(super) const TAG: usize = 8;
    pub(super) const JITED_PROG_LEN: usize = 16;
    pub(super) const XLATED_PROG_LEN: usize = 20;
    pub(super) const XLATED_PROG_INSNS: usize = 32;
    pub(super) const LOAD_TIME: usize = 40;
    pub(super) const CREATED_BY_UID: usize = 48;
    pub(super) const NR_MAP_IDS: usize = 52;
    pub(super) const MAP_IDS: usize = 56;
    pub(super) const NAME: usize = 64;
    pub(super) const GPL_COMPATIBLE: usize = 84;
    pub(super) const NR_JITED_KSYMS: usize = 104;
    pub(super) const NR_JITED_FUNC_LENS: usize = 108;
    pub(super) const JITED_KSYMS: usize = 112;
    pub(super) const JITED_FUNC_LENS: usize = 120;
    pub(super) const FUNC_INFO_REC_SIZE: usize = 132;
    pub(super) const NR_FUNC_INFO: usize = 144;
    pub(super) const NR_LINE_INFO: usize = 148;
    pub(super) const NR_JITED_LINE_INFO: usize = 168;
    pub(super) const LINE_INFO_REC_SIZE: usize = 172;
    pub(super) const JITED_LINE_INFO_REC_SIZE: usize = 176;
    pub(super) const NR_PROG_TAGS: usize = 180;
    pub(super) const PROG_TAGS: usize = 184;
    pub(super) const RUN_TIME_NS: usize = 192;
    pub(super) const RUN_CNT: usize = 200;
    pub(super) const VERIFIED_INSNS: usize = 216;
    /// The end of `attach_btf_id`, the last field.
    pub(super) const END: usize = 228;
}

/// The offsets in `struct bpf_map_info`.
mod map_info {
    pub(super) const TYPE: usize = 0;
    pub(super) const ID: usize = 4;
    pub(super) const KEY_SIZE: usize = 8;
    pub(super) const VALUE_SIZE: usize = 12;
    pub(super) const MAX_ENTRIES: usize = 16;
    pub(super) const MAP_FLAGS: usize = 20;
    pub(super) const NAME: usize = 24;
    pub(super) const MAP_EXTRA: usize = 80;
    pub(super) const HASH: usize = 88;
    pub(super) const HASH_SIZE: usize = 96;
    /// The end of `hash_size`, the last field.
    pub(super) const END: usize = 100;
}

/// The bytes of a `struct bpf_*_info`.
struct InfoBuf<'a> {
    buf: &'a mut [u8],
}

impl InfoBuf<'_> {
    fn u32(&self, off: usize) -> u32 {
        info_u32(self.buf, off)
    }

    fn u64(&self, off: usize) -> u64 {
        u64::from_ne_bytes(self.buf[off..off + 8].try_into().unwrap_or([0; 8]))
    }

    fn set_u32(&mut self, off: usize, v: u32) {
        self.buf[off..off + 4].copy_from_slice(&v.to_ne_bytes());
    }

    fn set_u64(&mut self, off: usize, v: u64) {
        self.buf[off..off + 8].copy_from_slice(&v.to_ne_bytes());
    }
}

/// The `u32` at `off` in `buf`.
fn info_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap_or([0; 4]))
}

/// Copies the `struct bpf_*_info` of `size` bytes from the program, as the start of the
/// `*_get_info_by_fd` functions of Linux. The kernel knows the first `known` bytes, and the
/// bytes after them must be zero. Gives `size` bytes, of which the program gave the first
/// `min(info_len, size)`.
fn info_copy_in(env: &dyn Env, attr: &BpfAttr, known: usize, size: usize) -> Result<Vec<u8>> {
    let uinfo = attr.u64(info::INFO);
    let info_len = attr.u32(info::INFO_LEN) as usize;
    bpf_check_uarg_tail_zero(known, info_len, |rest| {
        env.copy_from_user(uinfo.wrapping_add(known as u64), rest)
    })?;
    let mut buf = kvzalloc(size)?;
    env.copy_from_user(uinfo, &mut buf[..info_len.min(size)])?;
    Ok(buf)
}

/// Copies the first `len` bytes of the info back and writes `info_len`, as the end of the
/// `*_get_info_by_fd` functions of Linux.
fn info_copy_out(env: &dyn Env, attr: &BpfAttr, uattr: u64, buf: &[u8], len: usize) -> Result<i64> {
    env.copy_to_user(attr.u64(info::INFO), &buf[..len]).map_err(|_| Errno::EFAULT)?;
    env.copy_to_user(uattr + info::INFO_LEN as u64, &(len as u32).to_ne_bytes())
        .map_err(|_| Errno::EFAULT)?;
    Ok(0)
}

/// The instructions of a program for `xlated_prog_insns`, as `bpf_insn_prepare_dump` of Linux.
/// A load of a map or of a map value has the map ID in place of the index of the map. The
/// second half of a load of a map value keeps the offset in the value.
fn bpf_insn_prepare_dump(prog: &BpfProg) -> Vec<u8> {
    use crate::insn::{BPF_PSEUDO_MAP_FD, BPF_PSEUDO_MAP_VALUE};
    let mut out = Vec::with_capacity(prog.insns.len() * INSN_SIZE);
    for insn in &prog.insns {
        let mut i = *insn;
        if i.is_ld_imm64()
            && matches!(i.src_reg, BPF_PSEUDO_MAP_FD | BPF_PSEUDO_MAP_VALUE)
            && let Some(map) = prog.used_maps.get(i.imm as usize)
        {
            i.imm = map.id as i32;
        }
        out.extend_from_slice(&i.to_bytes());
    }
    out
}

/// The info of a program, `bpf_prog_get_info_by_fd` of Linux. rukernel has no JIT, so the
/// JIT fields have one function of length 0.
fn bpf_prog_get_info_by_fd(
    env: &dyn Env,
    prog: &BpfProg,
    attr: &BpfAttr,
    uattr: u64,
) -> Result<i64> {
    use prog_info::*;
    let len = (attr.u32(info::INFO_LEN) as usize).min(BPF_PROG_INFO_SIZE);
    let mut raw = info_copy_in(env, attr, END, BPF_PROG_INFO_SIZE)?;
    let mut info = InfoBuf { buf: &mut raw };
    info.set_u32(TYPE, prog.prog_type);
    info.set_u32(ID, prog.id);
    info.set_u64(LOAD_TIME, prog.load_time);
    info.set_u32(CREATED_BY_UID, prog.uid);
    info.set_u32(GPL_COMPATIBLE, u32::from(prog.gpl_compatible));
    info.buf[TAG..TAG + BPF_TAG_SIZE].copy_from_slice(&prog.tag);
    info.buf[NAME..NAME + 16].copy_from_slice(&prog.name);

    let ulen = info.u32(NR_MAP_IDS) as usize;
    info.set_u32(NR_MAP_IDS, prog.used_maps.len() as u32);
    let ulen = ulen.min(prog.used_maps.len());
    if ulen != 0 {
        let ids: Vec<u8> = prog.used_maps[..ulen].iter().flat_map(|m| m.id.to_ne_bytes()).collect();
        env.copy_to_user(info.u64(MAP_IDS), &ids).map_err(|_| Errno::EFAULT)?;
    }

    // `set_info_rec_size`: a size must be the one of the kernel, or 0 with a count of 0.
    let rec = [(NR_FUNC_INFO, FUNC_INFO_REC_SIZE, 8), (NR_LINE_INFO, LINE_INFO_REC_SIZE, 16)];
    for (nr, rec_size, want) in
        rec.into_iter().chain([(NR_JITED_LINE_INFO, JITED_LINE_INFO_REC_SIZE, 8)])
    {
        if (info.u32(nr) != 0 || info.u32(rec_size) != 0) && info.u32(rec_size) != want {
            return Err(Errno::EINVAL);
        }
        info.set_u32(rec_size, want);
    }

    info.set_u64(RUN_TIME_NS, 0);
    info.set_u64(RUN_CNT, prog.run_cnt.load(Ordering::Relaxed));
    info.set_u32(VERIFIED_INSNS, prog.verified_insns);

    if !bpf_capable(env) {
        for f in [
            JITED_PROG_LEN,
            XLATED_PROG_LEN,
            NR_JITED_KSYMS,
            NR_JITED_FUNC_LENS,
            NR_FUNC_INFO,
            NR_LINE_INFO,
            NR_JITED_LINE_INFO,
        ] {
            info.set_u32(f, 0);
        }
        return info_copy_out(env, attr, uattr, info.buf, len);
    }

    let ulen = info.u32(XLATED_PROG_LEN) as usize;
    let insns = bpf_insn_prepare_dump(prog);
    info.set_u32(XLATED_PROG_LEN, insns.len() as u32);
    if ulen != 0 {
        let n = ulen.min(insns.len());
        env.copy_to_user(info.u64(XLATED_PROG_INSNS), &insns[..n]).map_err(|_| Errno::EFAULT)?;
    }
    info.set_u32(JITED_PROG_LEN, 0);
    // One function: the address of the code and its length are 0 without a JIT.
    if info.u32(NR_JITED_KSYMS) != 0 {
        env.copy_to_user(info.u64(JITED_KSYMS), &0u64.to_ne_bytes()).map_err(|_| Errno::EFAULT)?;
    }
    info.set_u32(NR_JITED_KSYMS, 1);
    if info.u32(NR_JITED_FUNC_LENS) != 0 {
        env.copy_to_user(info.u64(JITED_FUNC_LENS), &0u32.to_ne_bytes())
            .map_err(|_| Errno::EFAULT)?;
    }
    info.set_u32(NR_JITED_FUNC_LENS, 1);
    // rukernel has no BTF, so the programs have no function and line information.
    info.set_u32(NR_FUNC_INFO, 0);
    info.set_u32(NR_LINE_INFO, 0);
    info.set_u32(NR_JITED_LINE_INFO, 0);
    if info.u32(NR_PROG_TAGS) != 0 {
        env.copy_to_user(info.u64(PROG_TAGS), &prog.tag).map_err(|_| Errno::EFAULT)?;
    }
    info.set_u32(NR_PROG_TAGS, 1);
    info_copy_out(env, attr, uattr, info.buf, len)
}

/// The info of a map, `bpf_map_get_info_by_fd` of Linux. Only `hash` and `hash_size` come from
/// the program.
fn bpf_map_get_info_by_fd(env: &dyn Env, map: &BpfMap, attr: &BpfAttr, uattr: u64) -> Result<i64> {
    use map_info::*;
    let len = (attr.u32(info::INFO_LEN) as usize).min(BPF_MAP_INFO_SIZE);
    let given = info_copy_in(env, attr, END, BPF_MAP_INFO_SIZE)?;
    let hash = u64::from_ne_bytes(given[HASH..HASH + 8].try_into().unwrap_or([0; 8]));
    let hash_size = info_u32(&given, HASH_SIZE);
    let mut raw = kvzalloc(BPF_MAP_INFO_SIZE)?;
    let mut info = InfoBuf { buf: &mut raw };
    info.set_u32(TYPE, map.map_type);
    info.set_u32(ID, map.id);
    info.set_u32(KEY_SIZE, map.key_size);
    info.set_u32(VALUE_SIZE, map.value_size);
    info.set_u32(MAX_ENTRIES, map.max_entries);
    info.set_u32(MAP_FLAGS, map.map_flags);
    info.set_u64(MAP_EXTRA, map.map_extra);
    info.buf[NAME..NAME + 16].copy_from_slice(&map.name);
    // rukernel has no `map_get_hash` for its map types.
    if hash != 0 || hash_size != 0 {
        return Err(Errno::EINVAL);
    }
    info_copy_out(env, attr, uattr, info.buf, len)
}

/// The info of a link, `bpf_link_get_info_by_fd` of Linux.
fn bpf_link_get_info_by_fd(
    env: &dyn Env,
    link: &BpfLink,
    attr: &BpfAttr,
    uattr: u64,
) -> Result<i64> {
    let len = (attr.u32(info::INFO_LEN) as usize).min(BPF_LINK_INFO_SIZE);
    let raw = info_copy_in(env, attr, BPF_LINK_INFO_SIZE, BPF_LINK_INFO_SIZE)?;
    let mut info = [0u8; BPF_LINK_INFO_SIZE];
    info.copy_from_slice(&raw);
    link.fill_info(&mut info)?;
    info_copy_out(env, attr, uattr, &info, len)
}

/// `BPF_OBJ_GET_INFO_BY_FD`: `bpf_obj_get_info_by_fd` of Linux. A bad descriptor gives
/// `EBADFD`, and a file that is not a BPF object gives `EINVAL`.
fn bpf_obj_get_info_by_fd(env: &dyn Env, attr: &BpfAttr, uattr: u64) -> Result<i64> {
    if attr.check_attr(last_field::BPF_OBJ_GET_INFO_BY_FD) {
        return Err(Errno::EINVAL);
    }
    let file = env.fdget(attr.u32(info::BPF_FD) as i32).map_err(|_| Errno::EBADFD)?;
    if let Some(prog) = bpf_prog_of(&file) {
        return bpf_prog_get_info_by_fd(env, &prog, attr, uattr);
    }
    if let Some(map) = bpf_map_of(&file) {
        return bpf_map_get_info_by_fd(env, &map, attr, uattr);
    }
    if let Some(link) = bpf_link_of(&file) {
        return bpf_link_get_info_by_fd(env, &link, attr, uattr);
    }
    Err(Errno::EINVAL)
}

/// The program of a descriptor, `bpf_prog_get` of Linux.
fn bpf_prog_get(env: &dyn Env, fd: u32) -> Result<Arc<BpfProg>> {
    bpf_prog_of(&*env.fdget(fd as i32)?).ok_or(Errno::EINVAL)
}

/// The link of a descriptor, `bpf_link_get_from_fd` of Linux.
fn bpf_link_get_from_fd(env: &dyn Env, fd: u32) -> Result<Arc<BpfLink>> {
    bpf_link_of(&*env.fdget(fd as i32)?).ok_or(Errno::EINVAL)
}

/// The program type of an attach type, `attach_type_to_prog_type` of Linux. An attach type of
/// a program type that rukernel does not have gives `BPF_PROG_TYPE_UNSPEC`.
pub fn attach_type_to_prog_type(attach_type: u32) -> u32 {
    match attach_type {
        BPF_CGROUP_INET_INGRESS | BPF_CGROUP_INET_EGRESS => BPF_PROG_TYPE_CGROUP_SKB,
        BPF_CGROUP_INET_SOCK_CREATE
        | BPF_CGROUP_INET_SOCK_RELEASE
        | BPF_CGROUP_INET4_POST_BIND
        | BPF_CGROUP_INET6_POST_BIND => BPF_PROG_TYPE_CGROUP_SOCK,
        BPF_CGROUP_INET4_BIND
        | BPF_CGROUP_INET6_BIND
        | BPF_CGROUP_INET4_CONNECT
        | BPF_CGROUP_INET6_CONNECT
        | BPF_CGROUP_UNIX_CONNECT
        | BPF_CGROUP_INET4_GETPEERNAME
        | BPF_CGROUP_INET6_GETPEERNAME
        | BPF_CGROUP_UNIX_GETPEERNAME
        | BPF_CGROUP_INET4_GETSOCKNAME
        | BPF_CGROUP_INET6_GETSOCKNAME
        | BPF_CGROUP_UNIX_GETSOCKNAME
        | BPF_CGROUP_UDP4_SENDMSG
        | BPF_CGROUP_UDP6_SENDMSG
        | BPF_CGROUP_UNIX_SENDMSG
        | BPF_CGROUP_UDP4_RECVMSG
        | BPF_CGROUP_UDP6_RECVMSG
        | BPF_CGROUP_UNIX_RECVMSG => BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        BPF_CGROUP_DEVICE => BPF_PROG_TYPE_CGROUP_DEVICE,
        _ => BPF_PROG_TYPE_UNSPEC,
    }
}

/// Checks that `prog` can attach at `attach_type`, `bpf_prog_attach_check_attach_type` of
/// Linux.
pub fn bpf_prog_attach_check_attach_type(
    env: &dyn Env,
    prog: &BpfProg,
    attach_type: u32,
) -> Result<()> {
    match prog.prog_type {
        BPF_PROG_TYPE_CGROUP_SOCK | BPF_PROG_TYPE_CGROUP_SOCK_ADDR => {
            if attach_type == prog.expected_attach_type { Ok(()) } else { Err(Errno::EINVAL) }
        }
        BPF_PROG_TYPE_CGROUP_SKB => {
            // A process without `CAP_BPF` can load a program of this type, so the attach checks
            // the right.
            if !env.capable(CAP_NET_ADMIN) {
                return Err(Errno::EPERM);
            }
            if prog.enforce_expected_attach_type && prog.expected_attach_type != attach_type {
                return Err(Errno::EINVAL);
            }
            if attach_type_to_prog_type(attach_type) != prog.prog_type {
                return Err(Errno::EINVAL);
            }
            Ok(())
        }
        t => {
            let ptype = attach_type_to_prog_type(attach_type);
            if ptype == BPF_PROG_TYPE_UNSPEC || ptype != t { Err(Errno::EINVAL) } else { Ok(()) }
        }
    }
}

/// `BPF_LINK_CREATE`: `link_create` of Linux.
fn link_create_cmd(env: &dyn Env, attr: &BpfAttr) -> Result<i64> {
    if attr.check_attr(last_field::BPF_LINK_CREATE) {
        return Err(Errno::EINVAL);
    }
    let attach_type = attr.u32(link_create::ATTACH_TYPE);
    // rukernel has no `struct_ops` maps.
    if attach_type == BPF_STRUCT_OPS {
        return Err(Errno::EINVAL);
    }
    let prog = bpf_prog_get(env, attr.u32(link_create::PROG_FD))?;
    bpf_prog_attach_check_attach_type(env, &prog, attach_type)?;
    match prog.prog_type {
        BPF_PROG_TYPE_CGROUP_SKB
        | BPF_PROG_TYPE_CGROUP_SOCK
        | BPF_PROG_TYPE_CGROUP_SOCK_ADDR
        | BPF_PROG_TYPE_CGROUP_DEVICE => {
            let cg = EnvCgroups(env);
            let flags = attr.u32(link_create::FLAGS);
            if flags & !crate::cgroup::BPF_F_LINK_ATTACH_MASK != 0 {
                return Err(Errno::EINVAL);
            }
            let cgrp = env.cgroup_get_from_fd(attr.u32(link_create::TARGET_FD))?;
            let get_anchor = |f, id_or_fd| bpf_get_anchor(env, f, id_or_fd);
            let link = cgroup_bpf_link_attach(
                &cg,
                cgrp,
                prog,
                attach_type,
                flags,
                attr.u32(link_create::RELATIVE_FD),
                &get_anchor,
                attr.u64(link_create::EXPECTED_REVISION),
                crate::link::bpf_link_settle,
            )?;
            bpf_link_new_fd(env, link)
        }
        // rukernel has no other hook for links yet.
        _ => Err(Errno::EINVAL),
    }
}

/// The program type of a descriptor, `bpf_prog_get_type` of Linux. Another type gives
/// `EINVAL`.
fn bpf_prog_get_type(env: &dyn Env, fd: u32, prog_type: u32) -> Result<Arc<BpfProg>> {
    let prog = bpf_prog_get(env, fd)?;
    if prog.prog_type != prog_type {
        return Err(Errno::EINVAL);
    }
    Ok(prog)
}

/// The anchor of `relative_fd` or `relative_id`, `bpf_get_anchor_link` and
/// `bpf_get_anchor_prog` of Linux.
fn bpf_get_anchor(env: &dyn Env, flags: u32, id_or_fd: u32) -> Result<Anchor> {
    let by_id = flags & BPF_F_ID != 0;
    if flags & BPF_F_LINK != 0 {
        if by_id {
            return bpf_link_by_id(id_or_fd).map(Anchor::Link);
        }
        if id_or_fd == 0 {
            return Err(Errno::EINVAL);
        }
        return bpf_link_get_from_fd(env, id_or_fd).map(Anchor::Link);
    }
    if by_id {
        let prog = if id_or_fd == 0 { None } else { PROG_IDR.find(id_or_fd) };
        return prog.map(Anchor::Prog).ok_or(Errno::ENOENT);
    }
    if id_or_fd == 0 {
        return Err(Errno::EINVAL);
    }
    bpf_prog_get(env, id_or_fd).map(Anchor::Prog)
}

/// Tells if a program type is a type of the cgroups that rukernel has, `is_cgroup_prog_type`
/// of Linux.
fn is_cgroup_prog_type(prog_type: u32) -> bool {
    matches!(
        prog_type,
        BPF_PROG_TYPE_CGROUP_SKB
            | BPF_PROG_TYPE_CGROUP_SOCK
            | BPF_PROG_TYPE_CGROUP_SOCK_ADDR
            | BPF_PROG_TYPE_CGROUP_DEVICE
    )
}

/// The attach flags of a program that is not of a cgroup, `BPF_F_ATTACH_MASK_BASE` of Linux.
const BPF_F_ATTACH_MASK_BASE: u32 =
    BPF_F_ALLOW_OVERRIDE | BPF_F_ALLOW_MULTI | BPF_F_REPLACE | BPF_F_PREORDER;

/// The attach flags of a list of programs, `BPF_F_ATTACH_MASK_MPROG` of Linux.
const BPF_F_ATTACH_MASK_MPROG: u32 =
    BPF_F_REPLACE | BPF_F_BEFORE | BPF_F_AFTER | BPF_F_ID | BPF_F_LINK;

/// `BPF_PROG_ATTACH`: `bpf_prog_attach` and `cgroup_bpf_prog_attach` of Linux.
fn bpf_prog_attach(env: &dyn Env, attr: &BpfAttr) -> Result<i64> {
    use prog_attach::*;
    if attr.check_attr(last_field::BPF_PROG_ATTACH) {
        return Err(Errno::EINVAL);
    }
    let attach_type = attr.u32(ATTACH_TYPE);
    let flags = attr.u32(ATTACH_FLAGS);
    let ptype = attach_type_to_prog_type(attach_type);
    if ptype == BPF_PROG_TYPE_UNSPEC {
        return Err(Errno::EINVAL);
    }
    if is_cgroup_prog_type(ptype) {
        if flags & !(BPF_F_ATTACH_MASK_BASE | BPF_F_ATTACH_MASK_MPROG) != 0 {
            return Err(Errno::EINVAL);
        }
    } else if flags & !BPF_F_ATTACH_MASK_BASE != 0
        || attr.u32(RELATIVE_FD) != 0
        || attr.u64(EXPECTED_REVISION) != 0
    {
        return Err(Errno::EINVAL);
    }
    let prog = bpf_prog_get_type(env, attr.u32(ATTACH_BPF_FD), ptype)?;
    if bpf_prog_attach_check_attach_type(env, &prog, attach_type).is_err() {
        return Err(Errno::EINVAL);
    }
    let cgrp = env.cgroup_get_from_fd(attr.u32(TARGET_FD))?;
    let replace_prog = if flags & BPF_F_ALLOW_MULTI != 0 && flags & BPF_F_REPLACE != 0 {
        Some(bpf_prog_get_type(env, attr.u32(REPLACE_BPF_FD), ptype)?)
    } else {
        None
    };
    let get_anchor = |f, id_or_fd| bpf_get_anchor(env, f, id_or_fd);
    cgroup_bpf_attach(
        &EnvCgroups(env),
        AttachArgs {
            cgrp,
            prog: Some(prog),
            replace_prog,
            link: None,
            attach_type,
            flags,
            relative: attr.u32(RELATIVE_FD),
            get_anchor: &get_anchor,
            revision: attr.u64(EXPECTED_REVISION),
        },
    )?;
    Ok(0)
}

/// `BPF_PROG_DETACH`: `bpf_prog_detach` and `cgroup_bpf_prog_detach` of Linux.
fn bpf_prog_detach(env: &dyn Env, attr: &BpfAttr) -> Result<i64> {
    use prog_attach::*;
    if attr.check_attr(last_field::BPF_PROG_DETACH) {
        return Err(Errno::EINVAL);
    }
    let attach_type = attr.u32(ATTACH_TYPE);
    let ptype = attach_type_to_prog_type(attach_type);
    if !is_cgroup_prog_type(ptype) {
        return Err(Errno::EINVAL);
    }
    if attr.u32(ATTACH_FLAGS) != 0 || attr.u32(RELATIVE_FD) != 0 {
        return Err(Errno::EINVAL);
    }
    let cgrp = env.cgroup_get_from_fd(attr.u32(TARGET_FD))?;
    // A bad descriptor detaches the only program, as in Linux.
    let prog = bpf_prog_get_type(env, attr.u32(ATTACH_BPF_FD), ptype).ok();
    cgroup_bpf_detach(
        cgrp,
        prog.as_ref(),
        attach_type,
        attr.u64(EXPECTED_REVISION),
        bpf_net_capable(env),
    )?;
    Ok(0)
}

/// `BPF_PROG_QUERY`: `bpf_prog_query` and `__cgroup_bpf_query` of Linux.
fn bpf_prog_query(env: &dyn Env, attr: &BpfAttr, uattr: u64, size: u32) -> Result<i64> {
    use query::*;
    if !bpf_net_capable(env) {
        return Err(Errno::EPERM);
    }
    if attr.check_attr(last_field::BPF_PROG_QUERY) {
        return Err(Errno::EINVAL);
    }
    let query_flags = attr.u32(QUERY_FLAGS);
    if query_flags & !BPF_F_QUERY_EFFECTIVE != 0 {
        return Err(Errno::EINVAL);
    }
    let attach_type = attr.u32(ATTACH_TYPE);
    if crate::cgroup::to_cgroup_bpf_attach_type(attach_type).is_none() {
        // The other cgroup types, and the types of other hooks, which rukernel does not have.
        return Err(Errno::EINVAL);
    }
    let cgrp = env.cgroup_get_from_fd(attr.u32(TARGET_FD))?;
    let effective = query_flags & BPF_F_QUERY_EFFECTIVE != 0;
    let prog_attach_flags = attr.u64(PROG_ATTACH_FLAGS);
    if effective && prog_attach_flags != 0 {
        return Err(Errno::EINVAL);
    }
    let q = cgroup_bpf_query(&EnvCgroups(env), cgrp, attach_type, effective)?;
    let put =
        |off: usize, b: &[u8]| env.copy_to_user(uattr + off as u64, b).map_err(|_| Errno::EFAULT);
    put(ATTACH_FLAGS, &q.attach_flags.to_ne_bytes())?;
    put(PROG_CNT, &q.prog_cnt.to_ne_bytes())?;
    if size as usize >= REVISION + 8 {
        put(REVISION, &q.revision.to_ne_bytes())?;
    }
    let prog_ids = attr.u64(PROG_IDS);
    let mut cnt = q.prog_cnt;
    if attr.u32(PROG_CNT) == 0 || prog_ids == 0 || cnt == 0 {
        return Ok(0);
    }
    let mut ret = Ok(0);
    if attr.u32(PROG_CNT) < cnt {
        cnt = attr.u32(PROG_CNT);
        ret = Err(Errno::ENOSPC);
    }
    let cnt = cnt as usize;
    let mut ids = Vec::with_capacity(cnt * 4);
    for id in &q.prog_ids[..cnt] {
        ids.extend_from_slice(&id.to_ne_bytes());
    }
    env.copy_to_user(prog_ids, &ids).map_err(|_| Errno::EFAULT)?;
    if prog_attach_flags != 0 {
        let mut flags = Vec::with_capacity(cnt * 4);
        for f in &q.prog_attach_flags[..cnt] {
            flags.extend_from_slice(&f.to_ne_bytes());
        }
        env.copy_to_user(prog_attach_flags, &flags).map_err(|_| Errno::EFAULT)?;
    }
    ret
}

/// `BPF_LINK_UPDATE`: `link_update` of Linux. With `BPF_F_REPLACE` the link must have the
/// program of `old_prog_fd`.
fn link_update_cmd(env: &dyn Env, attr: &BpfAttr) -> Result<i64> {
    use link_update::*;
    if attr.check_attr(last_field::BPF_LINK_UPDATE) {
        return Err(Errno::EINVAL);
    }
    let flags = attr.u32(FLAGS);
    if flags & !BPF_F_REPLACE != 0 {
        return Err(Errno::EINVAL);
    }
    let link = bpf_link_get_from_fd(env, attr.u32(LINK_FD))?;
    let new_prog = bpf_prog_get(env, attr.u32(NEW_PROG_FD))?;
    let old_prog = if flags & BPF_F_REPLACE != 0 {
        Some(bpf_prog_get(env, attr.u32(OLD_PROG_FD))?)
    } else if attr.u32(OLD_PROG_FD) != 0 {
        return Err(Errno::EINVAL);
    } else {
        None
    };
    link.ops.update_prog(&link, new_prog, old_prog.as_ref())?;
    Ok(0)
}

/// `BPF_LINK_DETACH`: `link_detach` of Linux.
fn link_detach(env: &dyn Env, attr: &BpfAttr) -> Result<i64> {
    if attr.check_attr(last_field::BPF_LINK_DETACH) {
        return Err(Errno::EINVAL);
    }
    let link = bpf_link_get_from_fd(env, attr.u32(link_update::LINK_FD))?;
    link.ops.detach(&link)?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inode::{Options, bpf_mkobj, bpf_obj_of};
    use crate::uapi::elem::{BPF_ANY, BPF_NOEXIST};
    use crate::uapi::flags::BPF_F_NO_PREALLOC;
    use alloc::collections::BTreeMap;
    use core::cell::{Cell, RefCell};
    use rk_vfs::InodeRef;

    /// A process with a flat memory from address 0x1000 and a table of descriptors.
    struct FakeEnv {
        mem: RefCell<Vec<u8>>,
        files: RefCell<BTreeMap<i32, Arc<File>>>,
        caps: Cell<bool>,
        bpffs: InodeRef,
    }

    const BASE: u64 = 0x1000;

    impl FakeEnv {
        fn new() -> Self {
            Self {
                mem: RefCell::new(alloc::vec![0; 4096]),
                files: RefCell::new(BTreeMap::new()),
                caps: Cell::new(true),
                bpffs: crate::inode::new(Options::default()),
            }
        }

        fn cstr(&self, addr: u64) -> Vec<u8> {
            let r = self.range(addr, 0).unwrap();
            let mem = self.mem.borrow();
            mem[r.start..].iter().take_while(|&&b| b != 0).copied().collect()
        }

        fn range(&self, addr: u64, len: usize) -> Result<core::ops::Range<usize>> {
            let start = addr.checked_sub(BASE).ok_or(Errno::EFAULT)? as usize;
            if start + len > self.mem.borrow().len() {
                return Err(Errno::EFAULT);
            }
            Ok(start..start + len)
        }

        fn put(&self, addr: u64, data: &[u8]) {
            self.copy_to_user(addr, data).unwrap();
        }

        fn get(&self, addr: u64, len: usize) -> Vec<u8> {
            let mut v = alloc::vec![0; len];
            self.copy_from_user(addr, &mut v).unwrap();
            v
        }

        fn call(&self, cmd: u32, attr: &BpfAttr) -> Result<i64> {
            self.put(BASE, &attr.0);
            sys_bpf(self, cmd, BASE, BPF_ATTR_SIZE as u32, 0, 0)
        }
    }

    impl Env for FakeEnv {
        fn copy_from_user(&self, addr: u64, buf: &mut [u8]) -> Result<()> {
            let r = self.range(addr, buf.len())?;
            buf.copy_from_slice(&self.mem.borrow()[r]);
            Ok(())
        }

        fn copy_to_user(&self, addr: u64, buf: &[u8]) -> Result<()> {
            let r = self.range(addr, buf.len())?;
            self.mem.borrow_mut()[r].copy_from_slice(buf);
            Ok(())
        }

        fn capable(&self, _cap: u32) -> bool {
            self.caps.get()
        }

        fn map_env(&self) -> MapEnv {
            MapEnv { nr_cpus: 2, cpu: 0 }
        }

        fn avail_mem(&self) -> u64 {
            1 << 30
        }

        fn fd_install(&self, file: Arc<File>) -> Result<i32> {
            let mut files = self.files.borrow_mut();
            let fd = files.len() as i32 + 3;
            files.insert(fd, file);
            Ok(fd)
        }

        fn fdget(&self, fd: i32) -> Result<Arc<File>> {
            self.files.borrow().get(&fd).cloned().ok_or(Errno::EBADF)
        }

        fn obj_pin(&self, path_fd: i32, pathname: u64, obj: BpfObj) -> Result<()> {
            assert_eq!(path_fd, AT_FDCWD);
            let name = self.cstr(pathname);
            bpf_mkobj(&self.bpffs, &name, 0o600, obj).map(drop)
        }

        fn obj_get(&self, path_fd: i32, pathname: u64, _mask: u32) -> Result<BpfObj> {
            assert_eq!(path_fd, AT_FDCWD);
            bpf_obj_of(&self.bpffs.lookup(&self.cstr(pathname))?)
        }

        fn boot_ns(&self) -> u64 {
            1234
        }

        fn uid(&self) -> u32 {
            1000
        }

        // The descriptors from 5000 are the cgroups 5000 and up, each one the child of the
        // one before.
        fn cgroup_get_from_fd(&self, fd: u32) -> Result<CgId> {
            if fd >= 5000 { Ok(fd) } else { Err(Errno::EBADF) }
        }

        fn cgroup_parent(&self, id: CgId) -> Option<CgId> {
            (id > 5000).then(|| id - 1)
        }

        fn cgroup_id(&self, id: CgId) -> u64 {
            u64::from(id)
        }
    }

    fn create(
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        flags: u32,
    ) -> BpfAttr {
        let mut a = BpfAttr::zeroed();
        a.set_u32(map_create::MAP_TYPE, map_type);
        a.set_u32(map_create::KEY_SIZE, key_size);
        a.set_u32(map_create::VALUE_SIZE, value_size);
        a.set_u32(map_create::MAX_ENTRIES, max_entries);
        a.set_u32(map_create::MAP_FLAGS, flags);
        a
    }

    fn elem(fd: i64, key: u64, value: u64, flags: u64) -> BpfAttr {
        let mut a = BpfAttr::zeroed();
        a.set_u32(map_elem::MAP_FD, fd as u32);
        a.set_u64(map_elem::KEY, key);
        a.set_u64(map_elem::VALUE, value);
        a.set_u64(map_elem::FLAGS, flags);
        a
    }

    const KEY: u64 = BASE + 0x400;
    const VAL: u64 = BASE + 0x800;

    #[test]
    fn a_hash_map_works_as_bpf_map01_tests_it() {
        let env = FakeEnv::new();
        let fd = env.call(BPF_MAP_CREATE, &create(BPF_MAP_TYPE_HASH, 8, 1024, 1, 0)).unwrap();
        env.put(KEY, &7u64.to_ne_bytes());
        assert_eq!(env.call(BPF_MAP_LOOKUP_ELEM, &elem(fd, KEY, VAL, 0)), Err(Errno::ENOENT));
        env.put(VAL, &[b'x'; 1024]);
        env.call(BPF_MAP_UPDATE_ELEM, &elem(fd, KEY, VAL, BPF_ANY)).unwrap();
        env.put(VAL, &[0; 1024]);
        env.call(BPF_MAP_LOOKUP_ELEM, &elem(fd, KEY, VAL, 0)).unwrap();
        assert_eq!(env.get(VAL, 1024), alloc::vec![b'x'; 1024]);
        assert_eq!(
            env.call(BPF_MAP_UPDATE_ELEM, &elem(fd, KEY, VAL, BPF_NOEXIST)),
            Err(Errno::EEXIST)
        );
        // The next key of the only key does not exist; without a key the call gives the first.
        assert_eq!(env.call(BPF_MAP_GET_NEXT_KEY, &elem(fd, KEY, VAL, 0)), Err(Errno::ENOENT));
        env.call(BPF_MAP_GET_NEXT_KEY, &elem(fd, 0, VAL, 0)).unwrap();
        assert_eq!(env.get(VAL, 8), 7u64.to_ne_bytes());
        // A byte after the last field of the command gives EINVAL.
        assert_eq!(env.call(BPF_MAP_DELETE_ELEM, &elem(fd, KEY, VAL, 0)), Err(Errno::EINVAL));
        env.call(BPF_MAP_DELETE_ELEM, &elem(fd, KEY, 0, 0)).unwrap();
        let info = bpf_map_of(&env.fdget(fd as i32).unwrap()).unwrap().show_fdinfo();
        assert!(
            core::str::from_utf8(&info)
                .unwrap()
                .starts_with("map_type:\t1\nkey_size:\t8\nvalue_size:\t1024\n")
        );
    }

    #[test]
    fn an_array_map_has_zero_values() {
        let env = FakeEnv::new();
        let fd = env.call(BPF_MAP_CREATE, &create(BPF_MAP_TYPE_ARRAY, 4, 1024, 1, 0)).unwrap();
        env.put(KEY, &0u32.to_ne_bytes());
        env.put(VAL, &[1; 1024]);
        env.call(BPF_MAP_LOOKUP_ELEM, &elem(fd, KEY, VAL, 0)).unwrap();
        assert_eq!(env.get(VAL, 1024), alloc::vec![0; 1024]);
    }

    #[test]
    fn the_size_and_the_tail_are_checked() {
        let env = FakeEnv::new();
        let a = create(BPF_MAP_TYPE_HASH, 8, 8, 1, 0);
        env.put(BASE, &a.0);
        // A short attribute is enough when the fields after it are zero.
        assert!(sys_bpf(&env, BPF_MAP_CREATE, BASE, 20, 0, 0).is_ok());
        env.put(BASE + 200, &[1]);
        assert_eq!(sys_bpf(&env, BPF_MAP_CREATE, BASE, 256, 0, 0), Err(Errno::E2BIG));
        assert_eq!(sys_bpf(&env, BPF_MAP_CREATE, BASE, 8192, 0, 0), Err(Errno::E2BIG));
        assert_eq!(sys_bpf(&env, 99, BASE, 20, 0, 0), Err(Errno::EINVAL));
        let mut a = create(BPF_MAP_TYPE_HASH, 8, 8, 1, 0);
        a.0[100] = 1;
        assert_eq!(env.call(BPF_MAP_CREATE, &a), Err(Errno::EINVAL));
    }

    #[test]
    fn the_rights_are_checked() {
        let env = FakeEnv::new();
        env.caps.set(false);
        assert_eq!(
            env.call(BPF_MAP_CREATE, &create(BPF_MAP_TYPE_HASH, 8, 8, 1, 0)),
            Err(Errno::EPERM)
        );
        env.caps.set(true);
        let mut a = create(BPF_MAP_TYPE_HASH, 8, 8, 1, 0);
        a.0[map_create::MAP_NAME] = b'-';
        assert_eq!(env.call(BPF_MAP_CREATE, &a), Err(Errno::EINVAL));
        assert_eq!(
            env.call(BPF_MAP_CREATE, &create(BPF_MAP_TYPE_LPM_TRIE, 8, 8, 1, 0)),
            Err(Errno::EINVAL)
        );
        assert!(
            env.call(BPF_MAP_CREATE, &create(BPF_MAP_TYPE_LPM_TRIE, 8, 8, 1, BPF_F_NO_PREALLOC))
                .is_ok()
        );

        let fd =
            env.call(BPF_MAP_CREATE, &create(BPF_MAP_TYPE_ARRAY, 4, 8, 1, BPF_F_RDONLY)).unwrap();
        env.put(KEY, &0u32.to_ne_bytes());
        assert_eq!(env.call(BPF_MAP_UPDATE_ELEM, &elem(fd, KEY, VAL, 0)), Err(Errno::EPERM));
        assert!(env.call(BPF_MAP_LOOKUP_ELEM, &elem(fd, KEY, VAL, 0)).is_ok());

        let fd = env.call(BPF_MAP_CREATE, &create(BPF_MAP_TYPE_ARRAY, 4, 8, 1, 0)).unwrap();
        env.call(BPF_MAP_UPDATE_ELEM, &elem(fd, KEY, VAL, 0)).unwrap();
        env.call(BPF_MAP_FREEZE, &elem(fd, 0, 0, 0)).unwrap();
        assert_eq!(env.call(BPF_MAP_FREEZE, &elem(fd, 0, 0, 0)), Err(Errno::EPERM));
        assert_eq!(env.call(BPF_MAP_UPDATE_ELEM, &elem(fd, KEY, VAL, 0)), Err(Errno::EPERM));
        assert_eq!(env.call(BPF_MAP_LOOKUP_ELEM, &elem(99, KEY, VAL, 0)), Err(Errno::EBADF));
    }

    #[test]
    fn a_percpu_map_copies_all_cpus() {
        let env = FakeEnv::new();
        let fd = env.call(BPF_MAP_CREATE, &create(BPF_MAP_TYPE_PERCPU_ARRAY, 4, 4, 2, 0)).unwrap();
        env.put(KEY, &1u32.to_ne_bytes());
        env.put(VAL, b"aaaa....bbbb....");
        env.call(BPF_MAP_UPDATE_ELEM, &elem(fd, KEY, VAL, 0)).unwrap();
        env.put(VAL, &[0; 16]);
        env.call(BPF_MAP_LOOKUP_ELEM, &elem(fd, KEY, VAL, 0)).unwrap();
        assert_eq!(env.get(VAL, 16), b"aaaa\0\0\0\0bbbb\0\0\0\0");
        env.call(BPF_MAP_LOOKUP_ELEM, &elem(fd, KEY, VAL, BPF_F_CPU | (1 << 32))).unwrap();
        assert_eq!(env.get(VAL, 4), b"bbbb");
        assert_eq!(
            env.call(BPF_MAP_LOOKUP_ELEM, &elem(fd, KEY, VAL, BPF_F_CPU | (2 << 32))),
            Err(Errno::ERANGE)
        );
    }

    /// The instructions of a program: the opcode, the registers, the offset and the immediate.
    fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0] = code;
        b[1] = (src << 4) | dst;
        b[2..4].copy_from_slice(&off.to_ne_bytes());
        b[4..8].copy_from_slice(&imm.to_ne_bytes());
        b
    }

    const INSNS: u64 = BASE + 0xa00;
    const LICENSE: u64 = BASE + 0xbf0;
    const LOG: u64 = BASE + 0xc00;

    fn load(env: &FakeEnv, insns: &[[u8; 8]], log_size: u32) -> Result<i64> {
        env.put(INSNS, &insns.concat());
        env.put(LICENSE, b"GPL\0");
        let mut a = BpfAttr::zeroed();
        a.set_u32(prog_load::PROG_TYPE, BPF_PROG_TYPE_SOCKET_FILTER);
        a.set_u32(prog_load::INSN_CNT, insns.len() as u32);
        a.set_u64(prog_load::INSNS, INSNS);
        a.set_u64(prog_load::LICENSE, LICENSE);
        if log_size != 0 {
            a.set_u32(prog_load::LOG_LEVEL, 1);
            a.set_u32(prog_load::LOG_SIZE, log_size);
            a.set_u64(prog_load::LOG_BUF, LOG);
        }
        env.call(BPF_PROG_LOAD, &a)
    }

    fn log_text(env: &FakeEnv) -> alloc::string::String {
        let b = env.get(LOG, 0x300);
        let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        alloc::string::String::from_utf8_lossy(&b[..n]).into_owned()
    }

    #[test]
    fn prog_load_checks_and_logs() {
        let env = FakeEnv::new();
        let map = env.call(BPF_MAP_CREATE, &create(BPF_MAP_TYPE_ARRAY, 4, 8, 1, 0)).unwrap();
        let good = [
            insn(0x18, 1, 1, 0, map as i32),
            insn(0, 0, 0, 0, 0),
            insn(0xbf, 2, 10, 0, 0),
            insn(0x07, 2, 0, 0, -8),
            insn(0x7a, 2, 0, 0, 0),
            insn(0x85, 0, 0, 0, 1),
            insn(0x15, 0, 0, 2, 0),
            insn(0xb7, 1, 0, 0, 1),
            insn(0xdb, 0, 1, 0, 0),
            insn(0xb7, 0, 0, 0, 0),
            insn(0x95, 0, 0, 0, 0),
        ];
        let fd = load(&env, &good, 0x200).unwrap();
        assert!(log_text(&env).starts_with("processed "));
        let file = env.fdget(fd as i32).unwrap();
        let prog = crate::prog::bpf_prog_of(&file).unwrap();
        assert_eq!(prog.used_maps.len(), 1);

        let mut bad = good;
        bad[6] = insn(0xb7, 3, 0, 0, 0);
        assert_eq!(load(&env, &bad, 0x200), Err(Errno::EACCES));
        assert!(log_text(&env).contains("R0 invalid mem access 'map_value_or_null'"));
        // A small log keeps the end of the text and gives ENOSPC.
        assert_eq!(load(&env, &bad, 8), Err(Errno::ENOSPC));
        assert_eq!(log_text(&env).len(), 7);
        // A log buffer without a level gives EINVAL.
        let mut a = BpfAttr::zeroed();
        a.set_u32(prog_load::LOG_SIZE, 8);
        a.set_u64(prog_load::LOG_BUF, LOG);
        assert_eq!(env.call(BPF_PROG_LOAD, &a), Err(Errno::EINVAL));
        assert_eq!(load(&env, &[], 0), Err(Errno::E2BIG));
        env.caps.set(false);
        assert_eq!(load(&env, &good, 0), Err(Errno::EPERM));
    }

    fn obj(pathname: u64, fd: i64, flags: u32) -> BpfAttr {
        let mut a = BpfAttr::zeroed();
        a.set_u64(obj::PATHNAME, pathname);
        a.set_u32(obj::BPF_FD, fd as u32);
        a.set_u32(obj::FILE_FLAGS, flags);
        a
    }

    #[test]
    fn obj_pin_and_obj_get_give_the_same_map() {
        let env = FakeEnv::new();
        let fd = env.call(BPF_MAP_CREATE, &create(BPF_MAP_TYPE_ARRAY, 4, 8, 1, 0)).unwrap();
        let path = BASE + 1024;
        env.put(path, b"m\0");
        assert_eq!(env.call(BPF_OBJ_PIN, &obj(path, fd, 0)), Ok(0));
        assert_eq!(env.call(BPF_OBJ_PIN, &obj(path, fd, 0)), Err(Errno::EEXIST));
        assert_eq!(env.call(BPF_OBJ_PIN, &obj(path, fd, 1)), Err(Errno::EINVAL));
        assert_eq!(env.call(BPF_OBJ_GET, &obj(path, fd, 0)), Err(Errno::EINVAL));
        let both = BPF_F_RDONLY | BPF_F_WRONLY;
        assert_eq!(env.call(BPF_OBJ_GET, &obj(path, 0, both)), Err(Errno::EINVAL));
        let mut path_fd = obj(path, 0, 0);
        path_fd.set_u32(obj::PATH_FD, 3);
        assert_eq!(env.call(BPF_OBJ_GET, &path_fd), Err(Errno::EINVAL));
        let got = env.call(BPF_OBJ_GET, &obj(path, 0, BPF_F_RDONLY)).unwrap();
        let a = bpf_map_of(&env.fdget(fd as i32).unwrap()).unwrap();
        let b = bpf_map_of(&env.fdget(got as i32).unwrap()).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert!(!env.fdget(got as i32).unwrap().flags().writable());
    }

    fn info_attr(fd: i64, info_len: u32, info: u64) -> BpfAttr {
        let mut a = BpfAttr::zeroed();
        a.set_u32(info::BPF_FD, fd as u32);
        a.set_u32(info::INFO_LEN, info_len);
        a.set_u64(info::INFO, info);
        a
    }

    fn id_attr(id: u32, open_flags: u32) -> BpfAttr {
        let mut a = BpfAttr::zeroed();
        a.set_u32(get_id::START_ID, id);
        a.set_u32(get_id::OPEN_FLAGS, open_flags);
        a
    }

    const INFO: u64 = BASE + 0x600;

    fn get_u32(env: &FakeEnv, addr: u64) -> u32 {
        u32::from_ne_bytes(env.get(addr, 4).try_into().unwrap())
    }

    #[test]
    fn a_map_has_an_id_and_an_info() {
        let env = FakeEnv::new();
        let fd = env.call(BPF_MAP_CREATE, &create(BPF_MAP_TYPE_ARRAY, 4, 8, 3, 0)).unwrap();
        env.put(INFO, &[0; BPF_MAP_INFO_SIZE]);
        let info_len = BPF_MAP_INFO_SIZE as u32 + 8;
        assert_eq!(env.call(BPF_OBJ_GET_INFO_BY_FD, &info_attr(fd, info_len, INFO)), Ok(0));
        assert_eq!(get_u32(&env, BASE + info::INFO_LEN as u64), BPF_MAP_INFO_SIZE as u32);
        let id = get_u32(&env, INFO + map_info::ID as u64);
        assert_ne!(id, 0);
        assert_eq!(get_u32(&env, INFO + map_info::TYPE as u64), BPF_MAP_TYPE_ARRAY);
        assert_eq!(get_u32(&env, INFO + map_info::MAX_ENTRIES as u64), 3);
        // A short info gets only its bytes.
        env.put(INFO, &[0xff; 8]);
        assert_eq!(env.call(BPF_OBJ_GET_INFO_BY_FD, &info_attr(fd, 4, INFO)), Ok(0));
        assert_eq!(env.get(INFO, 8), [2, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
        // A hash size without a hash gives EINVAL, and a bad descriptor gives EBADFD.
        env.put(INFO, &[0; BPF_MAP_INFO_SIZE]);
        env.put(INFO + map_info::HASH_SIZE as u64, &32u32.to_ne_bytes());
        let len = BPF_MAP_INFO_SIZE as u32;
        assert_eq!(env.call(BPF_OBJ_GET_INFO_BY_FD, &info_attr(fd, len, INFO)), Err(Errno::EINVAL));
        assert_eq!(env.call(BPF_OBJ_GET_INFO_BY_FD, &info_attr(99, 8, INFO)), Err(Errno::EBADFD));

        let got = env.call(BPF_MAP_GET_FD_BY_ID, &id_attr(id, BPF_F_RDONLY)).unwrap();
        let a = bpf_map_of(&env.fdget(fd as i32).unwrap()).unwrap();
        let b = bpf_map_of(&env.fdget(got as i32).unwrap()).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert!(!env.fdget(got as i32).unwrap().flags().writable());
        assert_eq!(env.call(BPF_MAP_GET_FD_BY_ID, &id_attr(id, 4)), Err(Errno::EINVAL));
        assert_eq!(env.call(BPF_MAP_GET_NEXT_ID, &id_attr(id - 1, 0)), Ok(0));
        assert_eq!(get_u32(&env, BASE + get_id::NEXT_ID as u64), id);
        assert_eq!(env.call(BPF_MAP_GET_NEXT_ID, &id_attr(ID_MAX, 0)), Err(Errno::EINVAL));
        env.caps.set(false);
        assert_eq!(env.call(BPF_MAP_GET_FD_BY_ID, &id_attr(id, 0)), Err(Errno::EPERM));
        assert_eq!(env.call(BPF_MAP_GET_NEXT_ID, &id_attr(0, 0)), Err(Errno::EPERM));
        env.caps.set(true);
        drop((a, b));
        env.files.borrow_mut().clear();
        assert_eq!(env.call(BPF_MAP_GET_FD_BY_ID, &id_attr(id, 0)), Err(Errno::ENOENT));
    }

    #[test]
    fn a_prog_has_an_id_and_an_info() {
        let env = FakeEnv::new();
        let map = env.call(BPF_MAP_CREATE, &create(BPF_MAP_TYPE_ARRAY, 4, 8, 1, 0)).unwrap();
        let insns = [
            insn(0x18, 1, 1, 0, map as i32),
            insn(0, 0, 0, 0, 0),
            insn(0xb7, 0, 0, 0, 0),
            insn(0x95, 0, 0, 0, 0),
        ];
        let fd = load(&env, &insns, 0).unwrap();
        let map_id = bpf_map_of(&env.fdget(map as i32).unwrap()).unwrap().id;
        let xlated = BASE + 0x100;
        let map_ids = BASE + 0x200;
        env.put(INFO, &[0; BPF_PROG_INFO_SIZE]);
        env.put(INFO + prog_info::XLATED_PROG_LEN as u64, &32u32.to_ne_bytes());
        env.put(INFO + prog_info::XLATED_PROG_INSNS as u64, &xlated.to_ne_bytes());
        env.put(INFO + prog_info::NR_MAP_IDS as u64, &4u32.to_ne_bytes());
        env.put(INFO + prog_info::MAP_IDS as u64, &map_ids.to_ne_bytes());
        let len = BPF_PROG_INFO_SIZE as u32;
        assert_eq!(env.call(BPF_OBJ_GET_INFO_BY_FD, &info_attr(fd, len, INFO)), Ok(0));
        let id = get_u32(&env, INFO + prog_info::ID as u64);
        assert_ne!(id, 0);
        assert_eq!(get_u32(&env, INFO + prog_info::TYPE as u64), BPF_PROG_TYPE_SOCKET_FILTER);
        assert_eq!(get_u32(&env, INFO + prog_info::CREATED_BY_UID as u64), 1000);
        assert_eq!(get_u32(&env, INFO + prog_info::LOAD_TIME as u64), 1234);
        assert_eq!(get_u32(&env, INFO + prog_info::NR_MAP_IDS as u64), 1);
        assert_eq!(get_u32(&env, map_ids), map_id);
        assert_eq!(get_u32(&env, INFO + prog_info::XLATED_PROG_LEN as u64), 32);
        // The dump has the ID of the map in the load of the map.
        assert_eq!(get_u32(&env, xlated + 4), map_id);
        assert_eq!(get_u32(&env, INFO + prog_info::FUNC_INFO_REC_SIZE as u64), 8);
        assert_eq!(get_u32(&env, INFO + prog_info::NR_JITED_KSYMS as u64), 1);
        // A bad size of a record gives EINVAL.
        env.put(INFO + prog_info::LINE_INFO_REC_SIZE as u64, &4u32.to_ne_bytes());
        assert_eq!(env.call(BPF_OBJ_GET_INFO_BY_FD, &info_attr(fd, len, INFO)), Err(Errno::EINVAL));
        // A byte after the fields that the kernel knows gives E2BIG.
        env.put(INFO, &[0; BPF_PROG_INFO_SIZE + 8]);
        env.put(INFO + BPF_PROG_INFO_SIZE as u64, &[1]);
        let long = info_attr(fd, len + 8, INFO);
        assert_eq!(env.call(BPF_OBJ_GET_INFO_BY_FD, &long), Err(Errno::E2BIG));

        let got = env.call(BPF_PROG_GET_FD_BY_ID, &id_attr(id, 0)).unwrap();
        let a = bpf_prog_of(&env.fdget(fd as i32).unwrap()).unwrap();
        let b = bpf_prog_of(&env.fdget(got as i32).unwrap()).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(env.call(BPF_PROG_GET_FD_BY_ID, &id_attr(0, 0)), Err(Errno::ENOENT));
        assert_eq!(env.call(BPF_PROG_GET_NEXT_ID, &id_attr(id - 1, 0)), Ok(0));
        assert_eq!(get_u32(&env, BASE + get_id::NEXT_ID as u64), id);
        // A socket filter has no link.
        let mut a = BpfAttr::zeroed();
        a.set_u32(link_create::PROG_FD, fd as u32);
        a.set_u32(link_create::ATTACH_TYPE, BPF_CGROUP_INET_INGRESS);
        assert_eq!(env.call(BPF_LINK_CREATE, &a), Err(Errno::EINVAL));
    }

    /// A hook that records the release of its link and can update its program.
    struct TestOps(Arc<core::sync::atomic::AtomicBool>);

    impl crate::link::BpfLinkOps for TestOps {
        fn release(&self, _link: &BpfLink) {
            self.0.store(true, Ordering::Relaxed);
        }

        fn detach(&self, link: &BpfLink) -> Result<()> {
            link.release_once();
            Ok(())
        }

        fn update_prog(
            &self,
            link: &BpfLink,
            new: Arc<BpfProg>,
            old: Option<&Arc<BpfProg>>,
        ) -> Result<()> {
            if let Some(old) = old
                && !link.prog().is_some_and(|p| Arc::ptr_eq(&p, old))
            {
                return Err(Errno::EPERM);
            }
            link.set_prog(Some(new));
            Ok(())
        }
    }

    fn link_attr(link_fd: i64, new_fd: i64, flags: u32, old_fd: i64) -> BpfAttr {
        let mut a = BpfAttr::zeroed();
        a.set_u32(link_update::LINK_FD, link_fd as u32);
        a.set_u32(link_update::NEW_PROG_FD, new_fd as u32);
        a.set_u32(link_update::FLAGS, flags);
        a.set_u32(link_update::OLD_PROG_FD, old_fd as u32);
        a
    }

    #[test]
    fn a_link_can_be_updated_pinned_and_detached() {
        let env = FakeEnv::new();
        let ret = [insn(0xb7, 0, 0, 0, 0), insn(0x95, 0, 0, 0, 0)];
        let p1 = load(&env, &ret, 0).unwrap();
        let p2 = load(&env, &ret, 0).unwrap();
        let prog1 = bpf_prog_of(&env.fdget(p1 as i32).unwrap()).unwrap();
        let prog2 = bpf_prog_of(&env.fdget(p2 as i32).unwrap()).unwrap();
        let released = Arc::new(core::sync::atomic::AtomicBool::new(false));
        let link =
            Arc::new(BpfLink::new(1, alloc::boxed::Box::new(TestOps(released.clone())), prog1, 3));
        let id = crate::link::bpf_link_settle(&link).unwrap();
        let fd = bpf_link_new_fd(&env, link.clone()).unwrap();

        assert_eq!(env.call(BPF_LINK_UPDATE, &link_attr(fd, p2, 0, p1)), Err(Errno::EINVAL));
        assert_eq!(env.call(BPF_LINK_UPDATE, &link_attr(fd, p2, 8, 0)), Err(Errno::EINVAL));
        let replace = link_attr(fd, p2, BPF_F_REPLACE, p2);
        assert_eq!(env.call(BPF_LINK_UPDATE, &replace), Err(Errno::EPERM));
        assert_eq!(env.call(BPF_LINK_UPDATE, &link_attr(fd, p2, BPF_F_REPLACE, p1)), Ok(0));
        assert!(Arc::ptr_eq(&link.prog().unwrap(), &prog2));
        assert_eq!(env.call(BPF_LINK_UPDATE, &link_attr(p1, p2, 0, 0)), Err(Errno::EINVAL));

        env.put(INFO, &[0; BPF_LINK_INFO_SIZE]);
        let len = BPF_LINK_INFO_SIZE as u32;
        assert_eq!(env.call(BPF_OBJ_GET_INFO_BY_FD, &info_attr(fd, len, INFO)), Ok(0));
        assert_eq!(get_u32(&env, INFO + 4), id);
        assert_eq!(get_u32(&env, INFO + 8), prog2.id);

        let path = BASE + 1024;
        env.put(path, b"l\0");
        assert_eq!(env.call(BPF_OBJ_PIN, &obj(path, fd, 0)), Ok(0));
        assert_eq!(env.call(BPF_OBJ_GET, &obj(path, 0, BPF_F_RDONLY)), Err(Errno::EINVAL));
        let got = env.call(BPF_OBJ_GET, &obj(path, 0, 0)).unwrap();
        assert!(Arc::ptr_eq(&bpf_link_of(&env.fdget(got as i32).unwrap()).unwrap(), &link));
        let by_id = env.call(BPF_LINK_GET_FD_BY_ID, &id_attr(id, 0)).unwrap();
        assert!(Arc::ptr_eq(&bpf_link_of(&env.fdget(by_id as i32).unwrap()).unwrap(), &link));
        assert_eq!(env.call(BPF_LINK_GET_FD_BY_ID, &id_attr(0, 0)), Err(Errno::ENOENT));

        let mut detach = BpfAttr::zeroed();
        detach.set_u32(link_update::LINK_FD, fd as u32);
        assert_eq!(env.call(BPF_LINK_DETACH, &detach), Ok(0));
        assert!(released.load(Ordering::Relaxed) && link.prog().is_none());
    }

    fn load_type(env: &FakeEnv, prog_type: u32, expected: u32, insns: &[[u8; 8]]) -> Result<i64> {
        env.put(INSNS, &insns.concat());
        env.put(LICENSE, b"GPL\0");
        let mut a = BpfAttr::zeroed();
        a.set_u32(prog_load::PROG_TYPE, prog_type);
        a.set_u32(prog_load::EXPECTED_ATTACH_TYPE, expected);
        a.set_u32(prog_load::INSN_CNT, insns.len() as u32);
        a.set_u64(prog_load::INSNS, INSNS);
        a.set_u64(prog_load::LICENSE, LICENSE);
        env.call(BPF_PROG_LOAD, &a)
    }

    fn attach_attr(target: u32, prog: i64, attach_type: u32, flags: u32) -> BpfAttr {
        let mut a = BpfAttr::zeroed();
        a.set_u32(prog_attach::TARGET_FD, target);
        a.set_u32(prog_attach::ATTACH_BPF_FD, prog as u32);
        a.set_u32(prog_attach::ATTACH_TYPE, attach_type);
        a.set_u32(prog_attach::ATTACH_FLAGS, flags);
        a
    }

    #[test]
    fn cgroup_programs_attach_query_and_detach() {
        let env = FakeEnv::new();
        let ret1 = [insn(0xb7, 0, 0, 0, 1), insn(0x95, 0, 0, 0, 0)];
        let ret2 = [insn(0xb7, 0, 0, 0, 2), insn(0x95, 0, 0, 0, 0)];
        // An ingress program gives 0 or 1. An egress program can give 2, and then it can only
        // attach at egress.
        assert_eq!(load_type(&env, BPF_PROG_TYPE_CGROUP_SKB, 0, &ret2), Err(Errno::EINVAL));
        let egress =
            load_type(&env, BPF_PROG_TYPE_CGROUP_SKB, BPF_CGROUP_INET_EGRESS, &ret2).unwrap();
        let skb = load_type(&env, BPF_PROG_TYPE_CGROUP_SKB, 0, &ret1).unwrap();
        assert_eq!(load_type(&env, BPF_PROG_TYPE_CGROUP_SOCK, 99, &ret1), Err(Errno::EINVAL));
        let sock = load_type(&env, BPF_PROG_TYPE_CGROUP_SOCK, 0, &ret1).unwrap();
        let sock_prog = bpf_prog_of(&env.fdget(sock as i32).unwrap()).unwrap();
        assert_eq!(sock_prog.expected_attach_type, BPF_CGROUP_INET_SOCK_CREATE);
        // A device program cannot write its context.
        let st = [insn(0xb7, 0, 0, 0, 1), insn(0x63, 1, 0, 0, 0), insn(0x95, 0, 0, 0, 0)];
        assert_eq!(load_type(&env, BPF_PROG_TYPE_CGROUP_DEVICE, 0, &st), Err(Errno::EACCES));

        let ingress = attach_attr(5100, egress, BPF_CGROUP_INET_INGRESS, 0);
        assert_eq!(env.call(BPF_PROG_ATTACH, &ingress), Err(Errno::EINVAL));
        let bad_fd = attach_attr(7, skb, BPF_CGROUP_INET_EGRESS, BPF_F_ALLOW_MULTI);
        assert_eq!(env.call(BPF_PROG_ATTACH, &bad_fd), Err(Errno::EBADF));
        let a = attach_attr(5100, skb, BPF_CGROUP_INET_EGRESS, BPF_F_ALLOW_MULTI);
        assert_eq!(env.call(BPF_PROG_ATTACH, &a), Ok(0));
        let b = attach_attr(5101, egress, BPF_CGROUP_INET_EGRESS, BPF_F_ALLOW_MULTI);
        assert_eq!(env.call(BPF_PROG_ATTACH, &b), Ok(0));
        let sk = attach_attr(5101, sock, BPF_CGROUP_INET_SOCK_CREATE, 0);
        assert_eq!(env.call(BPF_PROG_ATTACH, &sk), Ok(0));

        let ids = BASE + 0x900;
        let mut q = BpfAttr::zeroed();
        q.set_u32(query::TARGET_FD, 5101);
        q.set_u32(query::ATTACH_TYPE, BPF_CGROUP_INET_EGRESS);
        q.set_u32(query::QUERY_FLAGS, BPF_F_QUERY_EFFECTIVE);
        q.set_u64(query::PROG_IDS, ids);
        q.set_u32(query::PROG_CNT, 1);
        assert_eq!(env.call(BPF_PROG_QUERY, &q), Err(Errno::ENOSPC));
        assert_eq!(get_u32(&env, BASE + query::PROG_CNT as u64), 2);
        q.set_u32(query::PROG_CNT, 8);
        assert_eq!(env.call(BPF_PROG_QUERY, &q), Ok(0));
        let egress_prog = bpf_prog_of(&env.fdget(egress as i32).unwrap()).unwrap();
        let skb_prog = bpf_prog_of(&env.fdget(skb as i32).unwrap()).unwrap();
        assert_eq!([get_u32(&env, ids), get_u32(&env, ids + 4)], [egress_prog.id, skb_prog.id]);
        q.set_u32(query::QUERY_FLAGS, 0);
        assert_eq!(env.call(BPF_PROG_QUERY, &q), Ok(0));
        assert_eq!(get_u32(&env, BASE + query::ATTACH_FLAGS as u64), BPF_F_ALLOW_MULTI);
        assert_eq!(get_u32(&env, BASE + query::PROG_CNT as u64), 1);
        env.caps.set(false);
        assert_eq!(env.call(BPF_PROG_QUERY, &q), Err(Errno::EPERM));
        env.caps.set(true);

        // A link of a cgroup.
        let mut l = BpfAttr::zeroed();
        l.set_u32(link_create::PROG_FD, skb as u32);
        l.set_u32(link_create::TARGET_FD, 5102);
        l.set_u32(link_create::ATTACH_TYPE, BPF_CGROUP_INET_INGRESS);
        let link = env.call(BPF_LINK_CREATE, &l).unwrap();
        let link = bpf_link_of(&env.fdget(link as i32).unwrap()).unwrap();
        assert_eq!(
            alloc::string::String::from_utf8(link.show_fdinfo()).unwrap().lines().last(),
            Some("attach_type:\t0")
        );
        let d = attach_attr(5102, skb, BPF_CGROUP_INET_INGRESS, 0);
        assert_eq!(env.call(BPF_PROG_DETACH, &d), Err(Errno::ENOENT));
        let mut detach = BpfAttr::zeroed();
        detach.set_u32(link_update::LINK_FD, link.id());
        let fd = bpf_link_new_fd(&env, link.clone()).unwrap();
        detach.set_u32(link_update::LINK_FD, fd as u32);
        assert_eq!(env.call(BPF_LINK_DETACH, &detach), Ok(0));
        assert!(link.prog().is_none());

        let d = attach_attr(5100, skb, BPF_CGROUP_INET_EGRESS, 0);
        assert_eq!(env.call(BPF_PROG_DETACH, &d), Ok(0));
        assert_eq!(env.call(BPF_PROG_DETACH, &d), Err(Errno::ENOENT));
        crate::cgroup::cgroup_bpf_offline(5101);
    }
}
