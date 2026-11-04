//! The `bpf(2)` system call, kernel/bpf/syscall.c of Linux.
//!
//! The call has the command, `union bpf_attr` and its size, and with `BPF_COMMON_ATTRS` also
//! `struct bpf_common_attr` and its size. The caller gives the memory and the files of the
//! process through [`Env`].

use crate::UNPRIVILEGED_BPF_DISABLED;
use crate::attr::{
    BPF_ATTR_SIZE, BPF_COMMON_ATTR_SIZE, BpfAttr, bpf_check_uarg_tail_zero, common, last_field,
    map_create, map_elem, obj, prog_load,
};
use crate::file::{BpfMapFile, bpf_map_of};
use crate::inode::BpfObj;
use crate::insn::{BPF_COMPLEXITY_LIMIT_INSNS, BPF_MAXINSNS, INSN_SIZE, decode};
use crate::map::{
    BpfMap, MapAttr, MapEnv, bpf_map_type_known, bpf_obj_name_cpy, map_alloc, map_alloc_check,
};
use crate::prog::prog_flags::*;
use crate::prog::prog_type::*;
use crate::prog::{BpfProg, BpfProgFile, bpf_prog_alloc_id, bpf_prog_calc_tag, bpf_prog_of};
use crate::uapi::CAP_BPF;
use crate::uapi::cmd::*;
use crate::uapi::elem::{BPF_F_CPU, BPF_F_LOCK};
use crate::uapi::flags::{
    BPF_F_NUMA_NODE, BPF_F_PATH_FD, BPF_F_RDONLY, BPF_F_TOKEN_FD, BPF_F_WRONLY, BPF_F_ZERO_SEED,
};
use crate::uapi::map_type::*;
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
    // rukernel has no BTF, so a program cannot name a function to attach to. A socket filter
    // has no attach type, as `bpf_prog_load_check_attach` of Linux.
    if attr.u32(ATTACH_PROG_FD) != 0 || attr.u32(ATTACH_BTF_ID) != 0 {
        return Err(Errno::EINVAL);
    }
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
        bpf_capable: bpf_cap,
        allow_ptr_leaks: env.capable(CAP_PERFMON) || env.capable(CAP_SYS_ADMIN),
    };
    let map_by_fd = |fd: i32| -> Result<Arc<BpfMap>> {
        let file = env.fdget(fd)?;
        bpf_map_of(&file).ok_or(Errno::EINVAL)
    };
    let r = bpf_check(decode(&bytes), &opts, &map_by_fd, &mut log);
    // The error of the log comes before the error of the verifier.
    bpf_log_attr_finalize(env, log_attr, &log)?;
    let v = r?;
    let tag = bpf_prog_calc_tag(&v.insns);
    let prog = BpfProg {
        prog_type,
        expected_attach_type: attr.u32(EXPECTED_ATTACH_TYPE),
        insns: v.insns,
        used_maps: v.used_maps,
        id: bpf_prog_alloc_id(),
        name,
        tag,
        gpl_compatible,
        verified_insns: v.insn_processed,
        run_cnt: core::sync::atomic::AtomicU64::new(0),
    };
    let file = File::with_ops(Arc::new(BpfProgFile { prog: Arc::new(prog) }), None, O_RDWR);
    env.fd_install(file).map(i64::from)
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
    let file = File::with_ops(Arc::new(BpfMapFile { map }), None, f_flags);
    env.fd_install(file).map(i64::from)
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
    map.bpf_map_update_value(&key, &value, flags, env.map_env())?;
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

/// The map or the program of a descriptor, `bpf_fd_probe_obj` of Linux. A descriptor of
/// another file gives `EINVAL`.
fn bpf_fd_probe_obj(env: &dyn Env, fd: u32) -> Result<BpfObj> {
    let file = env.fdget(fd as i32)?;
    if let Some(map) = bpf_map_of(&file) {
        return Ok(BpfObj::Map(map));
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

/// `BPF_OBJ_GET`, `bpf_obj_get` and `bpf_obj_get_user` of Linux. A program needs a file that
/// can be read and written.
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
    let file = match env.obj_get(path_fd, attr.u64(obj::PATHNAME), acc_mode(f_flags))? {
        BpfObj::Prog(prog) => {
            if f_flags != O_RDWR {
                return Err(Errno::EINVAL);
            }
            File::with_ops(Arc::new(BpfProgFile { prog }), None, O_RDWR)
        }
        BpfObj::Map(map) => File::with_ops(Arc::new(BpfMapFile { map }), None, f_flags),
    };
    env.fd_install(file).map(i64::from)
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
}
