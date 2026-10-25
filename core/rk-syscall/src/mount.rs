//! `mount` and `umount2`, and the calls of the new mount API: `fsopen`, `fsconfig`, `fsmount`,
//! `fspick`, `move_mount` and `open_tree`.
//!
//! A file system context of the new mount API is a file. `fsconfig` keeps the options in the
//! file, and `FSCONFIG_CMD_CREATE` makes the file system with the same constructor as `mount`.
//! `fsmount` and `open_tree` with `OPEN_TREE_CLONE` give an `O_PATH` file of a mount that is not
//! attached, and `move_mount` attaches it.
//!
//! R1 has one mount name space and no propagation between mounts, so a change of the propagation
//! type has no effect. The VFS keeps the flags of a mount for `/proc/self/mounts`, but it does not
//! enforce `MS_RDONLY`, `MS_NOEXEC` and the other flags yet.

use crate::cx::{Cx, PATH_MAX, SysResult};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use rk_abi::Errno;
use rk_abi::native::at::{
    AT_EMPTY_PATH, AT_FDCWD, AT_NO_AUTOMOUNT, AT_RECURSIVE, AT_SYMLINK_NOFOLLOW,
};
use rk_abi::native::mount::{
    FSCONFIG_CMD_CREATE, FSCONFIG_CMD_CREATE_EXCL, FSCONFIG_CMD_RECONFIGURE, FSCONFIG_SET_BINARY,
    FSCONFIG_SET_FD, FSCONFIG_SET_FLAG, FSCONFIG_SET_PATH, FSCONFIG_SET_PATH_EMPTY,
    FSCONFIG_SET_STRING, FSMOUNT_CLOEXEC, FSOPEN_CLOEXEC, FSPICK_CLOEXEC, FSPICK_EMPTY_PATH,
    FSPICK_NO_AUTOMOUNT, FSPICK_SYMLINK_NOFOLLOW, MOUNT_ATTR__ATIME, MOUNT_ATTR_NOATIME,
    MOUNT_ATTR_NODEV, MOUNT_ATTR_NODIRATIME, MOUNT_ATTR_NOEXEC, MOUNT_ATTR_NOSUID,
    MOUNT_ATTR_NOSYMFOLLOW, MOUNT_ATTR_RDONLY, MOUNT_ATTR_RELATIME, MOUNT_ATTR_STRICTATIME,
    MOVE_MOUNT_BENEATH, MOVE_MOUNT_F_AUTOMOUNTS, MOVE_MOUNT_F_EMPTY_PATH, MOVE_MOUNT_F_SYMLINKS,
    MOVE_MOUNT_T_AUTOMOUNTS, MOVE_MOUNT_T_EMPTY_PATH, MOVE_MOUNT_T_SYMLINKS, MS_BIND, MS_DIRSYNC,
    MS_MGC_MSK, MS_MGC_VAL, MS_MOVE, MS_NOATIME, MS_NODEV, MS_NODIRATIME, MS_NOEXEC, MS_NOSUID,
    MS_NOSYMFOLLOW, MS_PRIVATE, MS_RDONLY, MS_RELATIME, MS_REMOUNT, MS_SHARED, MS_SLAVE,
    MS_STRICTATIME, MS_SYNCHRONOUS, MS_UNBINDABLE, OPEN_TREE_CLONE,
};
use rk_abi::native::open::{O_CLOEXEC, O_PATH, O_RDWR};
use rk_frame::sync::SpinLock;
use rk_vfs::file::{File, FileOps};
use rk_vfs::fstype::{self, FsType};
use rk_vfs::inode::InodeRef;
use rk_vfs::{FsContext, Location, Mount, MountNamespace, MountSource};

/// The flags of `umount2`. They are in `<sys/mount.h>` of the C library, not in the uAPI.
const MNT_FORCE: u64 = 1;
const MNT_DETACH: u64 = 2;
const MNT_EXPIRE: u64 = 4;
const UMOUNT_NOFOLLOW: u64 = 8;

/// The flags that a mount keeps and `/proc/self/mounts` shows.
const KEPT: u32 = MS_RDONLY
    | MS_NOSUID
    | MS_NODEV
    | MS_NOEXEC
    | MS_SYNCHRONOUS
    | MS_DIRSYNC
    | MS_NOATIME
    | MS_NODIRATIME
    | MS_RELATIME
    | MS_STRICTATIME
    | MS_NOSYMFOLLOW;

/// The most bytes of the data string. Linux copies one page.
const DATA_MAX: usize = 4096;

/// The propagation types.
const PROPAGATION: u32 = MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE;

pub(crate) fn mount(
    cx: &Cx<'_>,
    source: u64,
    target: u64,
    fstype: u64,
    flags: u64,
    data: u64,
) -> SysResult {
    let mut flags = flags as u32;
    // Old programs put the magic number 0xC0ED in the high 16 bits.
    if flags & MS_MGC_MSK == MS_MGC_VAL {
        flags &= !MS_MGC_MSK;
    }
    let target = cx.read_path(target)?;
    let fs = cx.fs()?;
    let at = fs.resolve(fs.cwd(), &target, true)?;
    let ns = fs.namespace();
    if flags & MS_REMOUNT != 0 {
        if !at.is_mount_root() {
            return Err(Errno::EINVAL);
        }
        let old = at.mount.flags() as u32;
        at.mount.set_flags(u64::from(atime_flags(flags, Some(old)) & KEPT));
        return Ok(0);
    }
    if flags & MS_BIND != 0 {
        let source = cx.read_path(source)?;
        let from = fs.resolve(fs.cwd(), &source, true)?;
        ns.bind(&from, &at)?;
        return Ok(0);
    }
    if flags & PROPAGATION != 0 {
        if !at.is_mount_root() || (flags & PROPAGATION).count_ones() != 1 {
            return Err(Errno::EINVAL);
        }
        return Ok(0);
    }
    if flags & MS_MOVE != 0 {
        let source = cx.read_path(source)?;
        let from = fs.resolve(fs.cwd(), &source, true)?;
        ns.move_to(&from, &at)?;
        return Ok(0);
    }
    let vm = cx.vm()?;
    let name = if fstype == 0 { Vec::new() } else { vm.read_cstr(fstype as usize, PATH_MAX)? };
    let ty = fstype::find(&name).ok_or(Errno::ENODEV)?;
    let data = if data == 0 { Vec::new() } else { vm.read_cstr(data as usize, DATA_MAX)? };
    let source = match source {
        0 => Vec::from(&b"none"[..]),
        addr => vm.read_cstr(addr as usize, PATH_MAX)?,
    };
    let root = make(&fs, ty, &source, &data, flags & MS_RDONLY != 0)?;
    let flags = atime_flags(flags, None) & KEPT;
    let source = MountSource { source, fstype: ty.name, flags: u64::from(flags) };
    ns.mount(root, &at, source)?;
    Ok(0)
}

/// Sets the atime flags of `mount(2)` as Linux does. A mount is relatime unless it is noatime or
/// strictatime. A remount that gives no atime flag keeps the atime flags of the mount, in `old`.
/// The mount keeps `MS_STRICTATIME`, so the VFS can tell a strictatime mount from a mount that the
/// kernel made with no flags.
fn atime_flags(flags: u32, old: Option<u32>) -> u32 {
    let atime = MS_NOATIME | MS_NODIRATIME | MS_RELATIME | MS_STRICTATIME;
    if let Some(old) = old
        && flags & atime == 0
    {
        return flags | (old & atime);
    }
    let mut flags = flags;
    if flags & MS_NOATIME == 0 {
        flags |= MS_RELATIME;
    }
    if flags & MS_STRICTATIME != 0 {
        flags &= !(MS_RELATIME | MS_NOATIME);
    }
    flags
}

/// Makes a file system of the type `ty` and gives its root. A file system on a disk has the
/// block device of the source path.
fn make(
    fs: &FsContext,
    ty: FsType,
    source: &[u8],
    data: &[u8],
    read_only: bool,
) -> Result<InodeRef, Errno> {
    let dev = if ty.nodev {
        None
    } else {
        let path = fs.resolve(fs.cwd(), source, true)?;
        let meta = path.inode().metadata();
        if meta.file_type() != Some(rk_vfs::FileType::BlockDevice) {
            return Err(Errno::ENOTBLK);
        }
        Some(meta.rdev)
    };
    let lookup = |path: &[u8]| Ok(fs.resolve(fs.cwd(), path, true)?.inode().clone());
    let args = fstype::MountArgs { data, dev, read_only, lookup: Some(&lookup) };
    (ty.make)(&args)
}

pub(crate) fn umount2(cx: &Cx<'_>, target: u64, flags: u64) -> SysResult {
    if flags & !(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW) != 0
        || (flags & MNT_EXPIRE != 0 && flags & (MNT_FORCE | MNT_DETACH) != 0)
    {
        return Err(Errno::EINVAL);
    }
    let target = cx.read_path(target)?;
    let fs = cx.fs()?;
    let at = fs.resolve(fs.cwd(), &target, flags & UMOUNT_NOFOLLOW == 0)?;
    fs.namespace().unmount(&at)?;
    Ok(0)
}

/// The most bytes of a key and of a string value of `fsconfig`, as Linux.
const PARAM_MAX: usize = 256;

/// The options that `fsconfig` gives to a file system context.
#[derive(Default)]
struct Config {
    /// The `source` option, or `None` if `fsconfig` did not give it.
    source: Option<Vec<u8>>,
    /// The other options, as the data string of `mount(2)`.
    data: Vec<u8>,
    /// The `ro` flag.
    read_only: bool,
    /// The root of the file system, after `FSCONFIG_CMD_CREATE`.
    root: Option<InodeRef>,
}

/// A file system context, the file of `fsopen` and `fspick`.
struct FsCtx {
    /// The type of the file system that `FSCONFIG_CMD_CREATE` makes, or `None` for the context
    /// of `fspick`.
    ty: Option<FsType>,
    /// The mount that `fspick` took, which `FSCONFIG_CMD_RECONFIGURE` changes.
    picked: Option<Arc<Mount>>,
    config: SpinLock<Config>,
}

impl FileOps for FsCtx {
    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

/// Gives the file system context of `fd`. Gives `EINVAL` if the file is not one.
fn context(cx: &Cx<'_>, fd: u64) -> Result<Arc<File>, Errno> {
    let file = cx.file(fd)?;
    if file.ops().as_any().and_then(|a| a.downcast_ref::<FsCtx>()).is_none() {
        return Err(Errno::EINVAL);
    }
    Ok(file)
}

/// Gives the place of the path at `addr` from the directory `dfd`. An empty path is the place
/// of `dfd` if `empty` is true.
fn locate(
    cx: &Cx<'_>,
    fs: &FsContext,
    dfd: u64,
    addr: u64,
    empty: bool,
    follow: bool,
) -> Result<Location, Errno> {
    let path = cx.read_path_opt(addr, empty)?;
    let start = cx.dir_start(fs, dfd, &path)?;
    if path.is_empty() {
        return Ok(start);
    }
    Ok(fs.resolve(&start, &path, follow)?)
}

/// Gives a new `O_PATH` descriptor of the root of `mount`.
fn mount_fd(cx: &Cx<'_>, fs: &FsContext, mount: Arc<Mount>, cloexec: bool) -> SysResult {
    let at = Location { dentry: mount.root().clone(), mount };
    let file = fs.open_at(at, O_PATH)?;
    Ok(cx.files()?.lock().insert(file, cloexec)? as u64)
}

pub(crate) fn fsopen(cx: &Cx<'_>, name: u64, flags: u64) -> SysResult {
    if flags & !u64::from(FSOPEN_CLOEXEC) != 0 {
        return Err(Errno::EINVAL);
    }
    let name = cx.vm()?.read_cstr(name as usize, PARAM_MAX)?;
    let ty = fstype::find(&name).ok_or(Errno::ENODEV)?;
    let ops = FsCtx { ty: Some(ty), picked: None, config: SpinLock::new(Config::default()) };
    let file = File::with_ops(Arc::new(ops), None, O_RDWR);
    Ok(cx.files()?.lock().insert(file, flags & u64::from(FSOPEN_CLOEXEC) != 0)? as u64)
}

pub(crate) fn fspick(cx: &Cx<'_>, dfd: u64, path: u64, flags: u64) -> SysResult {
    let known = FSPICK_CLOEXEC | FSPICK_SYMLINK_NOFOLLOW | FSPICK_NO_AUTOMOUNT | FSPICK_EMPTY_PATH;
    if flags & !u64::from(known) != 0 {
        return Err(Errno::EINVAL);
    }
    let flags = flags as u32;
    let fs = cx.fs()?;
    let empty = flags & FSPICK_EMPTY_PATH != 0;
    let at = locate(cx, &fs, dfd, path, empty, flags & FSPICK_SYMLINK_NOFOLLOW == 0)?;
    if !at.is_mount_root() {
        return Err(Errno::EINVAL);
    }
    let config = Config {
        read_only: at.mount.source().flags & u64::from(MS_RDONLY) != 0,
        ..Config::default()
    };
    let ops = FsCtx { ty: None, picked: Some(at.mount), config: SpinLock::new(config) };
    let file = File::with_ops(Arc::new(ops), None, O_RDWR);
    Ok(cx.files()?.lock().insert(file, flags & FSPICK_CLOEXEC != 0)? as u64)
}

pub(crate) fn fsconfig(
    cx: &Cx<'_>,
    fd: u64,
    cmd: u64,
    key: u64,
    value: u64,
    aux: u64,
) -> SysResult {
    let aux = aux as i32;
    let cmd = u32::try_from(cmd).map_err(|_| Errno::EOPNOTSUPP)?;
    // The checks of the arguments come before the check of the descriptor, as in Linux.
    let valid = match cmd {
        FSCONFIG_SET_FLAG => key != 0 && value == 0 && aux == 0,
        FSCONFIG_SET_STRING => key != 0 && value != 0 && aux == 0,
        FSCONFIG_SET_BINARY => key != 0 && value != 0 && aux > 0 && aux <= 1024 * 1024,
        FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY => {
            key != 0 && value != 0 && (aux == AT_FDCWD || aux >= 0)
        }
        FSCONFIG_SET_FD => key != 0 && value == 0 && aux >= 0,
        FSCONFIG_CMD_CREATE | FSCONFIG_CMD_CREATE_EXCL | FSCONFIG_CMD_RECONFIGURE => {
            key == 0 && value == 0 && aux == 0
        }
        _ => return Err(Errno::EOPNOTSUPP),
    };
    if !valid || (fd as i32) < 0 {
        return Err(Errno::EINVAL);
    }
    let file = context(cx, fd)?;
    let Some(ctx) = file.ops().as_any().and_then(|a| a.downcast_ref::<FsCtx>()) else {
        return Err(Errno::EINVAL);
    };
    let vm = cx.vm()?;
    let key = if key == 0 { Vec::new() } else { vm.read_cstr(key as usize, PARAM_MAX)? };
    match cmd {
        FSCONFIG_SET_FLAG => {
            let mut config = ctx.config.lock();
            match &key[..] {
                b"ro" => config.read_only = true,
                b"rw" => config.read_only = false,
                b"source" => return Err(Errno::EINVAL),
                _ => add_option(&mut config.data, &key, None)?,
            }
        }
        FSCONFIG_SET_STRING | FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY => {
            let value = vm.read_cstr(value as usize, PARAM_MAX)?;
            // Only the source of the file systems of R3 is a path.
            if cmd != FSCONFIG_SET_STRING && key != b"source" {
                return Err(Errno::EOPNOTSUPP);
            }
            let mut config = ctx.config.lock();
            if key == b"source" {
                if config.source.is_some() {
                    return Err(Errno::EINVAL);
                }
                config.source = Some(value);
            } else {
                add_option(&mut config.data, &key, Some(&value))?;
            }
        }
        // The file systems of R3 take only flags and strings.
        FSCONFIG_SET_BINARY | FSCONFIG_SET_FD => return Err(Errno::EOPNOTSUPP),
        FSCONFIG_CMD_RECONFIGURE => {
            let mount = ctx.picked.as_ref().ok_or(Errno::EBUSY)?;
            let read_only = ctx.config.lock().read_only;
            let flags = mount.source().flags & !u64::from(MS_RDONLY);
            mount.set_flags(flags | if read_only { u64::from(MS_RDONLY) } else { 0 });
        }
        _ => {
            let ty = ctx.ty.ok_or(Errno::EBUSY)?;
            let (source, data, read_only) = {
                let config = ctx.config.lock();
                if config.root.is_some() {
                    return Err(Errno::EBUSY);
                }
                let source = match &config.source {
                    Some(source) => source.clone(),
                    None if ty.nodev => Vec::from(&b"none"[..]),
                    None => return Err(Errno::EINVAL),
                };
                (source, config.data.clone(), config.read_only)
            };
            let root = make(&cx.fs()?, ty, &source, &data, read_only)?;
            let mut config = ctx.config.lock();
            if config.root.is_some() {
                return Err(Errno::EBUSY);
            }
            config.source = Some(source);
            config.root = Some(root);
        }
    }
    Ok(0)
}

/// Adds `key` or `key=value` to the comma separated data string `data`. Gives `EINVAL` for an
/// empty key, and if the string becomes longer than one page, as `legacy_parse_param` of Linux.
fn add_option(data: &mut Vec<u8>, key: &[u8], value: Option<&[u8]>) -> Result<(), Errno> {
    let len = key.len() + value.map_or(0, |v| v.len() + 1) + usize::from(!data.is_empty());
    if key.is_empty() || data.len() + len > DATA_MAX - 2 {
        return Err(Errno::EINVAL);
    }
    if !data.is_empty() {
        data.push(b',');
    }
    data.extend_from_slice(key);
    if let Some(value) = value {
        data.push(b'=');
        data.extend_from_slice(value);
    }
    Ok(())
}

/// Gives the `MS_*` flags of the `MOUNT_ATTR_*` flags of `fsmount`.
fn attr_flags(attr: u32) -> Result<u32, Errno> {
    let pairs = [
        (MOUNT_ATTR_RDONLY, MS_RDONLY),
        (MOUNT_ATTR_NOSUID, MS_NOSUID),
        (MOUNT_ATTR_NODEV, MS_NODEV),
        (MOUNT_ATTR_NOEXEC, MS_NOEXEC),
        (MOUNT_ATTR_NODIRATIME, MS_NODIRATIME),
        (MOUNT_ATTR_NOSYMFOLLOW, MS_NOSYMFOLLOW),
    ];
    let known = pairs.iter().fold(MOUNT_ATTR__ATIME, |all, (a, _)| all | a);
    if attr & !known != 0 {
        return Err(Errno::EINVAL);
    }
    let mut flags = match attr & MOUNT_ATTR__ATIME {
        MOUNT_ATTR_RELATIME => MS_RELATIME,
        MOUNT_ATTR_NOATIME => MS_NOATIME,
        MOUNT_ATTR_STRICTATIME => MS_STRICTATIME,
        _ => return Err(Errno::EINVAL),
    };
    for (a, ms) in pairs {
        if attr & a != 0 {
            flags |= ms;
        }
    }
    Ok(flags)
}

pub(crate) fn fsmount(cx: &Cx<'_>, fd: u64, flags: u64, attr: u64) -> SysResult {
    if flags & !u64::from(FSMOUNT_CLOEXEC) != 0 {
        return Err(Errno::EINVAL);
    }
    let attr = attr_flags(u32::try_from(attr).map_err(|_| Errno::EINVAL)?)?;
    let file = context(cx, fd)?;
    let Some(ctx) = file.ops().as_any().and_then(|a| a.downcast_ref::<FsCtx>()) else {
        return Err(Errno::EINVAL);
    };
    let ty = ctx.ty.ok_or(Errno::EINVAL)?;
    let (root, source, read_only) = {
        let config = ctx.config.lock();
        let root = config.root.clone().ok_or(Errno::EINVAL)?;
        (root, config.source.clone().unwrap_or_default(), config.read_only)
    };
    if !root.metadata().is_dir() {
        return Err(Errno::ENOTDIR);
    }
    let ro = if read_only { MS_RDONLY } else { 0 };
    let source = MountSource { source, fstype: ty.name, flags: u64::from((attr | ro) & KEPT) };
    let mount = MountNamespace::detached(rk_vfs::Dentry::new_root(root), source);
    mount_fd(cx, &cx.fs()?, mount, flags & u64::from(FSMOUNT_CLOEXEC) != 0)
}

pub(crate) fn move_mount(
    cx: &Cx<'_>,
    from_dfd: u64,
    from_path: u64,
    to_dfd: u64,
    to_path: u64,
    flags: u64,
) -> SysResult {
    let known = MOVE_MOUNT_F_SYMLINKS
        | MOVE_MOUNT_F_AUTOMOUNTS
        | MOVE_MOUNT_F_EMPTY_PATH
        | MOVE_MOUNT_T_SYMLINKS
        | MOVE_MOUNT_T_AUTOMOUNTS
        | MOVE_MOUNT_T_EMPTY_PATH
        | MOVE_MOUNT_BENEATH;
    if flags & !u64::from(known) != 0 {
        return Err(Errno::EINVAL);
    }
    let flags = flags as u32;
    let fs = cx.fs()?;
    let from = locate(
        cx,
        &fs,
        from_dfd,
        from_path,
        flags & MOVE_MOUNT_F_EMPTY_PATH != 0,
        flags & MOVE_MOUNT_F_SYMLINKS != 0,
    )?;
    let to = locate(
        cx,
        &fs,
        to_dfd,
        to_path,
        flags & MOVE_MOUNT_T_EMPTY_PATH != 0,
        flags & MOVE_MOUNT_T_SYMLINKS != 0,
    )?;
    let ns = fs.namespace();
    if !from.is_mount_root() {
        return Err(Errno::EINVAL);
    }
    if flags & MOVE_MOUNT_BENEATH != 0 {
        ns.move_beneath(&from, &to)?;
    } else if ns.contains(&from.mount) {
        ns.move_to(&from, &to)?;
    } else {
        ns.attach(&from.mount, &to)?;
    }
    Ok(0)
}

pub(crate) fn open_tree(cx: &Cx<'_>, dfd: u64, path: u64, flags: u64) -> SysResult {
    let at_flags = (AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW) as u32;
    let known = u64::from(OPEN_TREE_CLONE | O_CLOEXEC | at_flags);
    if flags & !known != 0 {
        return Err(Errno::EINVAL);
    }
    let flags = flags as u32;
    let clone = flags & OPEN_TREE_CLONE != 0;
    if flags & AT_RECURSIVE as u32 != 0 && !clone {
        return Err(Errno::EINVAL);
    }
    let fs = cx.fs()?;
    let empty = flags & AT_EMPTY_PATH as u32 != 0;
    let at = locate(cx, &fs, dfd, path, empty, flags & AT_SYMLINK_NOFOLLOW as u32 == 0)?;
    let cloexec = flags & O_CLOEXEC != 0;
    if !clone {
        let file = fs.open_at(at, O_PATH)?;
        return Ok(cx.files()?.lock().insert(file, cloexec)? as u64);
    }
    // The clone has the mount of `at` only. The mounts below it are not in the clone.
    mount_fd(cx, &fs, MountNamespace::clone_tree(&at), cloexec)
}
