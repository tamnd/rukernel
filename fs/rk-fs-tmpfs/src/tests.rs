//! The tests of tmpfs and of the VFS on tmpfs.

use super::*;
use alloc::vec;
use rk_abi::native::open as o;
use rk_vfs::cpio;
use rk_vfs::fstype::MountArgs;
use rk_vfs::{
    FdTable, File, FsContext, Location, MountAttr, MountNamespace, MountSource, Propagation,
    PropagationType, Whence,
};

fn setup() -> (FsContext, Location) {
    let fs = FsContext::new(MountNamespace::new(new(0o755)));
    let root = fs.root().clone();
    (fs, root)
}

fn write_file(fs: &FsContext, at: &Location, path: &[u8], data: &[u8]) {
    let f = fs.open(at, path, o::O_WRONLY | o::O_CREAT | o::O_TRUNC, 0o644).unwrap();
    assert_eq!(f.write(data), Ok(data.len()));
}

fn read_file(fs: &FsContext, at: &Location, path: &[u8]) -> Result<Vec<u8>> {
    let f = fs.open(at, path, o::O_RDONLY, 0)?;
    let mut out = Vec::new();
    let mut buf = [0u8; 7];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&buf[..n]);
    }
}

fn names(fs: &FsContext, at: &Location, path: &[u8]) -> Vec<Vec<u8>> {
    let f = fs.open(at, path, o::O_RDONLY | o::O_DIRECTORY, 0).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 64];
    loop {
        let n = f.read_dir(&mut buf).unwrap();
        if n == 0 {
            return out;
        }
        let mut at = 0;
        while at < n {
            let reclen = u16::from_ne_bytes([buf[at + 16], buf[at + 17]]) as usize;
            let name = &buf[at + 19..at + reclen];
            let end = name.iter().position(|&b| b == 0).unwrap();
            out.push(name[..end].to_vec());
            at += reclen;
        }
    }
}

#[test]
fn files_are_written_and_read() {
    let (fs, root) = setup();
    write_file(&fs, &root, b"/hello", b"hello, world");
    assert_eq!(read_file(&fs, &root, b"hello").as_deref(), Ok(&b"hello, world"[..]));
    let f = fs.open(&root, b"/hello", o::O_RDWR, 0).unwrap();
    assert_eq!(f.seek(-5, Whence::End), Ok(7));
    assert_eq!(f.seek(3, Whence::Data), Ok(3));
    assert_eq!(f.seek(3, Whence::Hole), Ok(12));
    assert_eq!(f.seek(12, Whence::Data), Err(Errno::ENXIO));
    assert_eq!(f.seek(-1, Whence::Hole), Err(Errno::ENXIO));
    assert_eq!(f.seek(-5, Whence::End), Ok(7));
    assert_eq!(f.write(b"there!"), Ok(6));
    assert_eq!(f.metadata().map(|m| m.size), Ok(13));
    assert_eq!(read_file(&fs, &root, b"/hello").as_deref(), Ok(&b"hello, there!"[..]));
    let ro = fs.open(&root, b"/hello", o::O_RDONLY, 0).unwrap();
    assert_eq!(ro.write(b"x"), Err(Errno::EBADF));
    let mut buf = [0u8; 5];
    assert_eq!(ro.read_at(7, &mut buf), Ok(5));
    assert_eq!(&buf, b"there");
    assert_eq!(ro.pos(), 0);
    let app = fs.open(&root, b"/hello", o::O_WRONLY | o::O_APPEND, 0).unwrap();
    assert_eq!(app.write(b"?"), Ok(1));
    assert_eq!(read_file(&fs, &root, b"/hello").as_deref(), Ok(&b"hello, there!?"[..]));
    fs.open(&root, b"/hello", o::O_WRONLY | o::O_TRUNC, 0).unwrap();
    assert_eq!(read_file(&fs, &root, b"/hello").as_deref(), Ok(&b""[..]));
}

#[test]
fn open_gives_the_errors_of_linux() {
    let (fs, root) = setup();
    fs.mkdir(&root, b"/d", 0o755).unwrap();
    write_file(&fs, &root, b"/d/f", b"x");
    assert_eq!(fs.open(&root, b"/nope", o::O_RDONLY, 0).err(), Some(Errno::ENOENT));
    assert_eq!(fs.open(&root, b"/d", o::O_WRONLY, 0).err(), Some(Errno::EISDIR));
    assert_eq!(fs.open(&root, b"/d/f/", o::O_RDONLY, 0).err(), Some(Errno::ENOTDIR));
    assert_eq!(fs.open(&root, b"/d/f/g", o::O_RDONLY, 0).err(), Some(Errno::ENOTDIR));
    assert_eq!(fs.open(&root, b"/d/f", o::O_DIRECTORY, 0).err(), Some(Errno::ENOTDIR));
    let excl = o::O_CREAT | o::O_EXCL | o::O_WRONLY;
    assert_eq!(fs.open(&root, b"/d/f", excl, 0o644).err(), Some(Errno::EEXIST));
    assert_eq!(fs.open(&root, b"/d/new/", excl, 0o644).err(), Some(Errno::EISDIR));
    assert_eq!(fs.open(&root, b"", o::O_RDONLY, 0).err(), Some(Errno::ENOENT));
    let long = vec![b'a'; 256];
    assert_eq!(fs.open(&root, &long, o::O_RDONLY, 0).err(), Some(Errno::ENAMETOOLONG));
    assert_eq!(fs.mkdir(&root, b"/d", 0o755).err(), Some(Errno::EEXIST));
    assert_eq!(fs.mkdir(&root, b"/", 0o755).err(), Some(Errno::EEXIST));
}

#[test]
fn the_umask_applies_to_new_files() {
    let (mut fs, root) = setup();
    fs.set_umask(0o027);
    let f = fs.open(&root, b"/f", o::O_CREAT | o::O_WRONLY, 0o666).unwrap();
    assert_eq!(f.metadata().map(|m| m.mode), Ok(mode::S_IFREG | 0o640));
    let d = fs.mkdir(&root, b"/d", 0o777).unwrap();
    assert_eq!(d.inode().metadata().mode, mode::S_IFDIR | 0o750);
}

#[test]
fn dot_dot_and_getcwd() {
    let (mut fs, root) = setup();
    fs.mkdir(&root, b"/a", 0o755).unwrap();
    fs.mkdir(&root, b"/a/b", 0o755).unwrap();
    fs.chdir(&root, b"/a/b").unwrap();
    assert_eq!(fs.getcwd().as_deref(), Ok(&b"/a/b"[..]));
    let cwd = fs.cwd().clone();
    fs.chdir(&cwd, b"../..").unwrap();
    assert_eq!(fs.getcwd().as_deref(), Ok(&b"/"[..]));
    let cwd = fs.cwd().clone();
    fs.chdir(&cwd, b"../../a/./b/..").unwrap();
    assert_eq!(fs.getcwd().as_deref(), Ok(&b"/a"[..]));
    // The current directory follows a rename of its parent.
    fs.rename(&root, b"/a", &root, b"/z", 0).unwrap();
    assert_eq!(fs.getcwd().as_deref(), Ok(&b"/z"[..]));
    // `..` stops at the root of a chroot.
    fs.chroot(&root, b"/z").unwrap();
    let cwd = fs.cwd().clone();
    assert!(fs.resolve(&cwd, b"../../..", true).unwrap().same(fs.root()));
    assert_eq!(fs.getcwd().as_deref(), Ok(&b"/"[..]));
}

#[test]
fn symbolic_links() {
    let (fs, root) = setup();
    fs.mkdir(&root, b"/dir", 0o755).unwrap();
    write_file(&fs, &root, b"/dir/file", b"data");
    fs.symlink(b"dir/file", &root, b"/rel").unwrap();
    fs.symlink(b"/dir", &root, b"/abs").unwrap();
    fs.symlink(b"loop2", &root, b"/loop1").unwrap();
    fs.symlink(b"loop1", &root, b"/loop2").unwrap();
    assert_eq!(read_file(&fs, &root, b"/rel").as_deref(), Ok(&b"data"[..]));
    assert_eq!(read_file(&fs, &root, b"/abs/file").as_deref(), Ok(&b"data"[..]));
    assert_eq!(fs.read_link(&root, b"/rel").as_deref(), Ok(&b"dir/file"[..]));
    assert_eq!(fs.read_link(&root, b"/dir").err(), Some(Errno::EINVAL));
    assert_eq!(fs.open(&root, b"/loop1", o::O_RDONLY, 0).err(), Some(Errno::ELOOP));
    let nofollow = o::O_RDONLY | o::O_NOFOLLOW;
    assert_eq!(fs.open(&root, b"/rel", nofollow, 0).err(), Some(Errno::ELOOP));
    assert!(fs.open(&root, b"/rel", nofollow | o::O_PATH, 0).is_ok());
    // A link in the middle of a path is followed, and `..` goes up from the target.
    assert_eq!(read_file(&fs, &root, b"/abs/../dir/file").as_deref(), Ok(&b"data"[..]));
    let at = fs.resolve(&root, b"/abs", false).unwrap();
    assert_eq!(at.inode().metadata().file_type(), Some(FileType::Symlink));
    let at = fs.resolve(&root, b"/abs/", false).unwrap();
    assert!(at.inode().metadata().is_dir());
}

#[test]
fn remove_files_and_directories() {
    let (fs, root) = setup();
    fs.mkdir(&root, b"/d", 0o755).unwrap();
    write_file(&fs, &root, b"/d/f", b"x");
    assert_eq!(fs.remove(&root, b"/d", false).err(), Some(Errno::EISDIR));
    assert_eq!(fs.remove(&root, b"/d/f", true).err(), Some(Errno::ENOTDIR));
    assert_eq!(fs.remove(&root, b"/d", true).err(), Some(Errno::ENOTEMPTY));
    assert_eq!(fs.remove(&root, b"/d/.", true).err(), Some(Errno::EINVAL));
    assert_eq!(fs.remove(&root, b"/d/f/", false).err(), Some(Errno::ENOTDIR));
    // An open file stays usable after its name goes away.
    let f = fs.open(&root, b"/d/f", o::O_RDWR, 0).unwrap();
    fs.remove(&root, b"/d/f", false).unwrap();
    assert_eq!(f.write(b"yz"), Ok(2));
    assert_eq!(f.metadata().map(|m| m.nlink), Ok(0));
    assert_eq!(fs.open(&root, b"/d/f", o::O_RDONLY, 0).err(), Some(Errno::ENOENT));
    assert_eq!(root.inode().metadata().nlink, 3);
    fs.remove(&root, b"/d", true).unwrap();
    assert_eq!(root.inode().metadata().nlink, 2);
}

#[test]
fn hard_links() {
    let (fs, root) = setup();
    write_file(&fs, &root, b"/a", b"same");
    let a = fs.resolve(&root, b"/a", false).unwrap();
    fs.link(&a, &root, b"/b").unwrap();
    assert_eq!(a.inode().metadata().nlink, 2);
    assert_eq!(fs.link(&a, &root, b"/b").err(), Some(Errno::EEXIST));
    fs.remove(&root, b"/a", false).unwrap();
    assert_eq!(read_file(&fs, &root, b"/b").as_deref(), Ok(&b"same"[..]));
    assert_eq!(fs.link(&root, &root, b"/c").err(), Some(Errno::EPERM));
}

#[test]
fn rename_exchange_swaps_the_names() {
    let (fs, root) = setup();
    let exchange = rk_vfs::fs::rename_flags::AT_RENAME_EXCHANGE as u32;
    let noreplace = rk_vfs::fs::rename_flags::AT_RENAME_NOREPLACE as u32;
    fs.mkdir(&root, b"/a", 0o755).unwrap();
    fs.mkdir(&root, b"/a/sub", 0o755).unwrap();
    write_file(&fs, &root, b"/f", b"1");
    write_file(&fs, &root, b"/a/g", b"2");
    fs.rename(&root, b"/f", &root, b"/a/g", exchange).unwrap();
    assert_eq!(read_file(&fs, &root, b"/f").as_deref(), Ok(&b"2"[..]));
    assert_eq!(read_file(&fs, &root, b"/a/g").as_deref(), Ok(&b"1"[..]));
    fs.rename(&root, b"/f", &root, b"/a/sub", exchange).unwrap();
    assert_eq!(read_file(&fs, &root, b"/a/sub").as_deref(), Ok(&b"2"[..]));
    assert_eq!(names(&fs, &root, b"/f"), [&b"."[..], b".."]);
    assert_eq!(fs.rename(&root, b"/f", &root, b"/none", exchange).err(), Some(Errno::ENOENT));
    let both = exchange | noreplace;
    assert_eq!(fs.rename(&root, b"/f", &root, b"/a", both).err(), Some(Errno::EINVAL));
    fs.mkdir(&root, b"/f/in", 0o755).unwrap();
    assert_eq!(fs.rename(&root, b"/f", &root, b"/f/in", exchange).err(), Some(Errno::EINVAL));
    assert_eq!(fs.rename(&root, b"/f/in", &root, b"/f", exchange).err(), Some(Errno::EINVAL));
}

#[test]
fn rename_follows_linux() {
    let (fs, root) = setup();
    fs.mkdir(&root, b"/a", 0o755).unwrap();
    fs.mkdir(&root, b"/a/sub", 0o755).unwrap();
    fs.mkdir(&root, b"/b", 0o755).unwrap();
    write_file(&fs, &root, b"/f", b"1");
    write_file(&fs, &root, b"/g", b"2");
    fs.rename(&root, b"/f", &root, b"/g", 0).unwrap();
    assert_eq!(read_file(&fs, &root, b"/g").as_deref(), Ok(&b"1"[..]));
    assert_eq!(fs.open(&root, b"/f", o::O_RDONLY, 0).err(), Some(Errno::ENOENT));
    assert_eq!(fs.rename(&root, b"/a", &root, b"/a/sub/x", 0).err(), Some(Errno::EINVAL));
    assert_eq!(fs.rename(&root, b"/g", &root, b"/b", 0).err(), Some(Errno::EISDIR));
    assert_eq!(fs.rename(&root, b"/b", &root, b"/g", 0).err(), Some(Errno::ENOTDIR));
    assert_eq!(fs.rename(&root, b"/a", &root, b"/b", 0), Ok(()));
    assert_eq!(fs.rename(&root, b"/b", &root, b"/g", 0).err(), Some(Errno::ENOTDIR));
    assert_eq!(names(&fs, &root, b"/b"), [&b"."[..], b"..", b"sub"]);
    write_file(&fs, &root, b"/h", b"3");
    let noreplace = rk_vfs::fs::rename_flags::AT_RENAME_NOREPLACE as u32;
    assert_eq!(fs.rename(&root, b"/h", &root, b"/g", noreplace).err(), Some(Errno::EEXIST));
    assert_eq!(fs.rename(&root, b"/h", &root, b"/h", 0), Ok(()));
    fs.mkdir(&root, b"/full", 0o755).unwrap();
    write_file(&fs, &root, b"/full/x", b"");
    fs.mkdir(&root, b"/empty", 0o755).unwrap();
    assert_eq!(fs.rename(&root, b"/empty", &root, b"/full", 0).err(), Some(Errno::ENOTEMPTY));
    assert_eq!(fs.rename(&root, b"/full", &root, b"/empty", 0), Ok(()));
    assert_eq!(read_file(&fs, &root, b"/empty/x").as_deref(), Ok(&b""[..]));
}

#[test]
fn mounts() {
    let (mut fs, root) = setup();
    fs.mkdir(&root, b"/mnt", 0o755).unwrap();
    write_file(&fs, &root, b"/mnt/hidden", b"below");
    let tmp = MountSource { source: b"none".to_vec(), fstype: "tmpfs", flags: 0 };
    fs.mount(new(0o1777), &root, b"/mnt", tmp.clone()).unwrap();
    assert_eq!(fs.open(&root, b"/mnt/hidden", o::O_RDONLY, 0).err(), Some(Errno::ENOENT));
    write_file(&fs, &root, b"/mnt/top", b"above");
    fs.mkdir(&root, b"/mnt/d", 0o755).unwrap();
    fs.chdir(&root, b"/mnt/d").unwrap();
    assert_eq!(fs.getcwd().as_deref(), Ok(&b"/mnt/d"[..]));
    let cwd = fs.cwd().clone();
    let up = fs.resolve(&cwd, b"../..", true).unwrap();
    assert!(up.same(&root));
    assert_eq!(fs.rename(&root, b"/mnt/top", &root, b"/top", 0).err(), Some(Errno::EXDEV));
    assert_eq!(fs.remove(&root, b"/mnt", true).err(), Some(Errno::EBUSY));
    let mnt = fs.resolve(&root, b"/mnt", true).unwrap();
    assert_eq!(mnt.inode().metadata().mode, mode::S_IFDIR | 0o1777);
    assert_eq!(mnt.mount.source(), tmp);
    fs.namespace().unmount(&mnt).unwrap();
    assert_eq!(read_file(&fs, &root, b"/mnt/hidden").as_deref(), Ok(&b"below"[..]));
}

#[test]
fn bind_mounts() {
    let (fs, root) = setup();
    fs.mkdir(&root, b"/a", 0o755).unwrap();
    fs.mkdir(&root, b"/b", 0o755).unwrap();
    write_file(&fs, &root, b"/a/f", b"data");
    write_file(&fs, &root, b"/g", b"");
    let a = fs.resolve(&root, b"/a", true).unwrap();
    let b = fs.resolve(&root, b"/b", true).unwrap();
    let g = fs.resolve(&root, b"/g", true).unwrap();
    assert_eq!(fs.namespace().bind(&a, &g).err(), Some(Errno::ENOTDIR));
    let f = fs.resolve(&root, b"/a/f", true).unwrap();
    assert_eq!(fs.namespace().bind(&f, &b).err(), Some(Errno::ENOTDIR));
    fs.namespace().bind(&a, &b).unwrap();
    assert_eq!(read_file(&fs, &root, b"/b/f").as_deref(), Ok(&b"data"[..]));
    let bf = fs.resolve(&root, b"/b/f", true).unwrap();
    assert_eq!(bf.absolute_path(), b"/b/f");
    assert_eq!(root.absolute_path(), b"/");
    assert_eq!(fs.namespace().mounts().len(), 2);
    assert_eq!(fs.namespace().mounts()[1].source(), MountSource::rootfs());
}

#[test]
fn mounts_propagate_to_peers_and_slaves() {
    let (fs, root) = setup();
    let tmp = MountSource { source: b"none".to_vec(), fstype: "tmpfs", flags: 0 };
    fs.mkdir(&root, b"/a", 0o755).unwrap();
    fs.mkdir(&root, b"/b", 0o755).unwrap();
    fs.mount(new(0o755), &root, b"/a", tmp.clone()).unwrap();
    fs.mkdir(&root, b"/a/d", 0o755).unwrap();
    let ns = fs.namespace().clone();
    let a = fs.resolve(&root, b"/a", true).unwrap();
    ns.set_propagation(&a, PropagationType::Shared, false).unwrap();
    let b = fs.resolve(&root, b"/b", true).unwrap();
    let mb = ns.bind(&a, &b).unwrap();
    assert_eq!(mb.propagation(), a.mount.propagation());

    // A mount on a peer shows on the other peer, and an unmount of the copy removes both.
    fs.mount(new(0o755), &root, b"/a/d", tmp.clone()).unwrap();
    write_file(&fs, &root, b"/a/d/x", b"x");
    assert_eq!(read_file(&fs, &root, b"/b/d/x").as_deref(), Ok(&b"x"[..]));
    let bd = fs.resolve(&root, b"/b/d", true).unwrap();
    ns.unmount(&bd).unwrap();
    assert_eq!(read_file(&fs, &root, b"/a/d/x").err(), Some(Errno::ENOENT));
    assert_eq!(ns.mounts().len(), 3);

    // A slave receives the mounts of its master, and sends none.
    let b = fs.resolve(&root, b"/b", true).unwrap();
    ns.set_propagation(&b, PropagationType::Slave, false).unwrap();
    assert_eq!(b.mount.propagation().master, a.mount.propagation().group);
    fs.mount(new(0o755), &root, b"/b/d", tmp.clone()).unwrap();
    write_file(&fs, &root, b"/b/d/y", b"y");
    assert_eq!(read_file(&fs, &root, b"/a/d/y").err(), Some(Errno::ENOENT));
    let bd = fs.resolve(&root, b"/b/d", true).unwrap();
    ns.unmount(&bd).unwrap();
    fs.mount(new(0o755), &root, b"/a/d", tmp).unwrap();
    write_file(&fs, &root, b"/a/d/z", b"z");
    assert_eq!(read_file(&fs, &root, b"/b/d/z").as_deref(), Ok(&b"z"[..]));

    // An unbindable mount cannot be bound, and a private mount has no propagation.
    ns.set_propagation(&a, PropagationType::Unbindable, false).unwrap();
    assert_eq!(ns.bind(&a, &root).err(), Some(Errno::EINVAL));
    ns.set_propagation(&a, PropagationType::Private, false).unwrap();
    assert_eq!(a.mount.propagation(), Propagation::default());
    let d = fs.resolve(&root, b"/a/d", true).unwrap();
    assert_eq!(ns.set_propagation(&d, PropagationType::Shared, true), Ok(()));
    let f = fs.resolve(&root, b"/a/d/z", true).unwrap();
    assert_eq!(ns.set_propagation(&f, PropagationType::Shared, false), Err(Errno::EINVAL));
}

#[test]
fn mount_setattr_changes_the_flags_and_the_propagation() {
    use rk_abi::native::mount::{MS_NOEXEC, MS_NOSUID, MS_RDONLY};
    let (fs, root) = setup();
    let tmp = MountSource { source: b"none".to_vec(), fstype: "tmpfs", flags: 0 };
    fs.mkdir(&root, b"/a", 0o755).unwrap();
    fs.mount(new(0o755), &root, b"/a", tmp.clone()).unwrap();
    fs.mkdir(&root, b"/a/d", 0o755).unwrap();
    fs.mount(new(0o755), &root, b"/a/d", tmp.clone()).unwrap();
    let ns = fs.namespace().clone();
    let a = fs.resolve(&root, b"/a", true).unwrap();
    let d = fs.resolve(&root, b"/a/d", true).unwrap();
    let (ro, nosuid, noexec) = (u64::from(MS_RDONLY), u64::from(MS_NOSUID), u64::from(MS_NOEXEC));

    // Without the recursive flag, only the mount of the path changes.
    let attr = MountAttr { set: ro | nosuid, ..MountAttr::default() };
    ns.set_attr(&a, attr, false).unwrap();
    assert_eq!((a.mount.flags(), d.mount.flags()), (ro | nosuid, 0));

    // The clear applies before the set, and the recursive flag changes the mounts below.
    let attr = MountAttr { clear: ro, set: noexec, propagation: Some(PropagationType::Shared) };
    ns.set_attr(&a, attr, true).unwrap();
    assert_eq!((a.mount.flags(), d.mount.flags()), (nosuid | noexec, noexec));
    assert_ne!(a.mount.propagation().group, 0);
    assert_ne!(d.mount.propagation().group, 0);

    // The path must be the root of a mount of the name space, or of a detached mount.
    fs.mkdir(&root, b"/a/e", 0o755).unwrap();
    let e = fs.resolve(&root, b"/a/e", true).unwrap();
    assert_eq!(ns.set_attr(&e, attr, false), Err(Errno::EINVAL));
    let detached = MountNamespace::clone_tree(&d).unwrap();
    assert!(detached.is_detached());
    let at = Location { dentry: detached.root().clone(), mount: detached.clone() };
    ns.set_attr(&at, MountAttr { set: ro, ..MountAttr::default() }, true).unwrap();
    assert_eq!(detached.flags(), noexec | ro);
    let mut copy = fs.clone();
    copy.unshare_namespace();
    assert!(!d.mount.is_detached());
    assert_eq!(copy.namespace().set_attr(&d, attr, false), Err(Errno::EINVAL));
}

#[test]
fn mount_attr_follows_build_mount_kattr() {
    use rk_abi::native::mount::*;
    let ms = u64::from;
    let ro = ms(MOUNT_ATTR_RDONLY);
    let atime = ms(MOUNT_ATTR__ATIME);
    let attr = MountAttr::from_user(ro, ms(MOUNT_ATTR_NOSUID), ms(MS_SLAVE)).unwrap();
    assert_eq!((attr.set, attr.clear), (ms(MS_RDONLY), ms(MS_NOSUID)));
    assert_eq!(attr.propagation, Some(PropagationType::Slave));

    // An atime value needs all of `MOUNT_ATTR__ATIME` in the clear flags.
    let noatime = ms(MOUNT_ATTR_NOATIME);
    assert_eq!(MountAttr::from_user(noatime, 0, 0), Err(Errno::EINVAL));
    assert_eq!(MountAttr::from_user(noatime, noatime, 0), Err(Errno::EINVAL));
    let attr = MountAttr::from_user(noatime, atime, 0).unwrap();
    assert_eq!(attr.set, ms(MS_NOATIME));
    assert_eq!(attr.clear, ms(MS_RELATIME | MS_NOATIME | MS_STRICTATIME));
    assert_eq!(MountAttr::from_user(0, atime, 0).unwrap().set, ms(MS_RELATIME));
    assert_eq!(MountAttr::from_user(atime, atime, 0), Err(Errno::EINVAL));

    // Unknown flags and more than one propagation type give `EINVAL`.
    assert_eq!(MountAttr::from_user(1 << 40, 0, 0), Err(Errno::EINVAL));
    assert_eq!(MountAttr::from_user(0, 0, ms(MS_SHARED | MS_PRIVATE)), Err(Errno::EINVAL));
    assert_eq!(MountAttr::from_user(0, 0, ms(MS_REC)), Err(Errno::EINVAL));
    let idmap = ms(MOUNT_ATTR_IDMAP);
    assert_eq!(MountAttr::from_user(idmap, 0, 0), Ok(MountAttr::default()));
}

#[test]
fn a_copy_of_the_name_space_has_its_own_mounts() {
    let (fs, root) = setup();
    let tmp = MountSource { source: b"none".to_vec(), fstype: "tmpfs", flags: 0 };
    fs.mkdir(&root, b"/a", 0o755).unwrap();
    let mut copy = fs.clone();
    copy.unshare_namespace();
    let top = copy.root().clone();
    assert!(!top.same(&root));
    assert!(copy.namespace().contains(&top.mount));
    copy.mount(new(0o755), &top, b"/a", tmp).unwrap();
    write_file(&copy, &top, b"/a/f", b"f");
    assert_eq!(read_file(&copy, &top, b"/a/f").as_deref(), Ok(&b"f"[..]));
    assert_eq!(read_file(&fs, &root, b"/a/f").err(), Some(Errno::ENOENT));
    assert_eq!((fs.namespace().mounts().len(), copy.namespace().mounts().len()), (1, 2));
}

#[test]
fn directory_entries() {
    let (fs, root) = setup();
    for name in [&b"/c"[..], b"/a", b"/a-much-longer-name-than-the-buffer-holds"] {
        write_file(&fs, &root, name, b"");
    }
    let got = names(&fs, &root, b"/");
    assert_eq!(got, [&b"."[..], b"..", b"a", b"a-much-longer-name-than-the-buffer-holds", b"c"]);
    let f = fs.open(&root, b"/", o::O_RDONLY, 0).unwrap();
    let mut small = [0u8; 16];
    assert_eq!(f.read_dir(&mut small), Err(Errno::EINVAL));
    assert_eq!(f.read(&mut small), Err(Errno::EISDIR));
}

#[test]
fn the_initramfs_is_unpacked() {
    let (fs, root) = setup();
    let mut w = cpio::Writer::new();
    w.add(b".", mode::S_IFDIR | 0o755, b"");
    w.add(b"bin", mode::S_IFDIR | 0o755, b"");
    w.add(b"bin/busybox", mode::S_IFREG | 0o755, b"\x7fELF");
    w.add(b"bin/sh", mode::S_IFLNK | 0o777, b"busybox");
    w.add(b"dev", mode::S_IFDIR | 0o755, b"");
    w.add_raw(90, b"dev/console", mode::S_IFCHR | 0o600, 1, (5, 1), b"");
    w.add_raw(91, b"etc/a", mode::S_IFREG | 0o644, 2, (0, 0), b"");
    w.add_raw(91, b"etc/b", mode::S_IFREG | 0o644, 2, (0, 0), b"shared");
    let mut image = w.finish();
    // A second archive after zero bytes adds to the first, as Linux reads it.
    image.extend_from_slice(&[0; 8]);
    let mut w = cpio::Writer::new();
    w.add(b"init", mode::S_IFREG | 0o700, b"#!/bin/sh\n");
    image.extend_from_slice(&w.finish());
    fs.mkdir(&root, b"/etc", 0o755).unwrap();
    assert_eq!(cpio::unpack(&fs, &image), Ok(8));
    assert_eq!(read_file(&fs, &root, b"/bin/sh").as_deref(), Ok(&b"\x7fELF"[..]));
    assert_eq!(read_file(&fs, &root, b"/etc/a").as_deref(), Ok(&b"shared"[..]));
    let a = fs.resolve(&root, b"/etc/a", false).unwrap();
    assert_eq!(a.inode().metadata().nlink, 2);
    let console = fs.resolve(&root, b"/dev/console", false).unwrap().inode().metadata();
    assert_eq!((console.mode, console.rdev), (mode::S_IFCHR | 0o600, 0x501));
    let init = fs.resolve(&root, b"/init", false).unwrap().inode().metadata();
    assert_eq!(init.mode, mode::S_IFREG | 0o700);
    // No driver has the console yet.
    assert_eq!(fs.open(&root, b"/dev/console", o::O_RDWR, 0).err(), Some(Errno::ENXIO));
    assert_eq!(cpio::unpack(&fs, b"070701zz"), Err(Errno::EINVAL));
}

#[test]
fn descriptor_table() {
    let (fs, root) = setup();
    let file: Arc<File> = fs.open(&root, b"/", o::O_RDONLY, 0).unwrap();
    let mut t = FdTable::new();
    assert_eq!(t.insert(file.clone(), false), Ok(0));
    assert_eq!(t.insert(file.clone(), true), Ok(1));
    assert_eq!(t.insert(file.clone(), false), Ok(2));
    assert!(t.remove(1).is_ok());
    assert_eq!(t.insert(file.clone(), false), Ok(1));
    assert_eq!(t.insert_from(10, file.clone(), true), Ok(10));
    assert!(t.set(5, file.clone(), false).is_ok_and(|old| old.is_none()));
    assert_eq!(t.close_on_exec().len(), 1);
    assert_eq!(t.get(10).err(), Some(Errno::EBADF));
    assert_eq!(t.get(-1).err(), Some(Errno::EBADF));
    assert_eq!(t.iter().map(|(fd, _)| fd).collect::<Vec<_>>(), [0, 1, 2, 5]);
    assert_eq!(t.remove_range(1, 4).len(), 2);
    assert_eq!(t.iter().map(|(fd, _)| fd).collect::<Vec<_>>(), [0, 5]);
    // The lowest free descriptor comes first after each change.
    assert_eq!(t.insert(file.clone(), false), Ok(1));
    assert_eq!(t.insert_from(3, file.clone(), false), Ok(3));
    assert_eq!(t.insert(file.clone(), false), Ok(2));
    assert_eq!(t.insert(file.clone(), false), Ok(4));
    assert_eq!(t.insert(file.clone(), false), Ok(6));
    assert!(t.remove(0).is_ok());
    assert_eq!(t.insert(file.clone(), false), Ok(0));
    assert_eq!(t.remove_range(2, 3).len(), 2);
    assert_eq!(t.insert(file.clone(), false), Ok(2));
    assert!(t.set_cloexec(1, true).is_ok());
    assert_eq!(t.close_on_exec().len(), 1);
    assert_eq!(t.insert(file.clone(), false), Ok(1));
    assert_eq!(t.insert(file.clone(), false), Ok(3));
}

/// One test, because the locks of all the tests share one table.
#[test]
fn file_locks() {
    use rk_vfs::lock::{self, LockKind, Owner, RecordLock};
    let (fs, root) = setup();
    write_file(&fs, &root, b"/l", b"data");
    let a = fs.open(&root, b"/l", o::O_RDWR, 0).unwrap();
    let b = fs.open(&root, b"/l", o::O_RDWR, 0).unwrap();
    let mut ta = FdTable::new();
    let tb = FdTable::new();
    let rec = |owner: usize, kind, start, end| RecordLock {
        owner: Owner::Posix(owner),
        kind,
        start,
        end,
        pid: 1,
    };
    let w = LockKind::Write;
    let r = LockKind::Read;
    assert_eq!(lock::set(&a, rec(ta.owner(), w, 0, 9), Some(w), false), Ok(()));
    // Another owner conflicts in the range, and not after it.
    assert_eq!(lock::set(&b, rec(tb.owner(), r, 5, 5), Some(r), false), Err(Errno::EAGAIN));
    assert_eq!(lock::set(&b, rec(tb.owner(), w, 10, u64::MAX), Some(w), false), Ok(()));
    let held = lock::test(&b, &rec(tb.owner(), r, 0, 0)).unwrap();
    assert_eq!(held.map(|h| (h.start, h.end)), Some((0, 9)));
    // An unlock in the middle splits the lock.
    assert_eq!(lock::set(&a, rec(ta.owner(), w, 3, 4), None, false), Ok(()));
    assert_eq!(lock::test(&b, &rec(tb.owner(), w, 3, 4)).unwrap(), None);
    assert!(lock::test(&b, &rec(tb.owner(), w, 2, 2)).unwrap().is_some());
    // A close of any descriptor of the file releases the POSIX locks of the table.
    let fd = ta.insert(a.clone(), false).unwrap();
    drop(ta.remove(fd));
    assert_eq!(lock::test(&b, &rec(tb.owner(), w, 0, 9)).unwrap(), None);
    // An OFD lock conflicts with a POSIX lock and goes away with its file.
    let c = fs.open(&root, b"/l", o::O_RDWR, 0).unwrap();
    let ofd = RecordLock { owner: Owner::File(lock::file_id(&c)), ..rec(0, r, 0, 0) };
    assert_eq!(lock::set(&c, ofd, Some(r), false), Ok(()));
    assert_eq!(lock::set(&a, rec(ta.owner(), w, 0, 0), Some(w), false), Err(Errno::EAGAIN));
    drop(c);
    assert_eq!(lock::set(&a, rec(ta.owner(), w, 0, 0), Some(w), false), Ok(()));
    drop(ta);
    drop(tb);
    // `flock` locks do not conflict with record locks, and a shared lock lets other shared locks.
    assert_eq!(lock::flock(&a, Some(r), false), Ok(()));
    assert_eq!(lock::flock(&b, Some(r), false), Ok(()));
    assert_eq!(lock::flock(&b, Some(w), false), Err(Errno::EWOULDBLOCK));
    assert_eq!(lock::flock(&a, None, false), Ok(()));
    assert_eq!(lock::flock(&b, Some(w), false), Ok(()));
    drop(b);
    assert_eq!(lock::flock(&a, Some(w), false), Ok(()));
}

#[test]
fn mount_options() {
    let root =
        mount(&MountArgs { data: b"size=1m,mode=700", dev: None, read_only: false, lookup: None })
            .unwrap();
    assert_eq!(root.metadata().mode, mode::S_IFDIR | 0o700);
    assert_eq!(root.fs_magic(), TMPFS_MAGIC);
    assert_eq!(
        mount(&MountArgs { data: b"", dev: None, read_only: false, lookup: None })
            .unwrap()
            .metadata()
            .mode,
        mode::S_IFDIR | 0o1777
    );
    assert_eq!(
        mount(&MountArgs { data: b"mode=9", dev: None, read_only: false, lookup: None }).err(),
        Some(Errno::EINVAL)
    );
}

#[test]
fn immutable_and_append_only_files() {
    use rk_vfs::inode::iflags;
    let (fs, root) = setup();
    write_file(&fs, &root, b"/i", b"x");
    write_file(&fs, &root, b"/a", b"x");
    let i = fs.resolve(&root, b"/i", true).unwrap();
    let a = fs.resolve(&root, b"/a", true).unwrap();
    assert_eq!(i.inode().set_attr_flags(0x1), Err(Errno::EOPNOTSUPP));
    i.inode().set_attr_flags(iflags::IMMUTABLE).unwrap();
    a.inode().set_attr_flags(iflags::APPEND).unwrap();
    assert_eq!(i.inode().attr_flags(), Ok(iflags::IMMUTABLE));
    assert_eq!(fs.open(&root, b"/i", o::O_WRONLY, 0).err(), Some(Errno::EPERM));
    assert_eq!(fs.remove(&root, b"/i", false), Err(Errno::EPERM));
    assert_eq!(fs.rename(&root, b"/i", &root, b"/j", 0), Err(Errno::EPERM));
    assert_eq!(fs.link(&i, &root, b"/j"), Err(Errno::EPERM));
    let chmod = SetAttr { mode: Some(0o600), ..SetAttr::default() };
    assert_eq!(rk_vfs::inode::check_set_attr(&**i.inode(), &chmod), Err(Errno::EPERM));
    assert_eq!(read_file(&fs, &root, b"/i").as_deref(), Ok(&b"x"[..]));
    assert_eq!(fs.open(&root, b"/a", o::O_WRONLY, 0).err(), Some(Errno::EPERM));
    assert_eq!(
        fs.open(&root, b"/a", o::O_WRONLY | o::O_APPEND | o::O_TRUNC, 0).err(),
        Some(Errno::EPERM)
    );
    let f = fs.open(&root, b"/a", o::O_WRONLY | o::O_APPEND, 0).unwrap();
    assert_eq!(f.write(b"y"), Ok(1));
    assert_eq!(f.truncate(0), Err(Errno::EPERM));
    assert_eq!(fs.remove(&root, b"/a", false), Err(Errno::EPERM));
    a.inode().set_attr_flags(0).unwrap();
    assert_eq!(read_file(&fs, &root, b"/a").as_deref(), Ok(&b"xy"[..]));
    fs.remove(&root, b"/a", false).unwrap();
}

#[test]
fn a_file_handle_opens_the_file_until_it_goes() {
    use rk_vfs::cred::{Cred, cap};
    let (mut fs, root) = setup();
    fs.mkdir(&root, b"/d", 0o755).unwrap();
    write_file(&fs, &root, b"/d/f", b"data");
    let dir = fs.resolve(&root, b"/d", true).unwrap();
    let (ty, fid) = fs.resolve(&root, b"/d/f", true).unwrap().inode().file_handle().unwrap();
    let (dir_ty, dir_fid) = dir.inode().file_handle().unwrap();
    // The handle stays valid after a rename.
    fs.rename(&root, b"/d/f", &root, b"/g", 0).unwrap();
    let at = fs.handle_location(&root, ty, &fid).unwrap();
    let f = fs.open_at(at, o::O_RDONLY).unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(f.read(&mut buf), Ok(4));
    assert_eq!(&buf, b"data");
    // The directory of a handle finds its entries.
    let at = fs.handle_location(&root, dir_ty, &dir_fid).unwrap();
    assert!(at.dentry.lookup(b"g").is_err());
    fs.rename(&root, b"/g", &root, b"/d/g", 0).unwrap();
    assert!(at.dentry.lookup(b"g").is_ok());
    // A handle of the root gives the root of the mount.
    let (root_ty, root_fid) = root.inode().file_handle().unwrap();
    assert!(fs.handle_location(&root, root_ty, &root_fid).unwrap().is_mount_root());
    // An open file without a link stays, and a removed file is stale.
    fs.remove(&root, b"/d/g", false).unwrap();
    assert!(fs.handle_location(&root, ty, &fid).is_ok());
    drop(f);
    assert_eq!(fs.handle_location(&root, ty, &fid).err(), Some(Errno::ESTALE));
    assert_eq!(fs.handle_location(&root, 2, &dir_fid).err(), Some(Errno::ESTALE));
    // The caller must have `CAP_DAC_READ_SEARCH`.
    let all = cap::ALL & !cap::bit(cap::DAC_READ_SEARCH);
    fs.set_cred(Arc::new(Cred::root().capset(all, cap::ALL, 0).unwrap()));
    assert_eq!(fs.handle_location(&root, dir_ty, &dir_fid).err(), Some(Errno::EPERM));
}

/// The calls that the VFS makes to the copies of the pages of a mapped file.
struct Pages(rk_frame::sync::SpinLock<Vec<(u8, u64, u64)>>);

impl rk_vfs::mapped::Mapped for Pages {
    fn wrote(&self, offset: u64, data: &[u8]) {
        self.0.lock().push((b'w', offset, data.len() as u64));
    }

    fn changed(&self, start: u64, end: u64) {
        self.0.lock().push((b'c', start, end));
    }

    fn sync(&self, start: u64, end: u64) -> Result<()> {
        self.0.lock().push((b's', start, end));
        Ok(())
    }
}

#[test]
fn the_pages_of_a_mapped_file_see_each_change() {
    let (fs, root) = setup();
    write_file(&fs, &root, b"/m", b"0123456789");
    let f = fs.open(&root, b"/m", o::O_RDWR, 0).unwrap();
    let pages = Arc::new(Pages(rk_frame::sync::SpinLock::new(Vec::new())));
    let mapped: Arc<dyn rk_vfs::mapped::Mapped> = pages.clone();
    rk_vfs::mapped::register(f.inode().unwrap(), Arc::downgrade(&mapped));
    assert_eq!(f.write_at(2, b"ab"), Ok(2));
    assert_eq!(f.write(b"xyz"), Ok(3));
    let mut buf = [0u8; 4];
    assert_eq!(f.read_at(1, &mut buf), Ok(4));
    assert_eq!(f.truncate(5), Ok(()));
    fs.open(&root, b"/m", o::O_WRONLY | o::O_TRUNC, 0).unwrap();
    assert_eq!(
        *pages.0.lock(),
        [(b'w', 2, 2), (b'w', 0, 3), (b's', 1, 5), (b'c', 5, u64::MAX), (b'c', 0, u64::MAX)]
    );
    // The record goes with the pages.
    drop((mapped, pages));
    assert_eq!(f.write_at(0, b"q"), Ok(1));
}

/// Makes a tmpfs at `/a` with the file `f`, the directory `d` and the link `l`, and gives the
/// root of the mount.
fn mount_at_a(fs: &FsContext, root: &Location) -> Location {
    let tmp = MountSource { source: b"none".to_vec(), fstype: "tmpfs", flags: 0 };
    fs.mkdir(root, b"/a", 0o755).unwrap();
    fs.mount(new(0o755), root, b"/a", tmp).unwrap();
    write_file(fs, root, b"/a/f", b"data");
    fs.mkdir(root, b"/a/d", 0o755).unwrap();
    fs.symlink(b"f", root, b"/a/l").unwrap();
    fs.resolve(root, b"/a", true).unwrap()
}

/// Checks that each change of a name or of the data under `dir` gives `EROFS`, and that the
/// checks that come first in Linux still give their errors.
fn check_read_only(fs: &FsContext, root: &Location, dir: &[u8]) {
    let path = |name: &str| [dir, name.as_bytes()].concat();
    let rofs = Some(Errno::EROFS);
    assert_eq!(fs.open(root, &path("/f"), o::O_WRONLY, 0).err(), rofs);
    assert_eq!(fs.open(root, &path("/f"), o::O_RDONLY | o::O_TRUNC, 0).err(), rofs);
    assert_eq!(fs.open(root, &path("/n"), o::O_RDWR | o::O_CREAT, 0o644).err(), rofs);
    assert_eq!(fs.open(root, &path("/d"), o::O_RDWR | o::O_TMPFILE, 0o644).err(), rofs);
    assert_eq!(fs.mkdir(root, &path("/x"), 0o755).err(), rofs);
    assert_eq!(fs.mknod(root, &path("/x"), mode::S_IFIFO | 0o644, 0).err(), rofs);
    assert_eq!(fs.symlink(b"f", root, &path("/x")).err(), rofs);
    let f = fs.resolve(root, &path("/f"), true).unwrap();
    assert_eq!(fs.link(&f, root, &path("/x")).err(), rofs);
    assert_eq!(fs.remove(root, &path("/f"), false).err(), rofs);
    assert_eq!(fs.remove(root, &path("/missing"), false).err(), rofs);
    assert_eq!(fs.remove(root, &path("/d"), true).err(), rofs);
    assert_eq!(fs.rename(root, &path("/f"), root, &path("/x"), 0).err(), rofs);
    // A name that exists gives `EEXIST` before `EROFS`, as `filename_create` of Linux.
    assert_eq!(fs.mkdir(root, &path("/d"), 0o755).err(), Some(Errno::EEXIST));
    assert_eq!(fs.symlink(b"f", root, &path("/l")).err(), Some(Errno::EEXIST));
    let excl = o::O_RDWR | o::O_CREAT | o::O_EXCL;
    assert_eq!(fs.open(root, &path("/f"), excl, 0o644).err(), Some(Errno::EEXIST));
    // A read and an open of an existing file without a write still work.
    assert_eq!(read_file(fs, root, &path("/f")).as_deref(), Ok(&b"data"[..]));
    assert!(fs.open(root, &path("/f"), o::O_RDONLY | o::O_CREAT, 0o644).is_ok());
    assert_eq!(names(fs, root, dir).len(), 5);
}

#[test]
fn a_read_only_mount_refuses_each_change() {
    use rk_abi::native::mount::MS_RDONLY;
    let (fs, root) = setup();
    let a = mount_at_a(&fs, &root);
    let ro = MountAttr { set: u64::from(MS_RDONLY), ..MountAttr::default() };
    fs.namespace().set_attr(&a, ro, false).unwrap();
    assert!(a.mount.is_read_only());
    assert_eq!(a.mount.want_write(), Err(Errno::EROFS));
    check_read_only(&fs, &root, b"/a");
    // The file system stays writable, and the mount above is not read only.
    assert!(!a.inode().is_read_only());
    write_file(&fs, &root, b"/b", b"b");
    a.mount.set_flags(0).unwrap();
    write_file(&fs, &root, b"/a/f", b"new");
    fs.remove(&root, b"/a/f", false).unwrap();
}

#[test]
fn a_read_only_bind_mount_does_not_change_its_source() {
    use rk_abi::native::mount::MS_RDONLY;
    let (fs, root) = setup();
    mount_at_a(&fs, &root);
    fs.mkdir(&root, b"/m", 0o755).unwrap();
    let a = fs.resolve(&root, b"/a", true).unwrap();
    let m = fs.resolve(&root, b"/m", true).unwrap();
    let bind = fs.namespace().bind(&a, &m).unwrap();
    bind.set_flags(u64::from(MS_RDONLY)).unwrap();
    check_read_only(&fs, &root, b"/m");
    write_file(&fs, &root, b"/a/f", b"new");
    assert_eq!(read_file(&fs, &root, b"/m/f").as_deref(), Ok(&b"new"[..]));
    // A file that is open for a write through the source does not stop the bind mount.
    let _w = fs.open(&root, b"/a/f", o::O_WRONLY, 0).unwrap();
    bind.set_flags(0).unwrap();
    bind.set_flags(u64::from(MS_RDONLY)).unwrap();
}

#[test]
fn a_mount_with_a_file_open_for_a_write_does_not_become_read_only() {
    use rk_abi::native::mount::MS_RDONLY;
    let (fs, root) = setup();
    let a = mount_at_a(&fs, &root);
    let ro = u64::from(MS_RDONLY);
    let w = fs.open(&root, b"/a/f", o::O_RDWR, 0).unwrap();
    assert!(a.mount.has_writers());
    assert!(rk_vfs::dentry::fs_has_writers(a.inode()));
    assert_eq!(a.mount.set_flags(ro), Err(Errno::EBUSY));
    let attr = MountAttr { set: ro, ..MountAttr::default() };
    assert_eq!(fs.namespace().set_attr(&root, attr, true), Err(Errno::EBUSY));
    assert_eq!(root.mount.flags(), 0);
    // A file for a read, a directory and an `O_PATH` file are not writers.
    let _r = fs.open(&root, b"/a/f", o::O_RDONLY, 0).unwrap();
    let _p = fs.open(&root, b"/a/f", o::O_PATH | o::O_RDWR, 0).unwrap();
    let _d = fs.open(&root, b"/a/d", o::O_RDONLY | o::O_DIRECTORY, 0).unwrap();
    drop(w);
    assert!(!a.mount.has_writers());
    assert!(!rk_vfs::dentry::fs_has_writers(a.inode()));
    a.mount.set_flags(ro).unwrap();
    // A read only mount stays read only without writers.
    a.mount.set_flags(ro).unwrap();
}

#[test]
fn a_read_only_tmpfs_refuses_each_change() {
    let (fs, root) = setup();
    let a = mount_at_a(&fs, &root);
    let f = fs.resolve(&root, b"/a/f", true).unwrap().inode().clone();
    let atime = f.metadata().atime;
    a.inode().set_read_only(true).unwrap();
    assert!(f.is_read_only());
    assert!(a.mount.is_read_only());
    check_read_only(&fs, &root, b"/a");
    let rofs = Err(Errno::EROFS);
    assert_eq!(f.write_at(0, b"x"), rofs.map(|()| 0));
    assert_eq!(f.set_attr(&SetAttr { mode: Some(0o600), ..SetAttr::default() }), rofs);
    assert_eq!(f.set_attr_flags(0), rofs);
    assert_eq!(f.fallocate(0, 0, 8), rofs);
    assert_eq!(f.set_xattr(b"user.a", b"v", 0), rofs);
    assert_eq!(f.remove_xattr(b"user.a"), rofs);
    let d = a.inode();
    assert_eq!(d.create(b"n", FileType::Regular, 0o644, 0).err(), rofs.err());
    assert_eq!(d.tmpfile(0o644).err(), rofs.err());
    assert_eq!(d.unlink(b"f"), rofs);
    assert_eq!(d.rmdir(b"d"), rofs);
    assert_eq!(d.rename(b"f", d, b"g"), rofs);
    assert_eq!(d.exchange(b"f", d, b"d"), rofs);
    f.set_atime(Timespec { sec: atime.sec + 100, nsec: 0 }).unwrap();
    assert_eq!(f.metadata().atime, atime);
    // A remount for writes makes the file system writable again.
    a.inode().set_read_only(false).unwrap();
    assert!(!a.mount.is_read_only());
    write_file(&fs, &root, b"/a/f", b"new");
    fs.remove(&root, b"/a/f", false).unwrap();
}

#[test]
fn a_read_only_mount_of_tmpfs_is_read_only() {
    let args = MountArgs { data: b"", dev: None, read_only: true, lookup: None };
    let root = mount(&args).unwrap();
    assert!(root.is_read_only());
    assert_eq!(root.create(b"n", FileType::Regular, 0o644, 0).err(), Some(Errno::EROFS));
    root.set_read_only(false).unwrap();
    assert!(root.create(b"n", FileType::Regular, 0o644, 0).is_ok());
}

#[test]
fn an_open_with_o_trunc_clears_the_set_id_bits() {
    use rk_vfs::cred::Cred;
    let (mut fs, root) = setup();
    write_file(&fs, &root, b"/f", b"data");
    let at = fs.resolve(&root, b"/f", true).unwrap();
    at.inode().set_attr(&SetAttr { mode: Some(0o6777), ..SetAttr::default() }).unwrap();
    let user = Cred::root().setresgid(1000, 1000, 1000).unwrap();
    fs.set_cred(Arc::new(user.setresuid(1000, 1000, 1000).unwrap()));
    // An open without `O_TRUNC` keeps the bits.
    fs.open(&root, b"/f", o::O_WRONLY, 0).unwrap();
    assert_eq!(at.inode().metadata().mode & 0o7777, 0o6777);
    fs.open(&root, b"/f", o::O_WRONLY | o::O_TRUNC, 0).unwrap();
    assert_eq!(at.inode().metadata().mode & 0o7777, 0o777);
    assert_eq!(at.inode().metadata().size, 0);
}
