//! The tests of tmpfs and of the VFS on tmpfs.

use super::*;
use alloc::vec;
use rk_abi::native::open as o;
use rk_vfs::cpio;
use rk_vfs::{FdTable, File, FsContext, Location, MountNamespace, MountSource, Whence};

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
}

#[test]
fn mount_options() {
    let root = mount(b"size=1m,mode=700").unwrap();
    assert_eq!(root.metadata().mode, mode::S_IFDIR | 0o700);
    assert_eq!(root.fs_magic(), TMPFS_MAGIC);
    assert_eq!(mount(b"").unwrap().metadata().mode, mode::S_IFDIR | 0o1777);
    assert_eq!(mount(b"mode=9").err(), Some(Errno::EINVAL));
}
