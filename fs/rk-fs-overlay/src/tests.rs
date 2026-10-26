//! The tests of overlayfs, with tmpfs layers.

use super::*;
use alloc::vec;

/// Makes a file with `data` in the directory `dir`.
fn file(dir: &InodeRef, name: &[u8], data: &[u8]) -> InodeRef {
    let f = dir.create(name, FileType::Regular, 0o644, 0).unwrap();
    f.write_at(0, data).unwrap();
    f
}

fn read(inode: &InodeRef) -> Vec<u8> {
    let mut buf = vec![0u8; 256];
    let n = inode.read_at(0, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

fn names(dir: &InodeRef) -> Vec<Vec<u8>> {
    real_entries(dir).unwrap().into_iter().map(|e| e.name).collect()
}

/// Gives a lower and an upper tmpfs and the overlay of them. The lower directory has the file
/// `a`, the directory `d` with the file `d/x`, and the file `b`.
fn setup() -> (InodeRef, InodeRef, InodeRef) {
    let lower = rk_fs_tmpfs::new(0o755);
    let upper = rk_fs_tmpfs::new(0o755);
    file(&lower, b"a", b"lower a");
    file(&lower, b"b", b"lower b");
    let d = lower.create(b"d", FileType::Directory, 0o755, 0).unwrap();
    file(&d, b"x", b"lower x");
    let root = new(vec![lower.clone()], Some(upper.clone())).unwrap();
    (lower, upper, root)
}

#[test]
fn the_upper_layer_hides_the_lower_layer() {
    let (_, upper, root) = setup();
    file(&upper, b"b", b"upper b");
    file(&upper, b"c", b"upper c");
    assert_eq!(read(&root.lookup(b"a").unwrap()), b"lower a");
    assert_eq!(read(&root.lookup(b"b").unwrap()), b"upper b");
    assert_eq!(names(&root), [&b"a"[..], b"b", b"c", b"d"]);
    assert_eq!(root.lookup(b"e").err(), Some(Errno::ENOENT));
    assert_eq!(root.fs_magic(), OVERLAYFS_SUPER_MAGIC);
}

#[test]
fn directories_of_two_layers_are_joined() {
    let (_, upper, root) = setup();
    let d = upper.create(b"d", FileType::Directory, 0o755, 0).unwrap();
    file(&d, b"y", b"upper y");
    let d = root.lookup(b"d").unwrap();
    assert_eq!(names(&d), [&b"x"[..], b"y"]);
    assert_eq!(d.metadata().dev, root.metadata().dev);
}

#[test]
fn a_write_copies_the_file_up() {
    let (lower, upper, root) = setup();
    let a = root.lookup(b"a").unwrap();
    a.write_at(0, b"LOWER").unwrap();
    assert_eq!(read(&a), b"LOWER a");
    assert_eq!(read(&lower.lookup(b"a").unwrap()), b"lower a");
    assert_eq!(read(&upper.lookup(b"a").unwrap()), b"LOWER a");
    // The copy up of a file in a directory copies the directory first.
    root.lookup(b"d")
        .unwrap()
        .lookup(b"x")
        .unwrap()
        .set_attr(&SetAttr { mode: Some(0o600), ..SetAttr::default() })
        .unwrap();
    let x = upper.lookup(b"d").unwrap().lookup(b"x").unwrap();
    assert_eq!(x.metadata().mode & mode::PERM_MASK, 0o600);
    assert_eq!(read(&x), b"lower x");
}

#[test]
fn a_removal_makes_a_whiteout() {
    let (lower, upper, root) = setup();
    root.unlink(b"a").unwrap();
    assert_eq!(root.lookup(b"a").err(), Some(Errno::ENOENT));
    assert!(is_whiteout(&upper.lookup(b"a").unwrap()));
    assert!(lower.lookup(b"a").is_ok());
    assert_eq!(names(&root), [&b"b"[..], b"d"]);
    // A new file takes the place of the whiteout, and a second removal makes it again.
    file(&root, b"a", b"new a");
    assert_eq!(read(&root.lookup(b"a").unwrap()), b"new a");
    root.unlink(b"a").unwrap();
    assert_eq!(root.lookup(b"a").err(), Some(Errno::ENOENT));
}

#[test]
fn a_new_directory_over_a_removed_one_is_opaque() {
    let (_, upper, root) = setup();
    let d = root.lookup(b"d").unwrap();
    assert_eq!(root.rmdir(b"d").err(), Some(Errno::ENOTEMPTY));
    d.unlink(b"x").unwrap();
    root.rmdir(b"d").unwrap();
    assert_eq!(root.lookup(b"d").err(), Some(Errno::ENOENT));
    let d = root.create(b"d", FileType::Directory, 0o755, 0).unwrap();
    assert!(names(&d).is_empty());
    let opaque = upper.lookup(b"d").unwrap().get_xattr(b"trusted.overlay.opaque");
    assert_eq!(opaque.as_deref(), Ok(&b"y"[..]));
    assert_eq!(d.list_xattr(), Ok(Vec::new()));
}

#[test]
fn a_rename_of_a_lower_file_moves_the_copy() {
    let (lower, _, root) = setup();
    root.rename(b"a", &root, b"c").unwrap();
    assert_eq!(read(&root.lookup(b"c").unwrap()), b"lower a");
    assert_eq!(root.lookup(b"a").err(), Some(Errno::ENOENT));
    assert!(lower.lookup(b"a").is_ok());
    // A lower directory cannot move, so `mv` copies it.
    assert_eq!(root.rename(b"d", &root, b"e").err(), Some(Errno::EXDEV));
}

#[test]
fn a_mount_without_an_upper_layer_is_read_only() {
    let (lower, _, _) = setup();
    let root = new(vec![lower], None).unwrap();
    assert_eq!(read(&root.lookup(b"a").unwrap()), b"lower a");
    assert_eq!(root.lookup(b"a").unwrap().write_at(0, b"x").err(), Some(Errno::EROFS));
    assert_eq!(root.unlink(b"a").err(), Some(Errno::EROFS));
    assert_eq!(root.create(b"n", FileType::Regular, 0o644, 0).err(), Some(Errno::EROFS));
}

#[test]
fn layers_below_a_file_are_hidden() {
    let top = rk_fs_tmpfs::new(0o755);
    let bottom = rk_fs_tmpfs::new(0o755);
    file(&top, b"d", b"a file");
    let d = bottom.create(b"d", FileType::Directory, 0o755, 0).unwrap();
    file(&d, b"x", b"");
    let root = new(vec![top, bottom], None).unwrap();
    assert_eq!(read(&root.lookup(b"d").unwrap()), b"a file");
}

#[test]
fn the_mount_options_are_checked() {
    let lower = rk_fs_tmpfs::new(0o755);
    let lookup = |_: &[u8]| Ok(lower.clone());
    let args = |data| MountArgs { data, dev: None, read_only: false, lookup: Some(&lookup) };
    assert!(mount(&args(b"lowerdir=/l")).is_ok());
    assert!(mount(&args(b"lowerdir=/l:/m,upperdir=/u,workdir=/w")).is_ok());
    assert_eq!(mount(&args(b"upperdir=/u,workdir=/w")).err(), Some(Errno::EINVAL));
    assert_eq!(mount(&args(b"lowerdir=/l,upperdir=/u")).err(), Some(Errno::EINVAL));
    assert_eq!(mount(&args(b"lowerdir=/l::/m")).err(), Some(Errno::EINVAL));
}

/// Gives a mount of `data`, where each path is a directory of a tmpfs, the same for each path.
fn mount_on(dir: &InodeRef, data: &[u8]) -> Result<InodeRef> {
    let lookup = |_: &[u8]| Ok(dir.clone());
    mount(&MountArgs { data, dev: None, read_only: false, lookup: Some(&lookup) })
}

#[test]
fn the_options_can_have_escaped_commas_and_colons() {
    let opts = Options::parse(br"lowerdir=/a\:b:/c\,d,upperdir=/u x,workdir=/w,index=off").unwrap();
    assert_eq!(opts.lowers, [&b"/a:b"[..], b"/c,d"]);
    assert_eq!(opts.upper.as_deref(), Some(&b"/u x"[..]));
    assert!(!opts.userxattr);
    assert_eq!(opts.show(), br",lowerdir=/a\072b:/c\054d,upperdir=/u\040x,workdir=/w");
    assert!(Options::parse(b"lowerdir=/l,userxattr").unwrap().userxattr);
}

#[test]
fn the_mount_makes_a_clean_work_directory() {
    let dir = rk_fs_tmpfs::new(0o755);
    let old = dir.create(WORK, FileType::Directory, 0o755, 0).unwrap();
    old.create(b"foo", FileType::Directory, 0o755, 0).unwrap();
    let root = mount_on(&dir, b"lowerdir=/l,upperdir=/u,workdir=/w").unwrap();
    let work = dir.lookup(WORK).unwrap();
    assert!(names(&work).is_empty());
    assert_eq!(work.metadata().mode & mode::PERM_MASK, 0);
    assert!(!root.is_read_only());
    assert_eq!(root.fs_options(), b",lowerdir=/l,upperdir=/u,workdir=/w");
    root.set_read_only(true).unwrap();
    assert!(root.is_read_only());
    root.set_read_only(false).unwrap();
}

#[test]
fn a_mount_without_a_work_directory_is_read_only() {
    let dir = rk_fs_tmpfs::new(0o755);
    dir.set_attr_flags(iflags::IMMUTABLE).unwrap();
    let root = mount_on(&dir, b"lowerdir=/l,upperdir=/u,workdir=/w").unwrap();
    assert!(root.is_read_only());
    assert_eq!(root.set_read_only(false), Err(Errno::EROFS));
    assert_eq!(root.create(b"n", FileType::Regular, 0o644, 0).err(), Some(Errno::EROFS));
    assert!(mount_on(&dir, b"lowerdir=/l").unwrap().is_read_only());
}

#[test]
fn the_upper_directory_cannot_be_on_overlayfs() {
    let (_, _, root) = setup();
    let data = b"lowerdir=/l,upperdir=/u,workdir=/w";
    assert_eq!(mount_on(&root, data).err(), Some(Errno::EINVAL));
    assert!(mount_on(&root, b"lowerdir=/l").is_ok());
}

#[test]
fn the_attributes_of_overlayfs_are_escaped() {
    let (_, upper, root) = setup();
    let c = root.create(b"c", FileType::Regular, 0o644, 0).unwrap();
    c.set_xattr(b"trusted.overlay.opaque", b"y", 0).unwrap();
    let real = upper.lookup(b"c").unwrap();
    assert_eq!(real.get_xattr(b"trusted.overlay.overlay.opaque").as_deref(), Ok(&b"y"[..]));
    assert_eq!(real.get_xattr(b"trusted.overlay.opaque").err(), Some(Errno::ENODATA));
    assert_eq!(c.get_xattr(b"trusted.overlay.opaque").as_deref(), Ok(&b"y"[..]));
    real.set_xattr(b"trusted.overlay.origin", b"o", 0).unwrap();
    assert_eq!(c.list_xattr(), Ok(vec![b"trusted.overlay.opaque".to_vec()]));
}

#[test]
fn a_regular_file_can_be_a_whiteout() {
    let top = rk_fs_tmpfs::new(0o755);
    let bottom = rk_fs_tmpfs::new(0o755);
    file(&bottom, b"hidden", b"x");
    file(&bottom, b"regular", b"x");
    let w = file(&top, b"hidden", b"");
    w.set_xattr(b"user.overlay.whiteout", b"y", 0).unwrap();
    top.set_xattr(b"user.overlay.opaque", b"x", 0).unwrap();
    // The attributes have the prefix `trusted.overlay.` without the option `userxattr`.
    let root = new(vec![top.clone(), bottom.clone()], None).unwrap();
    assert_eq!(names(&root), [&b"hidden"[..], b"regular"]);
    let lookup = |path: &[u8]| Ok(if path == b"/t" { top.clone() } else { bottom.clone() });
    let data = b"lowerdir=/t:/b,userxattr";
    let root = mount(&MountArgs { data, dev: None, read_only: false, lookup: Some(&lookup) });
    let root = root.unwrap();
    assert_eq!(names(&root), [&b"regular"[..]]);
    assert_eq!(root.lookup(b"hidden").err(), Some(Errno::ENOENT));
}

#[test]
fn a_copy_up_keeps_the_inode_number_and_the_flags() {
    let (lower, upper, root) = setup();
    let a = root.lookup(b"a").unwrap();
    let ino = a.metadata().ino;
    lower.lookup(b"a").unwrap().set_attr_flags(iflags::APPEND | iflags::NOATIME).unwrap();
    a.set_xattr(b"user.x", b"1", 0).unwrap();
    assert_eq!(a.metadata().ino, ino);
    let real = upper.lookup(b"a").unwrap();
    // The upper inode does not get the append-only flag, so the mount can change it.
    assert_eq!(real.attr_flags(), Ok(iflags::NOATIME));
    assert_eq!(real.get_xattr(b"trusted.overlay.protattr").as_deref(), Ok(&b"a"[..]));
    assert_eq!(a.attr_flags(), Ok(iflags::APPEND | iflags::NOATIME));
    a.set_attr_flags(iflags::IMMUTABLE).unwrap();
    assert_eq!(real.attr_flags(), Ok(0));
    assert_eq!(a.attr_flags(), Ok(iflags::IMMUTABLE));
    a.set_attr_flags(0).unwrap();
    assert_eq!(real.get_xattr(b"trusted.overlay.protattr").err(), Some(Errno::ENODATA));
}

/// Gives the node of the overlay inode `inode`.
fn node(inode: &InodeRef) -> &Node {
    let any: &dyn Any = &**inode;
    any.downcast_ref::<Node>().unwrap()
}

#[test]
fn a_removal_after_a_change_of_the_upper_file_gives_estale() {
    let (lower, upper, root) = setup();
    lower.create(b"t", FileType::Directory, 0o755, 0).unwrap();
    root.rmdir(b"t").unwrap();
    drop(root.create(b"t", FileType::Regular, 0o644, 0).unwrap());
    // The unused node keeps the upper file, so the lower directory does not show again.
    upper.unlink(b"t").unwrap();
    assert!(!root.lookup(b"t").unwrap().metadata().is_dir());
    assert_eq!(root.unlink(b"t"), Err(Errno::ESTALE));
    // A new upper file is also a change.
    lower.create(b"e", FileType::Directory, 0o755, 0).unwrap();
    drop(root.lookup(b"e").unwrap());
    upper.create(b"e", FileType::Directory, 0o755, 0).unwrap();
    assert_eq!(root.rmdir(b"e"), Err(Errno::ESTALE));
    // A removal through the mount stays correct.
    root.unlink(b"a").unwrap();
    assert_eq!(root.lookup(b"a").err(), Some(Errno::ENOENT));
}

#[test]
fn an_unused_node_stays_until_an_eviction() {
    let (_, _, root) = setup();
    for i in 0..10u8 {
        drop(file(&root, &[b'f', b'0' + i], b""));
    }
    let fs = &node(&root).fs;
    assert_eq!(fs.cache.count.load(Ordering::Relaxed), 10);
    let ino = root.lookup(b"f9").unwrap().metadata().ino;
    assert_eq!(root.lookup(b"f9").unwrap().metadata().ino, ino);
    fs.cache.shrink(3);
    assert_eq!(fs.cache.count.load(Ordering::Relaxed), 3);
    let kept: Vec<_> = node(&root).unused.lock().keys().cloned().collect();
    assert_eq!(kept, [&b"f7"[..], b"f8", b"f9"]);
    // An evicted name is found again in the layers.
    assert_eq!(root.lookup(b"f0").unwrap().metadata().size, 0);
}

#[test]
fn an_unused_directory_keeps_its_unused_children() {
    let (_, upper, root) = setup();
    let d = root.lookup(b"d").unwrap();
    drop(file(&d, b"n", b"new"));
    drop(d);
    let n = Arc::downgrade(&upper.lookup(b"d").unwrap().lookup(b"n").unwrap());
    upper.lookup(b"d").unwrap().unlink(b"n").unwrap();
    // The unused node of `d/n` keeps the upper file.
    assert!(n.strong_count() > 0);
    assert_eq!(root.lookup(b"d").unwrap().unlink(b"n"), Err(Errno::ESTALE));
    // The mount does not keep its unused nodes after the last use of its root.
    drop(root);
    assert_eq!(n.strong_count(), 0);
}
