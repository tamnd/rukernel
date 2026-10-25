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
    assert!(is_opaque(&upper.lookup(b"d").unwrap()));
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
