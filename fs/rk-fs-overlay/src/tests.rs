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
    assert!(mount(&args(b"lowerdir=/l::/m")).is_ok());
    assert_eq!(mount(&args(b"lowerdir=::/m")).err(), Some(Errno::EINVAL));
    assert_eq!(mount(&args(b"lowerdir=/l::/m:/n")).err(), Some(Errno::EINVAL));
    assert_eq!(mount(&args(b"lowerdir=/l,redirect_dir=bad")).err(), Some(Errno::EINVAL));
    let data = b"lowerdir=/l,upperdir=/u,workdir=/w,redirect_dir=follow,metacopy=on";
    assert_eq!(mount(&args(data)).err(), Some(Errno::EINVAL));
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
    // The first mount of a new overlay makes a uuid.
    assert_eq!(root.fs_options(), b",lowerdir=/l,upperdir=/u,workdir=/w,uuid=on");
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

/// Gives a mount of `data`, where `/l` is `lower`, `/u` is `upper`, `/w` is `work`, and another
/// path is `data`.
fn mount_layers(dirs: [&InodeRef; 4], data: &[u8]) -> Result<InodeRef> {
    let [lower, upper, work, other] = dirs;
    let lookup = |path: &[u8]| {
        Ok(match path {
            b"/l" => lower.clone(),
            b"/u" => upper.clone(),
            b"/w" => work.clone(),
            _ => other.clone(),
        })
    };
    mount(&MountArgs { data, dev: None, read_only: false, lookup: Some(&lookup) })
}

/// Gives a lower directory, an upper directory, a work directory and a data directory. The
/// upper and the work directories are on one tmpfs. The lower directory has the file `a`, the
/// directory `d` with the file `d/x`, and the file `b`.
fn layers() -> [InodeRef; 4] {
    let (lower, _, _) = setup();
    let fs = rk_fs_tmpfs::new(0o755);
    let upper = fs.create(b"u", FileType::Directory, 0o755, 0).unwrap();
    let work = fs.create(b"w", FileType::Directory, 0o755, 0).unwrap();
    [lower, upper, work, rk_fs_tmpfs::new(0o755)]
}

#[test]
fn a_rename_of_a_merged_directory_sets_a_redirect() {
    let [lower, upper, work, data] = layers();
    let dirs = [&lower, &upper, &work, &data];
    let root = mount_layers(dirs, b"lowerdir=/l,upperdir=/u,workdir=/w").unwrap();
    assert_eq!(root.rename(b"d", &root, b"e").err(), Some(Errno::EXDEV));
    drop(root);
    let opts = b"lowerdir=/l,upperdir=/u,workdir=/w,redirect_dir=on";
    let root = mount_layers(dirs, opts).unwrap();
    let ino = root.lookup(b"d").unwrap().metadata().ino;
    root.rename(b"d", &root, b"e").unwrap();
    let redirect = upper.lookup(b"e").unwrap().get_xattr(b"trusted.overlay.redirect");
    assert_eq!(redirect.as_deref(), Ok(&b"d"[..]));
    assert_eq!(root.lookup(b"d").err(), Some(Errno::ENOENT));
    assert_eq!(read(&root.lookup(b"e").unwrap().lookup(b"x").unwrap()), b"lower x");
    // A new directory in a merged directory is opaque with the feature.
    let f = root.create(b"f", FileType::Directory, 0o755, 0).unwrap();
    let opaque = upper.lookup(b"f").unwrap().get_xattr(b"trusted.overlay.opaque");
    assert_eq!(opaque.as_deref(), Ok(&b"y"[..]));
    // A move to another directory gets an absolute redirect.
    root.rename(b"e", &f, b"g").unwrap();
    let g = upper.lookup(b"f").unwrap().lookup(b"g").unwrap();
    assert_eq!(g.get_xattr(b"trusted.overlay.redirect").as_deref(), Ok(&b"/d"[..]));
    drop((f, root));
    // A new mount follows the redirects and keeps the inode number.
    let root = mount_layers(dirs, opts).unwrap();
    let g = root.lookup(b"f").unwrap().lookup(b"g").unwrap();
    assert_eq!(names(&g), [&b"x"[..]]);
    assert_eq!(read(&g.lookup(b"x").unwrap()), b"lower x");
    assert_eq!(g.metadata().ino, ino);
    assert_eq!(root.lookup(b"d").err(), Some(Errno::ENOENT));
    // A mount with `redirect_dir=nofollow` refuses the redirect below a merged directory.
    drop((g, root));
    root_redirect(&upper);
    let opts = b"lowerdir=/l,upperdir=/u,workdir=/w,redirect_dir=nofollow";
    let root = mount_layers(dirs, opts).unwrap();
    assert_eq!(root.lookup(b"h").err(), Some(Errno::EPERM));
}

/// Makes the directory `h` with a redirect to `d` in the upper root `upper`.
fn root_redirect(upper: &InodeRef) {
    let h = upper.create(b"h", FileType::Directory, 0o755, 0).unwrap();
    h.set_xattr(b"trusted.overlay.redirect", b"d", 0).unwrap();
}

#[test]
fn an_absolute_redirect_below_an_opaque_directory_is_followed() {
    let [lower, upper, _, _] = layers();
    let mid = upper.create(b"m", FileType::Directory, 0o755, 0).unwrap();
    let o = mid.create(b"o", FileType::Directory, 0o755, 0).unwrap();
    o.set_xattr(b"trusted.overlay.opaque", b"y", 0).unwrap();
    let r = o.create(b"r", FileType::Directory, 0o755, 0).unwrap();
    r.set_xattr(b"trusted.overlay.redirect", b"/d", 0).unwrap();
    let lookup = |path: &[u8]| Ok(if path == b"/m" { upper.clone() } else { lower.clone() });
    let data = b"lowerdir=/m:/l,redirect_dir=follow";
    let root = mount(&MountArgs { data, dev: None, read_only: false, lookup: Some(&lookup) });
    let r = root.unwrap().lookup(b"m").unwrap().lookup(b"o").unwrap().lookup(b"r").unwrap();
    assert_eq!(names(&r), [&b"x"[..]]);
}

#[test]
fn a_metacopy_copy_up_copies_the_data_later() {
    let [lower, upper, work, data] = layers();
    let dirs = [&lower, &upper, &work, &data];
    let opts = b"lowerdir=/l,upperdir=/u,workdir=/w,metacopy=on";
    let root = mount_layers(dirs, opts).unwrap();
    let want = b",lowerdir=/l,upperdir=/u,workdir=/w,redirect_dir=on,uuid=on,metacopy=on";
    assert_eq!(root.fs_options(), want);
    let a = root.lookup(b"a").unwrap();
    let ino = a.metadata().ino;
    a.set_attr(&SetAttr { mode: Some(0o600), ..SetAttr::default() }).unwrap();
    let real = upper.lookup(b"a").unwrap();
    assert_eq!(real.get_xattr(b"trusted.overlay.metacopy").as_deref(), Ok(&b""[..]));
    assert!(real.get_xattr(b"trusted.overlay.origin").is_ok());
    assert!(upper.get_xattr(b"trusted.overlay.impure").is_ok());
    assert_eq!(real.metadata().size, 7);
    assert_eq!(read(&real), [0; 7]);
    assert_eq!(read(&a), b"lower a");
    assert_eq!(a.list_xattr(), Ok(Vec::new()));
    drop((a, root));
    // A new mount finds the data in the lower layer.
    let root = mount_layers(dirs, opts).unwrap();
    let a = root.lookup(b"a").unwrap();
    assert_eq!(read(&a), b"lower a");
    assert_eq!(a.metadata().ino, ino);
    a.write_at(0, b"L").unwrap();
    assert_eq!(read(&real), b"Lower a");
    assert_eq!(real.get_xattr(b"trusted.overlay.metacopy").err(), Some(Errno::ENODATA));
    // A metacopy file moves with a redirect.
    let chmod = SetAttr { mode: Some(0o600), ..SetAttr::default() };
    root.lookup(b"b").unwrap().set_attr(&chmod).unwrap();
    let d = root.lookup(b"d").unwrap();
    root.rename(b"b", &d, b"c").unwrap();
    let c = upper.lookup(b"d").unwrap().lookup(b"c").unwrap();
    assert_eq!(c.get_xattr(b"trusted.overlay.redirect").as_deref(), Ok(&b"/b"[..]));
    drop((a, d, root));
    let root = mount_layers(dirs, opts).unwrap();
    assert_eq!(read(&root.lookup(b"d").unwrap().lookup(b"c").unwrap()), b"lower b");
}

#[test]
fn a_metacopy_file_finds_its_data_in_a_data_only_layer() {
    let [lower, _, work, data] = layers();
    let sub = data.create(b"sub", FileType::Directory, 0o755, 0).unwrap();
    file(&sub, b"f", b"data");
    for (name, redirect) in [(&b"m"[..], &b"/sub/f"[..]), (b"rel", b"f"), (b"lazy", b"/sub/g")] {
        let m = file(&lower, name, b"");
        m.set_attr(&SetAttr { size: Some(4), ..SetAttr::default() }).unwrap();
        m.set_xattr(b"trusted.overlay.metacopy", b"", 0).unwrap();
        m.set_xattr(b"trusted.overlay.redirect", redirect, 0).unwrap();
    }
    file(&lower, b"plain", b"").set_xattr(b"trusted.overlay.metacopy", b"", 0).unwrap();
    let dirs = [&lower, &work, &work, &data];
    // Without `metacopy=on`, the lookup does not follow the metacopy file.
    let root = mount_layers(dirs, b"lowerdir=/l::/d").unwrap();
    assert_eq!(root.lookup(b"m").err(), Some(Errno::EIO));
    let root = mount_layers(dirs, b"lowerdir=/l::/d,metacopy=on").unwrap();
    let m = root.lookup(b"m").unwrap();
    assert_eq!(read(&m), b"data");
    assert_eq!(m.metadata().size, 4);
    assert_eq!(root.lookup(b"rel").err(), Some(Errno::EIO));
    assert_eq!(root.lookup(b"plain").err(), Some(Errno::EIO));
    // A file without its data has the attributes but no data.
    let lazy = root.lookup(b"lazy").unwrap();
    assert_eq!(lazy.metadata().size, 4);
    assert_eq!(lazy.read_at(0, &mut [0; 4]), Err(Errno::ENOENT));
    // The data-only layers do not show their names.
    assert_eq!(root.lookup(b"sub").err(), Some(Errno::ENOENT));
}

#[test]
fn the_added_layers_are_checked() {
    let data = b"lowerdir+=/a b,lowerdir+=/c:d,datadir+=/e,redirect_dir=follow";
    let opts = Options::parse(data).unwrap();
    assert_eq!(opts.lowers, [&b"/a b"[..], b"/c:d"]);
    assert_eq!(opts.data, [&b"/e"[..]]);
    assert_eq!(opts.show(), br",lowerdir+=/a\040b,lowerdir+=/c:d,datadir+=/e,redirect_dir=on");
    let opts = Options::parse(b"lowerdir=/a::/b::/c").unwrap();
    assert_eq!(opts.data, [&b"/b"[..], b"/c"]);
    assert_eq!(opts.show(), b",lowerdir=/a::/b::/c,redirect_dir=on");
    for data in [
        &b"lowerdir=/a,lowerdir+=/b"[..],
        b"lowerdir=/a,datadir+=/b",
        b"datadir+=/a,lowerdir+=/b",
        b"datadir+=/a",
        b"lowerdir+=",
    ] {
        assert_eq!(Options::parse(data).err(), Some(Errno::EINVAL));
    }
    // A later `lowerdir=` replaces the added layers.
    let opts = Options::parse(b"lowerdir+=/a,datadir+=/b,lowerdir=/c").unwrap();
    assert_eq!((opts.lowers, opts.data, opts.added), (vec![b"/c".to_vec()], Vec::new(), false));
}

#[test]
fn the_uuid_gives_the_fsid() {
    let [lower, upper, work, data] = layers();
    let dirs = [&lower, &upper, &work, &data];
    let real = upper.fs_fsid();
    upper.create(b"d", FileType::Directory, 0o755, 0).unwrap();
    let root = mount_layers(dirs, b"lowerdir=/l,upperdir=/u,workdir=/w,uuid=null").unwrap();
    assert_eq!(root.lookup(b"d").unwrap().fs_fsid(), real);
    // The lookup of a merged directory marks the root as impure, so the overlay is old.
    assert!(upper.get_xattr(b"trusted.overlay.impure").is_ok());
    let root = mount_layers(dirs, b"lowerdir=/l,upperdir=/u,workdir=/w").unwrap();
    assert_eq!(root.fs_fsid(), real);
    assert_eq!(root.fs_options(), b",lowerdir=/l,upperdir=/u,workdir=/w,uuid=null");
    let root = mount_layers(dirs, b"lowerdir=/l,upperdir=/u,workdir=/w,uuid=on").unwrap();
    let unique = root.fs_fsid();
    assert_ne!(unique, real);
    assert_eq!(upper.get_xattr(b"trusted.overlay.uuid").map(|u| u.len()), Ok(16));
    let root = mount_layers(dirs, b"lowerdir=/l,upperdir=/u,workdir=/w").unwrap();
    assert_eq!(root.fs_fsid(), unique);
    assert_eq!(root.fs_options(), b",lowerdir=/l,upperdir=/u,workdir=/w");
    let root = mount_layers(dirs, b"lowerdir=/l,upperdir=/u,workdir=/w,uuid=off").unwrap();
    assert_eq!(root.fs_fsid(), real);
    let root = mount_layers(dirs, b"lowerdir=/u:/l,uuid=on").unwrap();
    assert_eq!(root.fs_fsid(), real);
}

#[test]
fn a_copy_up_keeps_the_inode_number_after_a_new_mount() {
    let [lower, upper, work, data] = layers();
    let dirs = [&lower, &upper, &work, &data];
    let opts = b"lowerdir=/l,upperdir=/u,workdir=/w";
    let root = mount_layers(dirs, opts).unwrap();
    let ino = root.lookup(b"a").unwrap().metadata().ino;
    let d = root.lookup(b"d").unwrap();
    let x = d.lookup(b"x").unwrap();
    let xino = x.metadata().ino;
    x.set_attr(&SetAttr { mode: Some(0o600), ..SetAttr::default() }).unwrap();
    root.rename(b"a", &d, b"a").unwrap();
    drop((x, d, root));
    let root = mount_layers(dirs, opts).unwrap();
    let d = root.lookup(b"d").unwrap();
    assert_eq!(d.lookup(b"a").unwrap().metadata().ino, ino);
    assert_eq!(d.lookup(b"x").unwrap().metadata().ino, xino);
    // The entries of a merged directory have the inode numbers of `stat`.
    let entries = real_entries(&d).unwrap();
    let a = entries.iter().find(|e| e.name == b"a").unwrap();
    assert_eq!(a.ino, ino);
}

#[test]
fn an_unused_node_keeps_its_redirect_and_metacopy_state() {
    let [lower, upper, work, data] = layers();
    let dirs = [&lower, &upper, &work, &data];
    let opts = b"lowerdir=/l,upperdir=/u,workdir=/w,redirect_dir=on,metacopy=on";
    let root = mount_layers(dirs, opts).unwrap();
    let chmod = SetAttr { mode: Some(0o600), ..SetAttr::default() };
    let a = root.lookup(b"a").unwrap();
    let ino = a.metadata().ino;
    a.set_attr(&chmod).unwrap();
    drop(a);
    root.rename(b"d", &root, b"e").unwrap();
    // The lookups give the unused nodes again, with the same state.
    let count = node(&root).fs.cache.count.load(Ordering::Relaxed);
    assert!(count >= 2);
    let a = root.lookup(b"a").unwrap();
    assert!(node(&a).is_metacopy());
    assert_eq!(read(&a), b"lower a");
    assert_eq!(a.metadata().ino, ino);
    a.write_at(0, b"L").unwrap();
    drop(a);
    let a = root.lookup(b"a").unwrap();
    assert!(!node(&a).is_metacopy());
    assert_eq!(read(&a), b"Lower a");
    let e = root.lookup(b"e").unwrap();
    assert_eq!(node(&e).redirect.lock().as_deref(), Some(&b"d"[..]));
    assert_eq!(read(&e.lookup(b"x").unwrap()), b"lower x");
}

/// Gives the layers of [`layers`], where the lower file `a` has the hard link `h`.
fn linked_layers() -> [InodeRef; 4] {
    let dirs = layers();
    let a = dirs[0].lookup(b"a").unwrap();
    dirs[0].link(b"h", &a).unwrap();
    dirs
}

#[test]
fn a_copy_up_of_a_lower_hard_link_goes_to_the_index() {
    let [lower, upper, work, data] = linked_layers();
    let dirs = [&lower, &upper, &work, &data];
    let opts = b"lowerdir=/l,upperdir=/u,workdir=/w,index=on";
    let root = mount_layers(dirs, opts).unwrap();
    assert_eq!(root.fs_options(), b",lowerdir=/l,upperdir=/u,workdir=/w,index=on,uuid=on");
    let index = work.lookup(INDEX).unwrap();
    let a = root.lookup(b"a").unwrap();
    let h = root.lookup(b"h").unwrap();
    let ino = a.metadata().ino;
    h.write_at(0, b"LOWER").unwrap();
    // The other name shows the copy, with the same inode number and count of links.
    assert_eq!(read(&a), b"LOWER a");
    assert_eq!((a.metadata().ino, a.metadata().nlink), (ino, 2));
    assert_eq!((h.metadata().ino, h.metadata().nlink), (ino, 2));
    let name = index_name(&lower.lookup(b"a").unwrap()).unwrap();
    assert!(name.iter().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    let entry = index.lookup(&name).unwrap();
    assert!(same_inode(&entry, &upper.lookup(b"h").unwrap()));
    assert_eq!(upper.lookup(b"a").err(), Some(Errno::ENOENT));
    // The removal of a lower name copies it up first, so the index keeps the count.
    root.unlink(b"a").unwrap();
    assert_eq!(h.metadata().nlink, 1);
    // The upper inode has two links, the index and `h`, and the overlay file has one.
    assert_eq!(entry.get_xattr(b"trusted.overlay.nlink").as_deref(), Ok(&b"U-1"[..]));
    root.link(b"n", &h).unwrap();
    assert_eq!(root.lookup(b"n").unwrap().metadata().nlink, 2);
    root.unlink(b"n").unwrap();
    // The removal of the last name removes the entry. The whiteouts share one inode.
    root.unlink(b"h").unwrap();
    assert_eq!(index.lookup(&name).err(), Some(Errno::ENOENT));
    let white = upper.lookup(b"a").unwrap();
    assert!(is_whiteout(&white));
    assert!(same_inode(&white, &upper.lookup(b"h").unwrap()));
    let temps = names(&index);
    assert_eq!(temps.len(), 1);
    assert!(temps[0].starts_with(b"#"));
    assert_eq!(white.metadata().nlink, 3);
}

#[test]
fn a_new_mount_finds_the_index_and_cleans_it() {
    let [lower, upper, work, data] = linked_layers();
    let dirs = [&lower, &upper, &work, &data];
    let opts = b"lowerdir=/l,upperdir=/u,workdir=/w,index=on";
    let root = mount_layers(dirs, opts).unwrap();
    root.lookup(b"a").unwrap().write_at(0, b"LOWER").unwrap();
    drop(root);
    let index = work.lookup(INDEX).unwrap();
    // An orphan entry and a temporary file go away in the next mount.
    let b = lower.lookup(b"b").unwrap();
    let orphan = file(&index, &index_name(&b).unwrap(), b"");
    assert!(set_origin_of(&orphan, &b));
    file(&index, b"#7", b"");
    let root = mount_layers(dirs, opts).unwrap();
    assert_eq!(names(&index).len(), 1);
    let h = root.lookup(b"h").unwrap();
    assert_eq!(read(&h), b"LOWER a");
    assert_eq!(h.metadata().nlink, 2);
    assert_eq!(h.metadata().ino, root.lookup(b"a").unwrap().metadata().ino);
}

/// Sets the attribute [`ORIGIN`] of `upper` to the file handle of `lower`.
fn set_origin_of(upper: &InodeRef, lower: &InodeRef) -> bool {
    upper.set_xattr(b"trusted.overlay.origin", &encode_fh(lower).unwrap(), 0).is_ok()
}

#[test]
fn the_index_is_only_for_its_layers() {
    let [lower, upper, work, data] = layers();
    let dirs = [&lower, &upper, &work, &data];
    let opts = b"lowerdir=/l,upperdir=/u,workdir=/w,index=on";
    drop(mount_layers(dirs, opts).unwrap());
    let other = rk_fs_tmpfs::new(0o755);
    let err = mount_layers([&other, &upper, &work, &data], opts).err();
    assert_eq!(err, Some(Errno::ESTALE));
    let upper2 = upper.create(b"u2", FileType::Directory, 0o755, 0).unwrap();
    let err = mount_layers([&lower, &upper2, &work, &data], opts).err();
    assert_eq!(err, Some(Errno::ESTALE));
    // Without the index, the mount does not check the layers.
    let off = b"lowerdir=/l,upperdir=/u,workdir=/w";
    assert!(mount_layers([&other, &upper, &work, &data], off).is_ok());
}

#[test]
fn an_upper_directory_in_use_gives_ebusy_with_the_index() {
    let [lower, upper, work, data] = layers();
    let work2 = upper.create(b"w2", FileType::Directory, 0o755, 0).unwrap();
    let on = b"lowerdir=/l,upperdir=/u,workdir=/w,index=on";
    let off = b"lowerdir=/l,upperdir=/u,workdir=/w,index=off";
    let root = mount_layers([&lower, &upper, &work, &data], on).unwrap();
    assert_eq!(mount_layers([&lower, &upper, &work2, &data], on).err(), Some(Errno::EBUSY));
    drop(mount_layers([&lower, &upper, &work2, &data], off).unwrap());
    drop(root);
    // The end of the mount frees the directories.
    drop(mount_layers([&lower, &upper, &work, &data], on).unwrap());
}

#[test]
fn a_directory_without_moved_names_loses_the_impure_attribute() {
    let [lower, upper, work, data] = layers();
    let root = mount_layers([&lower, &upper, &work, &data], b"lowerdir=/l,upperdir=/u,workdir=/w")
        .unwrap();
    let dir = root.create(b"new", FileType::Directory, 0o755, 0).unwrap();
    root.rename(b"a", &dir, b"a").unwrap();
    let real = upper.lookup(b"new").unwrap();
    assert!(real.get_xattr(b"trusted.overlay.impure").is_ok());
    names(&dir);
    assert!(real.get_xattr(b"trusted.overlay.impure").is_ok());
    dir.unlink(b"a").unwrap();
    names(&dir);
    assert_eq!(real.get_xattr(b"trusted.overlay.impure").err(), Some(Errno::ENODATA));
}
