use super::*;

fn root() -> InodeRef {
    mount(&MountArgs { data: b"", dev: None, read_only: false, lookup: None }).unwrap()
}

fn read(inode: &InodeRef) -> String {
    let mut buf = [0u8; 4096];
    let n = inode.read_at(0, &mut buf).unwrap();
    String::from_utf8(buf[..n].to_vec()).unwrap()
}

fn names(dir: &InodeRef) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some((e, next)) = dir.read_dir(pos).unwrap() {
        out.push(e.name);
        pos = next;
    }
    out
}

#[test]
fn mkdir_makes_a_cgroup_with_its_files() {
    let root = root();
    assert_eq!(root.fs_magic(), CGROUP2_MAGIC);
    let dir = root.create(b"fs-a", FileType::Directory, 0o755, 0).unwrap();
    let id = cgroup_of(&dir).unwrap();
    assert!(names(&root).contains(&b"fs-a".to_vec()));
    let list = names(&dir);
    assert_eq!(&list[..2], [b".".to_vec(), b"..".to_vec()]);
    assert!(list.contains(&b"cgroup.procs".to_vec()));
    let procs = dir.lookup(b"cgroup.procs").unwrap();
    assert_eq!(read(&procs), "");
    assert_eq!(procs.metadata().mode, mode::S_IFREG | 0o644);
    assert_eq!(cgroup_of(&procs), None);
    let events = dir.lookup(b"cgroup.events").unwrap();
    assert_eq!(read(&events), "populated 0\nfrozen 0\n");
    assert_eq!(dir.lookup(b"nothing").err(), Some(Errno::ENOENT));
    assert_eq!(root.create(b"fs-a", FileType::Directory, 0o755, 0).err(), Some(Errno::EEXIST));
    assert_eq!(root.create(b"file", FileType::Regular, 0o644, 0).err(), Some(Errno::EPERM));
    root.rmdir(b"fs-a").unwrap();
    assert!(rk_cgroup::with(|h| !h.exists(id)));
    assert_eq!(read_err(&events), Errno::ENODEV);
}

fn read_err(inode: &InodeRef) -> Errno {
    let mut buf = [0u8; 16];
    inode.read_at(0, &mut buf).unwrap_err()
}

#[test]
fn a_write_goes_to_the_hierarchy() {
    let root = root();
    let control = root.lookup(b"cgroup.subtree_control").unwrap();
    control.write_at(0, b"+memory +pids").unwrap();
    let dir = root.create(b"fs-b", FileType::Directory, 0o755, 0).unwrap();
    let max = dir.lookup(b"memory.max").unwrap();
    assert_eq!(read(&max), "max\n");
    max.write_at(0, b"1M\n").unwrap();
    assert_eq!(read(&max), "1048576\n");
    assert_eq!(max.write_at(0, b"lots").err(), Some(Errno::EINVAL));
    let pids = dir.lookup(b"pids.max").unwrap();
    pids.write_at(0, b"5").unwrap();
    assert_eq!(read(&pids), "5\n");
    let procs = dir.lookup(b"cgroup.procs").unwrap();
    assert_eq!(procs.write_at(0, b"42\n").err(), Some(Errno::ESRCH));
    assert_eq!(procs.write_at(0, b"x").err(), Some(Errno::EINVAL));
    let pressure = dir.lookup(b"cpu.pressure").unwrap();
    assert!(read(&pressure).starts_with("some avg10=0.00 avg60=0.00 avg300=0.00 total="));
    assert_eq!(pressure.write_at(0, b"some 150000 1000000").err(), Some(Errno::EOPNOTSUPP));
    assert_eq!(pressure.write_at(0, b"bad").err(), Some(Errno::EINVAL));
    assert_eq!(root.rmdir(b"cgroup.procs").err(), Some(Errno::ENOTDIR));
    root.rmdir(b"fs-b").unwrap();
}

#[test]
fn the_inode_number_holds_the_cgroup() {
    let root = root();
    assert_eq!(cgroup_of(&root), Some(rk_cgroup::ROOT));
    assert_eq!(root.metadata().ino, u64::from(rk_cgroup::ROOT) << INO_SHIFT);
    let a = root.lookup(b"cgroup.procs").unwrap().metadata().ino;
    let b = root.lookup(b"cgroup.stat").unwrap().metadata().ino;
    assert_ne!(a, b);
    assert_eq!(a >> INO_SHIFT, u64::from(rk_cgroup::ROOT));
    assert_eq!(parse_id(b" 12\n").unwrap(), 12);
}

#[test]
fn chown_and_chmod_change_one_inode() {
    let root = root();
    let dir = root.create(b"fs-c", FileType::Directory, 0o755, 0).unwrap();
    let procs = dir.lookup(b"cgroup.procs").unwrap();
    let attr = SetAttr { uid: Some(65534), gid: Some(65533), ..SetAttr::default() };
    procs.set_attr(&attr).unwrap();
    let m = procs.metadata();
    assert_eq!((m.uid, m.gid, m.mode), (65534, 65533, mode::S_IFREG | 0o644));
    assert_eq!(dir.metadata().uid, 0);
    assert_eq!(dir.lookup(b"cgroup.threads").unwrap().metadata().uid, 0);
    dir.set_attr(&SetAttr { mode: Some(0o700), ..SetAttr::default() }).unwrap();
    assert_eq!(dir.metadata().mode, mode::S_IFDIR | 0o700);
    root.rmdir(b"fs-c").unwrap();
    assert!(ATTRS.lock().keys().all(|&ino| ino >> INO_SHIFT != m.ino >> INO_SHIFT));
}
