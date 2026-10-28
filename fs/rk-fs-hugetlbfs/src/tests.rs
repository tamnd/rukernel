//! The tests of hugetlbfs.

use super::*;
use rk_vfs::inode::falloc::{KEEP_SIZE, PUNCH_HOLE};

const M2: u64 = HPAGE;

fn file(root: &InodeRef) -> InodeRef {
    root.create(b"f", FileType::Regular, 0o600, 0).unwrap()
}

#[test]
fn the_options_follow_linux() {
    let o = parse_options(b"mode=1770,uid=5,gid=6,size=8M,min_size=4M,nr_inodes=1k", 100).unwrap();
    assert_eq!(o.mode, 0o1770);
    assert_eq!((o.uid, o.gid), (5, 6));
    assert_eq!((o.max_pages, o.min_pages, o.max_inodes), (Some(4), Some(2), Some(1024)));
    assert_eq!(parse_options(b"size=50%", 10).unwrap().max_pages, Some(5));
    assert_eq!(parse_options(b"pagesize=2M", 0).unwrap(), Options::default());
    assert_eq!(parse_options(b"pagesize=1G", 0), Err(Errno::EINVAL));
    assert_eq!(parse_options(b"size=x", 0), Err(Errno::EINVAL));
    assert_eq!(parse_options(b"size=2M,min_size=4M", 0), Err(Errno::EINVAL));
}

#[test]
fn a_file_has_no_write_and_a_size_of_whole_huge_pages() {
    let root = new(Options::default());
    let f = file(&root);
    assert_eq!(f.write_at(0, b"x"), Err(Errno::EINVAL));
    let size = |s| SetAttr { size: Some(s), ..SetAttr::default() };
    assert_eq!(f.set_attr(&size(4096)), Err(Errno::EINVAL));
    assert_eq!(f.set_attr(&size(2 * M2)), Ok(()));
    let meta = f.metadata();
    assert_eq!((meta.size, meta.blocks, meta.blksize), (2 * M2, 0, HPAGE_SIZE as u32));
    assert_eq!(root.fs_magic(), HUGETLBFS_MAGIC);
}

#[test]
fn fallocate_gives_and_frees_whole_huge_pages() {
    let root = new(Options::default());
    let f = file(&root);
    assert_eq!(f.fallocate(0x10, 0, M2), Err(Errno::EOPNOTSUPP));
    f.fallocate(KEEP_SIZE, 1, M2).unwrap();
    assert_eq!(f.metadata().size, 0);
    assert_eq!(f.metadata().blocks, 2 * M2 / 512);
    f.fallocate(0, 0, 3 * M2).unwrap();
    assert_eq!(f.metadata().size, 3 * M2);
    assert_eq!(f.metadata().blocks, 3 * M2 / 512);
    let pages = huge_file(&f).unwrap();
    pages.fill(0, 3 * M2, 7);
    // The hole frees the second page, and the parts of the first and third pages become zeros.
    f.fallocate(PUNCH_HOLE | KEEP_SIZE, M2 - 1, M2 + 2).unwrap();
    assert_eq!(f.metadata().blocks, 2 * M2 / 512);
    let mut buf = [9u8; 4];
    assert_eq!(f.read_at(M2 - 2, &mut buf), Ok(4));
    assert_eq!(buf, [7, 0, 0, 0]);
    assert_eq!(f.read_at(2 * M2, &mut buf), Ok(4));
    assert_eq!(buf, [0, 7, 7, 7]);
    assert_eq!(f.read_at(3 * M2 - 1, &mut buf), Ok(1));
}

#[test]
fn the_counts_of_statfs_follow_the_options() {
    let root = new(Options { max_pages: Some(2), max_inodes: Some(3), ..Options::default() });
    let f = file(&root);
    f.fallocate(0, 0, M2).unwrap();
    let st = root.fs_stat().unwrap();
    assert_eq!((st.bsize, st.blocks, st.bfree, st.files, st.ffree), (M2, 2, 1, 3, 1));
    assert_eq!(f.fallocate(0, 0, 3 * M2), Err(Errno::ENOSPC));
    root.create(b"g", FileType::Regular, 0o600, 0).unwrap();
    assert_eq!(root.create(b"h", FileType::Regular, 0o600, 0).err(), Some(Errno::ENOSPC));
    let open = new(Options::default()).fs_stat().unwrap();
    assert_eq!((open.blocks, open.files), (0, u64::MAX));
}
