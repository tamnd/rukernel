//! Tests on a small XFS image of version 5 that the test makes byte by byte. The image has
//! blocks of 1 KiB, one allocation group of 64 blocks and inodes of 512 bytes, 2 in a block.

use super::*;
use alloc::boxed::Box;
use alloc::vec::Vec;
use rk_vfs::{FileType, Inode, Timespec};

const BS: usize = 1024;
const ROOT: u64 = 16;
const BIG: u64 = 17;
const LINK: u64 = 18;
const DIR: u64 = 19;
const TREE: u64 = 20;
const LONG: u64 = 21;
const NULL: u64 = 22;

struct Ram(Vec<u8>);

impl Disk for Ram {
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let at = offset as usize;
        buf.copy_from_slice(self.0.get(at..at + buf.len()).ok_or(Errno::EIO)?);
        Ok(())
    }
}

struct Image(Vec<u8>);

impl Image {
    fn put(&mut self, at: usize, v: &[u8]) {
        self.0[at..at + v.len()].copy_from_slice(v);
    }

    fn put16(&mut self, at: usize, v: u16) {
        self.put(at, &v.to_be_bytes());
    }

    fn put32(&mut self, at: usize, v: u32) {
        self.put(at, &v.to_be_bytes());
    }

    fn put64(&mut self, at: usize, v: u64) {
        self.put(at, &v.to_be_bytes());
    }

    /// Writes the core of a version 3 inode. Gives the offset of its data fork.
    fn inode(&mut self, ino: u64, mode: u16, format: u8, size: u64, extents: u32) -> usize {
        let at = ino as usize * 512;
        self.put16(at, 0x494e);
        self.put16(at + 2, mode);
        self.0[at + 4] = 3;
        self.0[at + 5] = format;
        self.put32(at + 8, 1000);
        self.put32(at + 12, 100);
        self.put32(at + 16, 1);
        self.put32(at + 32, 1_700_000_000);
        self.put32(at + 36, 5);
        self.put64(at + 56, size);
        self.put32(at + 76, extents);
        self.put64(at + 152, ino);
        at + 176
    }

    /// Writes an extent record at `at`.
    fn extent(&mut self, at: usize, off: u64, block: u64, len: u64, unwritten: bool) {
        self.put64(at, u64::from(unwritten) << 63 | off << 9 | block >> 43);
        self.put64(at + 8, block << 21 | len);
    }
}

/// Makes the image. The root has `big`, `link`, `d`, `tree`, `long` and `null`.
fn image() -> Image {
    let mut img = Image(vec![0u8; 64 * BS]);
    img.put32(0, 0x5846_5342);
    img.put32(4, BS as u32);
    img.put64(8, 64);
    img.put64(56, ROOT);
    img.put32(84, 64);
    img.put32(88, 1);
    img.put16(100, 0xb4a5);
    img.put16(104, 512);
    img.put16(106, 2);
    img.0[120] = 10;
    img.0[122] = 9;
    img.0[123] = 1;
    img.0[124] = 6;
    img.put64(128, 64);
    img.put64(136, 57);
    img.put64(144, 30);
    img.put32(216, 0x1 | 0x8);

    let entries: [(&[u8], u8, u64); 6] = [
        (b"big", 1, BIG),
        (b"link", 7, LINK),
        (b"d", 2, DIR),
        (b"tree", 1, TREE),
        (b"long", 7, LONG),
        (b"null", 3, NULL),
    ];
    let mut sf = vec![entries.len() as u8, 0];
    sf.extend_from_slice(&(ROOT as u32).to_be_bytes());
    for (name, ftype, ino) in entries {
        sf.push(name.len() as u8);
        sf.extend_from_slice(&[0, 0]);
        sf.extend_from_slice(name);
        sf.push(ftype);
        sf.extend_from_slice(&(ino as u32).to_be_bytes());
    }
    let fork = img.inode(ROOT, 0o40755, 1, sf.len() as u64, 0);
    img.put(fork, &sf);

    // 2500 bytes: block 0, a hole, and block 2.
    let fork = img.inode(BIG, 0o100644, 2, 2500, 2);
    img.extent(fork, 0, 20, 1, false);
    img.extent(fork + 16, 2, 21, 1, false);
    img.0[20 * BS..21 * BS].fill(b'a');
    img.0[21 * BS..22 * BS].fill(b'c');

    let fork = img.inode(LINK, 0o120777, 1, 3, 0);
    img.put(fork, b"big");

    // A directory with one block: `.`, `..`, an unused space and `x`.
    let fork = img.inode(DIR, 0o40755, 2, BS as u64, 1);
    img.extent(fork, 0, 22, 1, false);
    let b = 22 * BS;
    img.put32(b, 0x5844_4233);
    let mut at = b + 64;
    for (name, ino, ftype) in [(&b"."[..], DIR, 2u8), (b"..", ROOT, 2)] {
        img.put64(at, ino);
        img.0[at + 8] = name.len() as u8;
        img.put(at + 9, name);
        img.0[at + 9 + name.len()] = ftype;
        at += 16;
    }
    img.put16(at, 0xffff);
    img.put16(at + 2, 16);
    at += 16;
    img.put64(at, BIG);
    img.0[at + 8] = 1;
    img.0[at + 9] = b'x';
    img.0[at + 10] = 1;
    at += 16;
    img.put16(at, 0xffff);
    img.put16(at + 2, (b + BS - 8 - at) as u16);

    // A file with a tree of extents of one level, and the large time stamps.
    let fork = img.inode(TREE, 0o100600, 3, 2 * BS as u64, 2);
    img.put64(TREE as usize * 512 + 120, 0x8);
    img.put64(TREE as usize * 512 + 32, (1u64 << 31) * 1_000_000_000 + 7);
    img.put16(fork, 1);
    img.put16(fork + 2, 1);
    let max = (512 - 176 - 4) / 16;
    img.put64(fork + 4, 0);
    img.put64(fork + 4 + max * 8, 23);
    let leaf = 23 * BS;
    img.put32(leaf, 0x424d_4133);
    img.put16(leaf + 6, 2);
    img.extent(leaf + 72, 0, 24, 1, false);
    img.extent(leaf + 88, 1, 25, 1, true);
    img.0[24 * BS..25 * BS].fill(b't');
    img.0[25 * BS..26 * BS].fill(b'u');

    // A symbolic link with its target in a block, after the header of version 5.
    let fork = img.inode(LONG, 0o120777, 2, 300, 1);
    img.extent(fork, 0, 26, 1, false);
    img.put32(26 * BS, 0x5853_4c4d);
    img.put32(26 * BS + 8, 300);
    img.0[26 * BS + 56..26 * BS + 356].fill(b'y');

    let fork = img.inode(NULL, 0o20666, 0, 0, 0);
    img.put32(fork, 1 << 18 | 3);
    img
}

fn mount(img: Image) -> Result<Arc<Fs>> {
    Fs::open(9, Box::new(Ram(img.0)))
}

fn names(dir: &dyn Inode) -> Vec<(Vec<u8>, u64, FileType)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some((e, next)) = dir.read_dir(pos).unwrap() {
        out.push((e.name, e.ino, e.kind));
        pos = next;
    }
    out
}

fn read_all(inode: &InodeRef) -> Vec<u8> {
    let mut buf = vec![0u8; inode.metadata().size as usize + 10];
    let n = inode.read_at(0, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

#[test]
fn reads_the_short_form_root() {
    let fs = mount(image()).unwrap();
    let root = fs.root().unwrap();
    let got = names(&*root);
    let want: Vec<(Vec<u8>, u64, FileType)> = [
        (&b"."[..], ROOT, FileType::Directory),
        (b"..", ROOT, FileType::Directory),
        (b"big", BIG, FileType::Regular),
        (b"link", LINK, FileType::Symlink),
        (b"d", DIR, FileType::Directory),
        (b"tree", TREE, FileType::Regular),
        (b"long", LONG, FileType::Symlink),
        (b"null", NULL, FileType::CharDevice),
    ]
    .into_iter()
    .map(|(n, i, k)| (n.to_vec(), i, k))
    .collect();
    assert_eq!(got, want);
    assert_eq!(root.lookup(b"nope").err(), Some(Errno::ENOENT));
    let m = root.metadata();
    assert_eq!((m.ino, m.mode, m.uid, m.gid), (ROOT, 0o40755, 1000, 100));
    assert_eq!(m.atime, Timespec { sec: 1_700_000_000, nsec: 5 });
    assert_eq!(root.fs_magic(), XFS_MAGIC);
    let st = root.fs_stat().unwrap();
    assert_eq!((st.bsize, st.blocks, st.bfree, st.files, st.ffree), (1024, 64, 30, 64, 57));
}

#[test]
fn reads_a_file_with_a_hole() {
    let fs = mount(image()).unwrap();
    let big = fs.root().unwrap().lookup(b"big").unwrap();
    let data = read_all(&big);
    assert_eq!(data.len(), 2500);
    assert!(data[..BS].iter().all(|&b| b == b'a'));
    assert!(data[BS..2 * BS].iter().all(|&b| b == 0));
    assert!(data[2 * BS..].iter().all(|&b| b == b'c'));
    let mut buf = [0u8; 4];
    assert_eq!(big.read_at(BS as u64 - 2, &mut buf).unwrap(), 4);
    assert_eq!(&buf, b"aa\0\0");
    assert_eq!(big.read_at(2500, &mut buf).unwrap(), 0);
    assert_eq!(big.write_at(0, b"x").err(), Some(Errno::EROFS));
}

#[test]
fn reads_a_tree_of_extents() {
    let fs = mount(image()).unwrap();
    let tree = fs.root().unwrap().lookup(b"tree").unwrap();
    let data = read_all(&tree);
    assert!(data[..BS].iter().all(|&b| b == b't'));
    // The second extent is unwritten, so it reads as zeros.
    assert!(data[BS..].iter().all(|&b| b == 0));
    assert_eq!(tree.metadata().atime, Timespec { sec: 0, nsec: 7 });
}

#[test]
fn reads_a_directory_block() {
    let fs = mount(image()).unwrap();
    let d = fs.root().unwrap().lookup(b"d").unwrap();
    let got: Vec<_> = names(&*d).into_iter().map(|(n, i, _)| (n, i)).collect();
    assert_eq!(got, [(b".".to_vec(), DIR), (b"..".to_vec(), ROOT), (b"x".to_vec(), BIG)]);
    let x = d.lookup(b"x").unwrap();
    assert_eq!(x.metadata().ino, BIG);
    assert_eq!(d.create(b"y", FileType::Regular, 0o644, 0).err(), Some(Errno::EROFS));
}

#[test]
fn reads_links_and_devices() {
    let fs = mount(image()).unwrap();
    let root = fs.root().unwrap();
    assert_eq!(root.lookup(b"link").unwrap().read_link().unwrap(), b"big");
    assert_eq!(root.lookup(b"long").unwrap().read_link().unwrap(), vec![b'y'; 300]);
    let null = root.lookup(b"null").unwrap();
    assert_eq!(null.metadata().rdev, rk_vfs::device::makedev(1, 3));
}

#[test]
fn one_inode_for_two_lookups() {
    let fs = mount(image()).unwrap();
    let root = fs.root().unwrap();
    let a = root.lookup(b"big").unwrap();
    let b = fs.root().unwrap().lookup(b"d").unwrap().lookup(b"x").unwrap();
    assert!(Arc::ptr_eq(&a, &b));
}

#[test]
fn refuses_bad_disks() {
    let mut img = image();
    img.put32(0, 0);
    assert_eq!(mount(img).err(), Some(Errno::EINVAL));
    let mut img = image();
    img.put32(216, 0x1 | 0x10);
    assert_eq!(mount(img).err(), Some(Errno::EUCLEAN));
    let mut img = image();
    img.put32(216, 0x1 | 0x1000);
    assert_eq!(mount(img).err(), Some(Errno::EOPNOTSUPP));
    let mut img = image();
    img.put16(BIG as usize * 512, 0);
    let fs = mount(img).unwrap();
    assert_eq!(fs.root().unwrap().lookup(b"big").err(), Some(Errno::EUCLEAN));
    let mut img = image();
    img.put32(22 * BS, 0);
    let fs = mount(img).unwrap();
    assert_eq!(fs.root().unwrap().lookup(b"d").unwrap().read_dir(0).err(), Some(Errno::EUCLEAN));
}
