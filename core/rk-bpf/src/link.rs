//! The BPF links, `struct bpf_link` in kernel/bpf/syscall.c of Linux.
//!
//! A link attaches a program to a hook. The hook keeps the program while the link exists: the
//! last close of a link file, or the `unlink` of its pin in bpffs, detaches the program, as
//! `bpf_link_free` of Linux. `BPF_LINK_DETACH` detaches the program while the link stays, and
//! `BPF_LINK_UPDATE` puts a new program in the hook. Each type of hook has its operations, as
//! `struct bpf_link_ops` of Linux.

use crate::idr::Idr;
use crate::prog::BpfProg;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use rk_abi::Errno;
use rk_frame::sync::SpinLock;
use rk_vfs::file::{File, FileOps};
use rk_vfs::inode::Metadata;

/// The result of a link operation.
pub type Result<T> = core::result::Result<T, Errno>;

/// The link types, `enum bpf_link_type` of Linux.
#[allow(missing_docs)]
pub mod link_type {
    pub const BPF_LINK_TYPE_UNSPEC: u32 = 0;
    pub const BPF_LINK_TYPE_RAW_TRACEPOINT: u32 = 1;
    pub const BPF_LINK_TYPE_TRACING: u32 = 2;
    pub const BPF_LINK_TYPE_CGROUP: u32 = 3;
    pub const BPF_LINK_TYPE_ITER: u32 = 4;
    pub const BPF_LINK_TYPE_NETNS: u32 = 5;
    pub const BPF_LINK_TYPE_XDP: u32 = 6;
    pub const BPF_LINK_TYPE_PERF_EVENT: u32 = 7;
    pub const BPF_LINK_TYPE_KPROBE_MULTI: u32 = 8;
    pub const BPF_LINK_TYPE_STRUCT_OPS: u32 = 9;
    pub const BPF_LINK_TYPE_NETFILTER: u32 = 10;
    pub const BPF_LINK_TYPE_TCX: u32 = 11;
    pub const BPF_LINK_TYPE_UPROBE_MULTI: u32 = 12;
    pub const BPF_LINK_TYPE_NETKIT: u32 = 13;
    pub const BPF_LINK_TYPE_SOCKMAP: u32 = 14;
}

/// The names of the link types in fdinfo, `bpf_link_type_strs` of Linux.
const BPF_LINK_TYPE_STRS: [&str; 15] = [
    "<invalid>",
    "raw_tracepoint",
    "tracing",
    "cgroup",
    "iter",
    "netns",
    "xdp",
    "perf_event",
    "kprobe_multi",
    "struct_ops",
    "netfilter",
    "tcx",
    "uprobe_multi",
    "netkit",
    "sockmap",
];

/// The size of `struct bpf_link_info` of Linux 7.3.
pub const BPF_LINK_INFO_SIZE: usize = 64;

/// The offsets in `struct bpf_link_info`.
pub mod link_info {
    /// `type`.
    pub const TYPE: usize = 0;
    /// `id`.
    pub const ID: usize = 4;
    /// `prog_id`.
    pub const PROG_ID: usize = 8;
    /// The union of the fields of each type.
    pub const UNION: usize = 16;
}

/// The operations of a type of link, `struct bpf_link_ops` of Linux.
pub trait BpfLinkOps: Send + Sync {
    /// Takes the program out of the hook, `release`. The link calls it once, when the link is
    /// dropped or detached.
    fn release(&self, link: &BpfLink);

    /// Detaches the link from its hook for `BPF_LINK_DETACH`, `detach`. A type without it gives
    /// `EOPNOTSUPP`.
    fn detach(&self, link: &BpfLink) -> Result<()> {
        let _ = link;
        Err(Errno::EOPNOTSUPP)
    }

    /// Puts `new` in the hook in place of the program of the link, `update_prog`. With
    /// `BPF_F_REPLACE`, `old` is the program that the link must have. A type without it gives
    /// `EINVAL`.
    fn update_prog(
        &self,
        link: &BpfLink,
        new: Arc<BpfProg>,
        old: Option<&Arc<BpfProg>>,
    ) -> Result<()> {
        let _ = (link, new, old);
        Err(Errno::EINVAL)
    }

    /// Writes the fields of the type in `struct bpf_link_info`, `fill_link_info`.
    fn fill_link_info(&self, link: &BpfLink, info: &mut [u8; BPF_LINK_INFO_SIZE]) -> Result<()> {
        let _ = (link, info);
        Ok(())
    }

    /// Adds the lines of the type to the fdinfo of the link, `show_fdinfo`.
    fn show_fdinfo(&self, link: &BpfLink, out: &mut String) {
        let _ = (link, out);
    }
}

/// The IDs of the links, `link_idr` of Linux.
pub static LINK_IDR: Idr<BpfLink> = Idr::new();

/// A link, `struct bpf_link` of Linux.
pub struct BpfLink {
    /// The type, `BPF_LINK_TYPE_*`.
    pub link_type: u32,
    /// The attach type.
    pub attach_type: u32,
    /// The ID. It is 0 until [`bpf_link_settle`], so `BPF_LINK_GET_FD_BY_ID` does not find a
    /// link that is not complete.
    id: AtomicU32,
    /// The program. It is `None` after the link is detached.
    prog: SpinLock<Option<Arc<BpfProg>>>,
    /// The operations of the type, with the state of the hook.
    pub ops: Box<dyn BpfLinkOps>,
}

impl BpfLink {
    /// Makes a link of `prog`, as `bpf_link_init` of Linux.
    pub fn new(
        link_type: u32,
        ops: Box<dyn BpfLinkOps>,
        prog: Arc<BpfProg>,
        attach_type: u32,
    ) -> Self {
        Self { link_type, attach_type, id: AtomicU32::new(0), prog: SpinLock::new(Some(prog)), ops }
    }

    /// The ID, or 0 before [`bpf_link_settle`].
    pub fn id(&self) -> u32 {
        self.id.load(Ordering::Acquire)
    }

    /// The program, or `None` after the link is detached.
    pub fn prog(&self) -> Option<Arc<BpfProg>> {
        self.prog.lock().clone()
    }

    /// Changes the program, for the `update_prog` of a type. Gives the old program.
    pub fn set_prog(&self, prog: Option<Arc<BpfProg>>) -> Option<Arc<BpfProg>> {
        core::mem::replace(&mut *self.prog.lock(), prog)
    }

    /// The text of `/proc/PID/fdinfo` after the common lines, as `bpf_link_show_fdinfo` of
    /// Linux.
    pub fn show_fdinfo(&self) -> Vec<u8> {
        let mut out = String::new();
        match BPF_LINK_TYPE_STRS.get(self.link_type as usize) {
            Some(name) => out.push_str(&format!("link_type:\t{name}\n")),
            None => out.push_str(&format!("link_type:\t<{}>\n", self.link_type)),
        }
        out.push_str(&format!("link_id:\t{}\n", self.id()));
        if let Some(prog) = self.prog() {
            let mut tag = String::new();
            for b in prog.tag {
                tag.push_str(&format!("{b:02x}"));
            }
            out.push_str(&format!("prog_tag:\t{tag}\nprog_id:\t{}\n", prog.id));
        }
        self.ops.show_fdinfo(self, &mut out);
        out.into_bytes()
    }

    /// The bytes of `struct bpf_link_info`, as `bpf_link_get_info_by_fd` of Linux. `info` has
    /// the bytes that the program gave.
    pub fn fill_info(&self, info: &mut [u8; BPF_LINK_INFO_SIZE]) -> Result<()> {
        info[link_info::TYPE..link_info::TYPE + 4].copy_from_slice(&self.link_type.to_ne_bytes());
        info[link_info::ID..link_info::ID + 4].copy_from_slice(&self.id().to_ne_bytes());
        let prog_id = self.prog().map_or(0, |p| p.id);
        info[link_info::PROG_ID..link_info::PROG_ID + 4].copy_from_slice(&prog_id.to_ne_bytes());
        self.ops.fill_link_info(self, info)
    }

    /// Detaches the program, for the `detach` of a type: calls `release` once and drops the
    /// program. A detached link gives `false`.
    pub fn release_once(&self) -> bool {
        if self.prog.lock().is_none() {
            return false;
        }
        self.ops.release(self);
        self.prog.lock().take();
        true
    }
}

impl Drop for BpfLink {
    /// `bpf_link_free` of Linux: frees the ID and detaches the program.
    fn drop(&mut self) {
        LINK_IDR.remove(self.id());
        self.release_once();
    }
}

/// The operations of a link file, `bpf_link_fops` of Linux.
pub struct BpfLinkFile {
    /// The link.
    pub link: Arc<BpfLink>,
}

impl FileOps for BpfLinkFile {
    fn metadata(&self) -> Option<Metadata> {
        Some(crate::file::anon_inode_metadata())
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }

    fn fdinfo(&self, _file: &File) -> Vec<u8> {
        self.link.show_fdinfo()
    }
}

/// The link of a file, `bpf_link_get_from_fd` of Linux. A file that is not a link gives `None`.
pub fn bpf_link_of(file: &File) -> Option<Arc<BpfLink>> {
    file.ops().as_any()?.downcast_ref::<BpfLinkFile>().map(|f| f.link.clone())
}

/// Gives a link its ID, as `bpf_link_prime` and `bpf_link_settle` of Linux. After this
/// `BPF_LINK_GET_FD_BY_ID` finds the link. All IDs in use give `ENOSPC`.
pub fn bpf_link_settle(link: &Arc<BpfLink>) -> Result<u32> {
    let id = LINK_IDR.alloc().ok_or(Errno::ENOSPC)?;
    link.id.store(id, Ordering::Release);
    LINK_IDR.publish(id, link);
    Ok(id)
}

/// The link of an ID, as `bpf_link_by_id` of Linux. ID 0 and an ID without a link give
/// `ENOENT`.
pub fn bpf_link_by_id(id: u32) -> Result<Arc<BpfLink>> {
    if id == 0 {
        return Err(Errno::ENOENT);
    }
    LINK_IDR.find(id).ok_or(Errno::ENOENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicBool;

    /// A hook that records the release of its link.
    pub(crate) struct TestOps(pub Arc<AtomicBool>);

    impl BpfLinkOps for TestOps {
        fn release(&self, _link: &BpfLink) {
            self.0.store(true, Ordering::Relaxed);
        }

        fn detach(&self, link: &BpfLink) -> Result<()> {
            link.release_once();
            Ok(())
        }
    }

    fn prog() -> Arc<BpfProg> {
        Arc::new(BpfProg {
            prog_type: 1,
            expected_attach_type: 0,
            insns: Vec::new(),
            used_maps: Vec::new(),
            id: 0,
            name: [0; 16],
            tag: [0xab; 8],
            gpl_compatible: true,
            verified_insns: 0,
            run_cnt: core::sync::atomic::AtomicU64::new(0),
            load_time: 0,
            uid: 0,
            enforce_expected_attach_type: false,
        })
    }

    #[test]
    fn a_dropped_link_releases_its_program_and_its_id() {
        let released = Arc::new(AtomicBool::new(false));
        let link = Arc::new(BpfLink::new(
            link_type::BPF_LINK_TYPE_CGROUP,
            Box::new(TestOps(released.clone())),
            prog(),
            0,
        ));
        let id = bpf_link_settle(&link).unwrap();
        assert!(Arc::ptr_eq(&bpf_link_by_id(id).unwrap(), &link));
        let info = String::from_utf8(link.show_fdinfo()).unwrap();
        assert!(info.starts_with("link_type:\tcgroup\nlink_id:\t"));
        assert!(info.contains("prog_tag:\tabababababababab\n"));
        drop(link);
        assert!(released.load(Ordering::Relaxed));
        assert_eq!(bpf_link_by_id(id).err(), Some(Errno::ENOENT));
    }

    #[test]
    fn a_detached_link_has_no_program() {
        let released = Arc::new(AtomicBool::new(false));
        let link = BpfLink::new(7, Box::new(TestOps(released.clone())), prog(), 0);
        link.ops.detach(&link).unwrap();
        assert!(released.load(Ordering::Relaxed) && link.prog().is_none());
        let mut info = [0u8; BPF_LINK_INFO_SIZE];
        link.fill_info(&mut info).unwrap();
        assert_eq!(info[..12], [7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }
}
