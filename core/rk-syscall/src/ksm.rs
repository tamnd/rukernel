//! The calls of Kernel Samepage Merging: `prctl(PR_SET_MEMORY_MERGE)` and
//! `prctl(PR_GET_MEMORY_MERGE)`. `madvise` in `mm.rs` gives `MADV_MERGEABLE` and
//! `MADV_UNMERGEABLE`. The merge logic is in rk-mm.

use crate::cx::{Cx, SysResult};
use rk_abi::Errno;

/// `PR_SET_MEMORY_MERGE` of `<linux/prctl.h>`.
const PR_SET_MEMORY_MERGE: u64 = 67;
/// `PR_GET_MEMORY_MERGE` of `<linux/prctl.h>`.
const PR_GET_MEMORY_MERGE: u64 = 68;

/// Does the `prctl` options of KSM. Gives `None` for another option.
pub(crate) fn prctl(cx: &Cx<'_>, option: u64, args: [u64; 4]) -> Option<SysResult> {
    Some(match option {
        PR_SET_MEMORY_MERGE => {
            if args[1..].iter().any(|&a| a != 0) {
                return Some(Err(Errno::EINVAL));
            }
            cx.vm().and_then(|vm| rk_mm::ksm::set_merge_any(&vm, args[0] != 0)).map(|()| 0)
        }
        PR_GET_MEMORY_MERGE => {
            if args.iter().any(|&a| a != 0) {
                return Some(Err(Errno::EINVAL));
            }
            cx.vm().map(|vm| u64::from(rk_mm::ksm::merge_any(&vm)))
        }
        _ => return None,
    })
}
