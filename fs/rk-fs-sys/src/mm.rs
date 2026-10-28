//! The directory `/sys/kernel/mm`. It has the directory `transparent_hugepage`, which lib.rs
//! makes, the directory `ksm` with the files of Kernel Samepage Merging, as mm/ksm.c of Linux,
//! and the directory `hugepages` with the counters of the pool of hugetlbfs, as mm/hugetlb.c of
//! Linux. A read of a file gives the value of that moment, and a write to a file that a write can
//! change goes to `rk_mm::ksm` or `rk_mm::hugetlb`.

use crate::Kind;
use alloc::string::String;
use alloc::vec::Vec;
use rk_abi::Errno;

/// The path of the directory of KSM, from the root of sysfs.
const KSM_DIR: &str = "kernel/mm/ksm/";

/// The path of the directory of the pool of hugetlbfs, from the root of sysfs.
const HUGE_DIR: &str = "kernel/mm/hugepages/hugepages-2048kB/";

/// The entries of `/sys/kernel/mm` and of its directories. `rest` is the path below
/// `kernel/mm`. Gives `None` if no directory has the path.
pub(crate) fn entries(rest: &[&str]) -> Option<Vec<(String, Kind)>> {
    match rest {
        [] => Some(Vec::from([
            (String::from("hugepages"), Kind::Dir),
            (String::from("ksm"), Kind::Dir),
            (String::from("transparent_hugepage"), Kind::Dir),
        ])),
        ["hugepages"] => Some(Vec::from([(String::from(rk_mm::hugetlb::HPAGE_DIR), Kind::Dir)])),
        ["hugepages", dir] if *dir == rk_mm::hugetlb::HPAGE_DIR => Some(
            rk_mm::hugetlb::SYSFS_FILES
                .iter()
                .map(|&(name, writable)| (String::from(name), Kind::Mm { writable }))
                .collect(),
        ),
        ["ksm"] => Some(
            rk_mm::ksm::sysfs_files()
                .into_iter()
                .map(|(name, _, writable)| (String::from(name), Kind::Mm { writable }))
                .collect(),
        ),
        _ => None,
    }
}

/// The name of the file of KSM at `path`.
fn ksm_name(path: &str) -> &str {
    path.strip_prefix(KSM_DIR).unwrap_or(path)
}

/// The text of the file of KSM or of the pool at `path`.
pub(crate) fn read(path: &str) -> Vec<u8> {
    if let Some(name) = path.strip_prefix(HUGE_DIR) {
        let counts = rk_mm::hugetlb::counts();
        return rk_mm::hugetlb::show(&counts, name).unwrap_or_default().into_bytes();
    }
    let control = *rk_mm::ksm::CONTROL.lock();
    rk_mm::ksm::show(&control, ksm_name(path)).unwrap_or_default().into_bytes()
}

/// Writes `data` to the file of KSM or of the pool at `path`, and gives the number of bytes that
/// it took.
///
/// # Errors
///
/// The error of `rk_mm::ksm::sysfs_store` or of `rk_mm::hugetlb::store`.
pub(crate) fn write(path: &str, data: &[u8]) -> Result<usize, Errno> {
    if let Some(name) = path.strip_prefix(HUGE_DIR) {
        rk_mm::hugetlb::store(name, data)?;
        return Ok(data.len());
    }
    rk_mm::ksm::sysfs_store(ksm_name(path), data)?;
    Ok(data.len())
}
