//! The directory `/sys/kernel/mm`. It has the directory `ksm` with the files of Kernel Samepage
//! Merging, as mm/ksm.c of Linux. A read of a file gives the value of that moment, and a write to
//! a file that a write can change goes to `rk_mm::ksm`.

use crate::Kind;
use alloc::string::String;
use alloc::vec::Vec;
use rk_abi::Errno;

/// The path of the directory of KSM, from the root of sysfs.
const KSM_DIR: &str = "kernel/mm/ksm/";

/// The entries of `/sys/kernel/mm` and of its directories. `rest` is the path below
/// `kernel/mm`. Gives `None` if no directory has the path.
pub(crate) fn entries(rest: &[&str]) -> Option<Vec<(String, Kind)>> {
    match rest {
        [] => Some(Vec::from([(String::from("ksm"), Kind::Dir)])),
        ["ksm"] => Some(
            rk_mm::ksm::sysfs_files()
                .into_iter()
                .map(|(name, _, writable)| (String::from(name), Kind::Ksm { writable }))
                .collect(),
        ),
        _ => None,
    }
}

/// The name of the file of KSM at `path`.
fn ksm_name(path: &str) -> &str {
    path.strip_prefix(KSM_DIR).unwrap_or(path)
}

/// The text of the file of KSM at `path`.
pub(crate) fn read(path: &str) -> Vec<u8> {
    let control = *rk_mm::ksm::CONTROL.lock();
    rk_mm::ksm::show(&control, ksm_name(path)).unwrap_or_default().into_bytes()
}

/// Writes `data` to the file of KSM at `path`, and gives the number of bytes that it took.
///
/// # Errors
///
/// The error of `rk_mm::ksm::sysfs_store`.
pub(crate) fn write(path: &str, data: &[u8]) -> Result<usize, Errno> {
    rk_mm::ksm::sysfs_store(ksm_name(path), data)?;
    Ok(data.len())
}
