//! AppArmor, as security/apparmor of Linux.
//!
//! AppArmor confines a program with a profile. The policy compiler `apparmor_parser` loads the
//! profiles through the files of `/sys/kernel/security/apparmor`. This crate has the module and
//! its files ([`fs`]), the features that the kernel tells the compiler ([`features`]), the
//! unpack of the binary policy ([`unpack`]) with its DFA tables ([`dfa`]), the policy namespace
//! that holds the profiles ([`policy`]), the audit records ([`audit`]), the label of a task
//! with its change at an exec ([`domain`]) and the checks of the open files ([`file`]).
//!
//! The module is active when the command line has `apparmor=1`, or when `lsm=` names it. With
//! `apparmor=0` it is not active. This is the value 0 of the old
//! `CONFIG_SECURITY_APPARMOR_BOOTPARAM_VALUE` of Linux. The file
//! `/sys/module/apparmor/parameters/enabled` tells if the module is active.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod audit;
pub mod dfa;
pub mod domain;
pub mod features;
pub mod file;
pub mod fs;
pub mod policy;
pub mod unpack;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use rk_vfs::cred::Cred;
use rk_vfs::file::File;
use rk_vfs::inode::Result;
use rk_vfs::security::{
    BlobSizes, Bprm, FLAG_EXCLUSIVE, FLAG_LEGACY_MAJOR, LsmId, LsmInfo, Order, SecurityHooks, Task,
    id,
};

/// The hooks of AppArmor. Each profile acts in complain mode, so each hook allows the
/// operation.
struct AppArmor;

impl SecurityHooks for AppArmor {
    fn bprm_creds_for_exec(&self, bprm: &mut Bprm<'_>) -> Result<()> {
        domain::bprm_creds_for_exec(bprm);
        Ok(())
    }

    fn file_alloc_security(&self, f: &File) {
        file::file_alloc(f);
    }

    fn file_open(&self, f: &File, cred: &Cred, flags: u32) -> Result<()> {
        file::file_open(f, cred, flags);
        Ok(())
    }

    fn file_permission(&self, f: &File, mask: u32) -> Result<()> {
        file::file_perm(file::op::FPERM, f, mask);
        Ok(())
    }

    fn file_lock(&self, f: &File, cmd: u32) -> Result<()> {
        file::file_lock(f, cmd);
        Ok(())
    }

    fn mmap_file(&self, f: Option<&File>, _reqprot: u64, prot: u64, flags: u64) -> Result<()> {
        file::mmap_file(f, prot, flags);
        Ok(())
    }

    fn getprocattr(&self, task: &Task<'_>, name: &str) -> Option<Result<Vec<u8>>> {
        Some(domain::getprocattr(task, name))
    }
}

/// The description of the module, as `DEFINE_LSM(apparmor)` of Linux. AppArmor is a major
/// module that `security=apparmor` selects, and it cannot be active with another exclusive
/// module, as SELinux.
pub static LSM: LsmInfo = LsmInfo {
    id: LsmId { name: "apparmor", id: id::APPARMOR },
    order: Order::Mutable,
    flags: FLAG_LEGACY_MAJOR | FLAG_EXCLUSIVE,
    blobs: BlobSizes { cred: domain::CRED_BLOB, file: file::FILE_BLOB, ..BlobSizes::NONE },
    hooks: &AppArmor,
};

/// The module is active, `apparmor_enabled` and `apparmor_initialized` of Linux.
static ENABLED: AtomicBool = AtomicBool::new(false);

/// Tells if the module is active.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Tells if the module can be active, from the values of the parameters `apparmor=` and `lsm=`
/// of the command line, as `apparmor_enabled_setup` of Linux. `apparmor=` takes a number, and a
/// value that is not 0 makes the module active. A value that is not a number has no effect.
/// Without `apparmor=`, the module is active only if `lsm=` names it.
pub fn wanted(apparmor: Option<&str>, lsm: Option<&str>) -> bool {
    match apparmor.and_then(parse_ulong) {
        Some(v) => v != 0,
        None => lsm.is_some_and(|l| l.split(',').any(|m| m == "apparmor")),
    }
}

/// Parses a number as `kstrtoul` with the base 0: decimal, octal with `0`, or hex with `0x`.
fn parse_ulong(s: &str) -> Option<u64> {
    let s = s.strip_suffix('\n').unwrap_or(s);
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if s.len() > 1 && s.starts_with('0') {
        u64::from_str_radix(&s[1..], 8).ok()
    } else {
        s.parse().ok()
    }
}

/// The text of the parameter `enabled`, as `param_get_aaintbool` of Linux.
fn enabled_text() -> String {
    String::from(if enabled() { "Y\n" } else { "N\n" })
}

/// Starts the module after `rk_vfs::security::init`, as `apparmor_init` and
/// `aa_create_aafs` of Linux. The parameter `enabled` is always there, as on Linux, where the
/// module is in the kernel. The files of securityfs are there only if the module is active.
pub fn init() {
    rk_fs_sys::add_param(rk_fs_sys::Param {
        module: "apparmor",
        name: "enabled",
        read: enabled_text,
    });
    let active = rk_vfs::security::modules().iter().any(|m| m.info.id.id == id::APPARMOR);
    if !active {
        return;
    }
    ENABLED.store(true, Ordering::Relaxed);
    fs::init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_parameters_of_the_command_line_select_the_module() {
        assert!(!wanted(None, None));
        assert!(wanted(Some("1"), None));
        assert!(wanted(Some("0x10"), None));
        assert!(!wanted(Some("0"), Some("capability,apparmor")));
        assert!(wanted(None, Some("capability,yama,apparmor")));
        assert!(!wanted(None, Some("capability,yama")));
        assert!(!wanted(Some("yes"), None));
        assert!(wanted(Some("yes"), Some("apparmor")));
        assert_eq!(parse_ulong("010"), Some(8));
        assert_eq!(parse_ulong("x"), None);
    }
}
