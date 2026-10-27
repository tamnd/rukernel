//! The mount options of overlayfs, as fs/overlayfs/params.c of Linux.

use alloc::vec::Vec;
use rk_abi::Errno;
use rk_vfs::Result;

/// The value of the option `redirect_dir`, as `enum ovl_redirect_mode` of Linux.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Redirect {
    /// The mount does not make redirects, but it follows them, as Linux with the option
    /// `redirect_always_follow` of the module.
    Off,
    /// The mount does not make redirects, but it follows them. This is the default.
    #[default]
    Follow,
    /// The mount does not make redirects, and a lookup that finds one gives `EPERM`.
    NoFollow,
    /// The mount makes a redirect for a rename of a directory of a lower layer, and follows
    /// redirects.
    On,
}

impl Redirect {
    fn name(self) -> &'static [u8] {
        match self {
            Redirect::Off => b"off",
            Redirect::Follow => b"follow",
            Redirect::NoFollow => b"nofollow",
            Redirect::On => b"on",
        }
    }
}

/// The value of the option `uuid`, as `enum ovl_uuid` of Linux.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Uuid {
    /// The mount has no uuid. The file system id is the id of the real root.
    Off,
    /// The same as [`Uuid::Off`] for this file system.
    Null,
    /// The mount uses a uuid that the upper root keeps. A new overlay gets one. An old overlay
    /// without one gets [`Uuid::Null`]. This is the default.
    #[default]
    Auto,
    /// The mount uses the uuid that the upper root keeps, and makes it if it is not there.
    On,
}

impl Uuid {
    fn name(self) -> &'static [u8] {
        match self {
            Uuid::Off => b"off",
            Uuid::Null => b"null",
            Uuid::Auto => b"auto",
            Uuid::On => b"on",
        }
    }
}

/// The options of a mount.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Options {
    /// The lower directories, the top layer first.
    pub(crate) lowers: Vec<Vec<u8>>,
    /// The data-only lower directories, below the lower directories. A lookup finds a file in
    /// them only through an absolute redirect of a metacopy file.
    pub(crate) data: Vec<Vec<u8>>,
    /// The options `lowerdir+` and `datadir+` gave the lower directories.
    pub(crate) added: bool,
    pub(crate) upper: Option<Vec<u8>>,
    pub(crate) work: Option<Vec<u8>>,
    /// The option `userxattr`: the attributes of overlayfs have the prefix `user.overlay.`.
    pub(crate) userxattr: bool,
    pub(crate) redirect: Redirect,
    /// The option `metacopy`: a change of the attributes of a regular file copies up only the
    /// attributes.
    pub(crate) metacopy: bool,
    pub(crate) uuid: Uuid,
    /// The option `index`: a copy up of a lower hard link puts the upper file in the index
    /// directory, so the other names of the lower inode find it.
    pub(crate) index: bool,
    /// The option `nfs_export`: `name_to_handle_at` gives file handles of the overlay, and
    /// `open_by_handle_at` finds the files of these handles. It needs the option `index`.
    pub(crate) nfs_export: bool,
}

impl Options {
    /// Reads the data string of `mount(2)`, as `ovl_parse_param` and `ovl_fs_params_verify` of
    /// Linux. A comma separates the options. In `lowerdir=`, a colon separates the lower
    /// directories, and two colons put the data-only directories after them. A backslash before
    /// a comma or a colon makes it a part of the path. The values of `lowerdir+=` and `datadir+=`
    /// are paths without escapes. Linux ignores other options, such as `xino=off`, when it does
    /// not have the feature, and so does this file system.
    pub(crate) fn parse(data: &[u8]) -> Result<Options> {
        let mut out = Options::default();
        // The option `lowerdir=` was given. Then `lowerdir+=` and `datadir+=` are not valid.
        let mut lowerdir = false;
        let (mut set_redirect, mut set_metacopy) = (false, false);
        let (mut set_index, mut set_nfs_export) = (false, false);
        for opt in split_escaped(data, b',') {
            let (key, value) = match opt.iter().position(|&b| b == b'=') {
                Some(i) => (&opt[..i], Some(&opt[i + 1..])),
                None => (opt, None),
            };
            match (key, value) {
                (b"lowerdir", Some(v)) => {
                    out.set_lowerdir(v)?;
                    lowerdir = true;
                }
                (b"lowerdir+", Some(v)) => {
                    if lowerdir || v.is_empty() || !out.data.is_empty() {
                        return Err(Errno::EINVAL);
                    }
                    out.lowers.push(v.to_vec());
                    out.added = true;
                }
                (b"datadir+", Some(v)) => {
                    if lowerdir || v.is_empty() {
                        return Err(Errno::EINVAL);
                    }
                    out.data.push(v.to_vec());
                    out.added = true;
                }
                (b"upperdir", Some(v)) => out.upper = Some(unescape(v)),
                (b"workdir", Some(v)) => out.work = Some(unescape(v)),
                (b"userxattr", None) => out.userxattr = true,
                (b"redirect_dir", Some(v)) => {
                    out.redirect = match v {
                        b"on" => Redirect::On,
                        b"follow" => Redirect::Follow,
                        b"nofollow" => Redirect::NoFollow,
                        b"off" => Redirect::Off,
                        _ => return Err(Errno::EINVAL),
                    };
                    set_redirect = true;
                }
                (b"metacopy", Some(v)) => {
                    out.metacopy = on_off(v)?;
                    set_metacopy = true;
                }
                (b"index", Some(v)) => {
                    out.index = on_off(v)?;
                    set_index = true;
                }
                (b"nfs_export", Some(v)) => {
                    out.nfs_export = on_off(v)?;
                    set_nfs_export = true;
                }
                (b"uuid", Some(v)) => {
                    out.uuid = match v {
                        b"on" => Uuid::On,
                        b"auto" => Uuid::Auto,
                        b"null" => Uuid::Null,
                        b"off" => Uuid::Off,
                        _ => return Err(Errno::EINVAL),
                    };
                }
                _ => {}
            }
        }
        if out.lowers.is_empty() {
            return Err(Errno::EINVAL);
        }
        // A redirect is made only on the upper layer, so without it `follow` is the same as
        // `on`.
        if out.upper.is_none() && out.redirect == Redirect::Follow {
            out.redirect = Redirect::On;
        }
        // A metacopy file can be renamed only with a redirect.
        if out.metacopy && out.redirect != Redirect::On {
            if set_metacopy && set_redirect {
                return Err(Errno::EINVAL);
            }
            if set_redirect {
                out.metacopy = false;
            } else {
                out.redirect = Redirect::On;
            }
        }
        // The index is kept in the work directory, so a mount without an upper directory has
        // none.
        if out.upper.is_none() {
            out.index = false;
            set_index = false;
        }
        // The decode of a file handle needs the index. A mount without an upper directory has
        // no index, so it needs lower layers without redirects.
        if out.nfs_export && !out.index {
            if out.upper.is_none() && out.redirect != Redirect::NoFollow {
                out.nfs_export = false;
            } else if set_nfs_export && set_index {
                return Err(Errno::EINVAL);
            } else if set_index {
                out.nfs_export = false;
            } else {
                out.index = out.upper.is_some();
            }
        }
        // A metacopy file has no entry in the index, so a decode cannot find its upper inode.
        if out.nfs_export && out.metacopy {
            if set_nfs_export && set_metacopy {
                return Err(Errno::EINVAL);
            }
            if set_metacopy {
                out.nfs_export = false;
            } else {
                out.metacopy = false;
            }
        }
        // The uuid is kept in the upper root.
        if out.upper.is_none() && out.uuid == Uuid::On {
            out.uuid = Uuid::Null;
        }
        Ok(out)
    }

    /// Reads the value of `lowerdir=`, which replaces the lower directories of the options
    /// before it, as `ovl_parse_param_lowerdir` of Linux. An empty part, which two colons make,
    /// puts the next directory in the data-only layers. A lower directory cannot come after a
    /// data-only directory.
    fn set_lowerdir(&mut self, value: &[u8]) -> Result<()> {
        self.lowers.clear();
        self.data.clear();
        self.added = false;
        let parts = split_escaped(value, b':');
        let mut data = false;
        for (i, path) in parts.iter().enumerate() {
            if path.is_empty() {
                if i == 0 || i == parts.len() - 1 || data {
                    return Err(Errno::EINVAL);
                }
                data = true;
                continue;
            }
            if data {
                self.data.push(unescape(path));
            } else if self.data.is_empty() {
                self.lowers.push(unescape(path));
            } else {
                return Err(Errno::EINVAL);
            }
            data = false;
        }
        Ok(())
    }

    /// Gives the options for `/proc/PID/mountinfo`, as `ovl_show_options` of Linux.
    pub(crate) fn show(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.added {
            for path in &self.lowers {
                out.extend_from_slice(b",lowerdir+=");
                show_escaped(&mut out, path, b"");
            }
            for path in &self.data {
                out.extend_from_slice(b",datadir+=");
                show_escaped(&mut out, path, b"");
            }
        } else {
            out.extend_from_slice(b",lowerdir=");
            for (i, path) in self.lowers.iter().enumerate() {
                if i > 0 {
                    out.push(b':');
                }
                show_escaped(&mut out, path, b":");
            }
            for path in &self.data {
                out.extend_from_slice(b"::");
                show_escaped(&mut out, path, b":");
            }
        }
        if let (Some(upper), Some(work)) = (&self.upper, &self.work) {
            out.extend_from_slice(b",upperdir=");
            show_escaped(&mut out, upper, b"");
            out.extend_from_slice(b",workdir=");
            show_escaped(&mut out, work, b"");
        }
        if self.redirect != Redirect::Follow {
            out.extend_from_slice(b",redirect_dir=");
            out.extend_from_slice(self.redirect.name());
        }
        if self.index {
            out.extend_from_slice(b",index=on");
        }
        if self.uuid != Uuid::Auto {
            out.extend_from_slice(b",uuid=");
            out.extend_from_slice(self.uuid.name());
        }
        if self.nfs_export {
            out.extend_from_slice(b",nfs_export=on");
        }
        if self.metacopy {
            out.extend_from_slice(b",metacopy=on");
        }
        if self.userxattr {
            out.extend_from_slice(b",userxattr");
        }
        out
    }
}

/// Reads the value `on` or `off` of an option.
fn on_off(value: &[u8]) -> Result<bool> {
    match value {
        b"on" => Ok(true),
        b"off" => Ok(false),
        _ => Err(Errno::EINVAL),
    }
}

/// Splits `data` at each `sep` that has no backslash before it. The parts keep the backslashes.
pub(crate) fn split_escaped(data: &[u8], sep: u8) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let (mut start, mut i) = (0, 0);
    while i < data.len() {
        if data[i] == b'\\' {
            i += 2;
            continue;
        }
        if data[i] == sep {
            out.push(&data[start..i]);
            start = i + 1;
        }
        i += 1;
    }
    out.push(&data[start..]);
    out
}

/// Removes the backslashes of `s` that make the next byte a part of the path, as
/// `ovl_unescape` of Linux.
fn unescape(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.iter();
    while let Some(&b) = bytes.next() {
        if b == b'\\' {
            match bytes.next() {
                Some(&next) => out.push(next),
                None => break,
            }
        } else {
            out.push(b);
        }
    }
    out
}

/// Writes the path `s` for an option of `/proc/PID/mountinfo`. A byte of `extra`, a comma, an
/// equal sign, a space, a tab, a new line and a backslash become an octal escape, as
/// `seq_show_option` of Linux does.
fn show_escaped(out: &mut Vec<u8>, s: &[u8], extra: &[u8]) {
    for &b in s {
        if b",= \t\n\\".contains(&b) || extra.contains(&b) {
            out.extend_from_slice(alloc::format!("\\{b:03o}").as_bytes());
        } else {
            out.push(b);
        }
    }
}
