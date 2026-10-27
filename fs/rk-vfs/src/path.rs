//! The path walk, as `namei` of Linux.
//!
//! A walk starts at the root of the process for an absolute path, and at a directory for a
//! relative path. It goes through each component, goes down into a mount and up out of a mount,
//! and follows symbolic links. It stops at the root of the process for `..`, so a `chroot` holds.

use crate::cred::{Cred, may, protected};
use crate::dentry::{Location, MountNamespace};
use crate::inode::{FileType, Result};
use alloc::sync::Arc;
use alloc::vec::Vec;
use rk_abi::Errno;

/// The `RESOLVE_*` flags of `openat2`, as include/uapi/linux/openat2.h of Linux.
pub mod resolve {
    /// The walk does not cross a mount.
    pub const NO_XDEV: u32 = 0x01;
    /// The walk does not follow a magic link of `/proc`.
    pub const NO_MAGICLINKS: u32 = 0x02;
    /// The walk does not follow a symbolic link.
    pub const NO_SYMLINKS: u32 = 0x04;
    /// The walk stays under the start directory. An escape gives `EXDEV`.
    pub const BENEATH: u32 = 0x08;
    /// The start directory is the root of the walk, as a `chroot`.
    pub const IN_ROOT: u32 = 0x10;
    /// The walk uses only the dentry cache.
    pub const CACHED: u32 = 0x20;
    /// All the flags.
    pub const ALL: u32 = NO_XDEV | NO_MAGICLINKS | NO_SYMLINKS | BENEATH | IN_ROOT | CACHED;
}

/// The number of symbolic links that one walk follows before it gives `ELOOP`, as Linux.
pub const MAX_LINKS: u32 = 40;

/// The longest name of one component.
pub const NAME_MAX: usize = 255;

/// The longest path, with the zero byte at the end.
pub const PATH_MAX: usize = 4096;

/// The state of one walk.
pub struct Walk<'a> {
    ns: &'a MountNamespace,
    root: &'a Location,
    cred: &'a Cred,
    links: u32,
    /// The `RESOLVE_*` flags. With `BENEATH` or `IN_ROOT`, `root` is the start directory.
    flags: u32,
}

/// The last component of a path and the directory that holds it.
pub struct Parent {
    /// The directory.
    pub dir: Location,
    /// The last component. It is `.` or `..` if the path ends in one of them.
    pub name: Vec<u8>,
    /// The path ends with `/`.
    pub trailing_slash: bool,
}

impl Parent {
    /// Tells if the last component is `.` or `..`, which a create, a remove or a rename cannot
    /// use.
    pub fn is_dot(&self) -> bool {
        self.name == b"." || self.name == b".."
    }
}

/// The components of `path`, with the first one at the end.
fn components(path: &[u8]) -> Vec<Vec<u8>> {
    path.split(|&b| b == b'/').filter(|p| !p.is_empty()).rev().map(<[u8]>::to_vec).collect()
}

fn is_symlink(at: &Location) -> bool {
    at.inode().metadata().file_type() == Some(FileType::Symlink)
}

fn is_dir(at: &Location) -> bool {
    at.inode().metadata().is_dir()
}

impl<'a> Walk<'a> {
    /// Starts a walk in the name space `ns` for a process with the root `root` and the
    /// credentials `cred`. The walk needs the search permission on each directory that it goes
    /// through.
    pub fn new(ns: &'a MountNamespace, root: &'a Location, cred: &'a Cred) -> Self {
        Self { ns, root, cred, links: 0, flags: 0 }
    }

    /// Sets the `RESOLVE_*` flags of `openat2`, as `LOOKUP_NO_XDEV` and the other scope flags
    /// of Linux.
    pub fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Checks a jump to the root for an absolute path or an absolute link target from `at`, as
    /// the jump to the root in fs/namei.c of Linux.
    fn jump_root(&self, at: &Location) -> Result<Location> {
        if self.flags & resolve::BENEATH != 0 {
            return Err(Errno::EXDEV);
        }
        if self.flags & resolve::NO_XDEV != 0 && !Arc::ptr_eq(&at.mount, &self.root.mount) {
            return Err(Errno::EXDEV);
        }
        Ok(self.root.clone())
    }

    /// Checks that the walk can follow a symbolic link, as `pick_link` of Linux.
    fn may_follow(&self) -> Result<()> {
        if self.flags & resolve::NO_SYMLINKS != 0 { Err(Errno::ELOOP) } else { Ok(()) }
    }

    /// Goes to the parent of `at` for `..`, as `follow_dotdot` of Linux. `BENEATH` gives
    /// `EXDEV` at the start directory, and `NO_XDEV` gives `EXDEV` out of a mount.
    fn dotdot(&self, at: &Location) -> Result<Location> {
        if self.flags & resolve::BENEATH != 0 && at.same(self.root) {
            return Err(Errno::EXDEV);
        }
        let up = self.up(at);
        if self.flags & resolve::NO_XDEV != 0 && !Arc::ptr_eq(&up.mount, &at.mount) {
            return Err(Errno::EXDEV);
        }
        Ok(up)
    }

    /// Checks that the walk can look up a name in the directory `at`, as `may_lookup` of Linux.
    fn may_lookup(&self, at: &Location) -> Result<()> {
        if !at.inode().metadata().is_dir() {
            return Err(Errno::ENOTDIR);
        }
        self.cred.inode_permission(&**at.inode(), may::EXEC)
    }

    /// Gives the location of `path`. A relative path starts at `start`. If `follow` is `false`, a
    /// symbolic link as the last component is not followed.
    ///
    /// The walk is a loop and not a recursion, so that a chain of `MAX_LINKS` symbolic links
    /// does not use much of the kernel stack.
    pub fn resolve(&mut self, start: &Location, path: &[u8], follow: bool) -> Result<Location> {
        let mut parent = self.resolve_parent(start, path)?;
        let mut follow = follow;
        // A path or a link target that ends with `/` must give a directory.
        let mut must_be_dir = false;
        loop {
            let Parent { dir, name, trailing_slash } = parent;
            must_be_dir |= trailing_slash;
            let at = match &name[..] {
                b"." => dir,
                b".." => self.dotdot(&dir)?,
                name => {
                    let next = self.child(&dir, name)?;
                    if is_symlink(&next) && (follow || trailing_slash) {
                        self.may_follow()?;
                        if let Some(jump) = self.jump(&dir, &next)? {
                            if must_be_dir && !is_dir(&jump) {
                                return Err(Errno::ENOTDIR);
                            }
                            return Ok(jump);
                        }
                        let target = self.link_target(&dir, &next)?;
                        parent = self.resolve_parent(&dir, &target)?;
                        follow = true;
                        continue;
                    }
                    next
                }
            };
            if must_be_dir && !is_dir(&at) {
                return Err(Errno::ENOTDIR);
            }
            return Ok(at);
        }
    }

    /// Gives the directory of the last component of `path` and the last component. The last
    /// component does not have to exist. The path `/` gives the root and the name `.`.
    pub fn resolve_parent(&mut self, start: &Location, path: &[u8]) -> Result<Parent> {
        if path.is_empty() {
            return Err(Errno::ENOENT);
        }
        if path.len() >= PATH_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        let mut at = if path[0] == b'/' { self.jump_root(start)? } else { start.clone() };
        let trailing_slash = path.ends_with(b"/");
        // The components that are left, with the next one at the end. A symbolic link adds the
        // components of its target.
        let mut rest = components(path);
        let Some(last) = rest.first().cloned() else {
            return Ok(Parent { dir: at, name: Vec::from(&b"."[..]), trailing_slash: false });
        };
        rest.remove(0);
        while let Some(part) = rest.pop() {
            at = self.step(&at, &part, &mut rest)?;
        }
        self.may_lookup(&at)?;
        if last.len() > NAME_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        Ok(Parent { dir: at, name: last, trailing_slash })
    }

    /// Goes from the directory `at` to the component `part`. For a symbolic link, it adds the
    /// components of the target to `rest` and gives the place where the target starts.
    fn step(&mut self, at: &Location, part: &[u8], rest: &mut Vec<Vec<u8>>) -> Result<Location> {
        self.may_lookup(at)?;
        match part {
            b"." => Ok(at.clone()),
            b".." => self.dotdot(at),
            name => {
                if name.len() > NAME_MAX {
                    return Err(Errno::ENAMETOOLONG);
                }
                let next = self.child(at, name)?;
                if !is_symlink(&next) {
                    return Ok(next);
                }
                self.may_follow()?;
                if let Some(jump) = self.jump(at, &next)? {
                    return Ok(jump);
                }
                let target = self.link_target(at, &next)?;
                if target.is_empty() {
                    return Err(Errno::ENOENT);
                }
                if target.len() >= PATH_MAX {
                    return Err(Errno::ENAMETOOLONG);
                }
                rest.extend(components(&target));
                if target[0] == b'/' { self.jump_root(at) } else { Ok(at.clone()) }
            }
        }
    }

    /// Gives the target of the symbolic link `link` in the directory `dir`, and counts the link.
    /// Gives `ELOOP` after `MAX_LINKS` links in one walk, and `EACCES` if
    /// `fs.protected_symlinks` forbids the follow.
    fn link_target(&mut self, dir: &Location, link: &Location) -> Result<Vec<u8>> {
        self.links += 1;
        if self.links > MAX_LINKS {
            return Err(Errno::ELOOP);
        }
        let level = protected::get(&protected::SYMLINKS);
        self.cred.may_follow_link(level, &dir.inode().metadata(), &link.inode().metadata())?;
        link.inode().follow_link()
    }

    /// Gives the place of the magic link `link` in `dir`, or `None` for a usual symbolic link.
    /// A magic link counts as a link for `ELOOP`. The checks of the `RESOLVE_*` flags are the
    /// checks of `pick_link` and of the jump of a magic link in fs/namei.c of Linux.
    fn jump(&mut self, dir: &Location, link: &Location) -> Result<Option<Location>> {
        let Some(jump) = link.inode().magic_link() else { return Ok(None) };
        if self.flags & resolve::NO_MAGICLINKS != 0 {
            return Err(Errno::ELOOP);
        }
        self.links += 1;
        if self.links > MAX_LINKS {
            return Err(Errno::ELOOP);
        }
        let jump = jump?;
        if self.flags & resolve::NO_XDEV != 0 && !Arc::ptr_eq(&jump.mount, &dir.mount) {
            return Err(Errno::EXDEV);
        }
        if self.flags & (resolve::BENEATH | resolve::IN_ROOT) != 0 {
            return Err(Errno::EXDEV);
        }
        Ok(Some(jump))
    }

    /// The child `name` of the directory `at`, in the mount that is on top of it.
    fn child(&self, at: &Location, name: &[u8]) -> Result<Location> {
        let dentry = at.dentry.lookup(name)?;
        let mut next = Location { mount: at.mount.clone(), dentry };
        while let Some(mount) = self.ns.mounted_on(&next) {
            if self.flags & resolve::NO_XDEV != 0 {
                return Err(Errno::EXDEV);
            }
            next = Location { dentry: mount.root().clone(), mount };
        }
        Ok(next)
    }

    /// The parent of the directory `at`. The parent of the root of the process is the root.
    pub fn up(&self, at: &Location) -> Location {
        let mut at = at.clone();
        loop {
            if at.same(self.root) {
                return at;
            }
            if !at.is_mount_root() {
                break;
            }
            match at.mount.mountpoint() {
                Some(below) => at = below,
                None => return at,
            }
        }
        match at.dentry.parent() {
            Some(dentry) => Location { mount: at.mount, dentry },
            None => at,
        }
    }

    /// The absolute path of `at`, as `getcwd` gives it. A location that is not under the root of
    /// the process gives `ENOENT`, as a location that was removed does.
    pub fn path_of(&self, at: &Location) -> Result<Vec<u8>> {
        let mut parts: Vec<Vec<u8>> = Vec::new();
        let mut at = at.clone();
        loop {
            if at.same(self.root) {
                break;
            }
            if at.is_mount_root() {
                match at.mount.mountpoint() {
                    Some(below) => {
                        at = below;
                        continue;
                    }
                    None => return Err(Errno::ENOENT),
                }
            }
            let Some(parent) = at.dentry.parent() else { return Err(Errno::ENOENT) };
            parts.push(at.dentry.name());
            at = Location { mount: at.mount, dentry: parent };
        }
        let mut path = Vec::new();
        for part in parts.iter().rev() {
            path.push(b'/');
            path.extend_from_slice(part);
        }
        if path.is_empty() {
            path.push(b'/');
        }
        Ok(path)
    }
}
