//! The path walk, as `namei` of Linux.
//!
//! A walk starts at the root of the process for an absolute path, and at a directory for a
//! relative path. It goes through each component, goes down into a mount and up out of a mount,
//! and follows symbolic links. It stops at the root of the process for `..`, so a `chroot` holds.

use crate::dentry::{Location, MountNamespace};
use crate::inode::{FileType, Result};
use alloc::vec::Vec;
use rk_abi::Errno;

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
    links: u32,
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

fn is_symlink(at: &Location) -> bool {
    at.inode().metadata().file_type() == Some(FileType::Symlink)
}

fn is_dir(at: &Location) -> bool {
    at.inode().metadata().is_dir()
}

impl<'a> Walk<'a> {
    /// Starts a walk in the name space `ns` for a process with the root `root`.
    pub fn new(ns: &'a MountNamespace, root: &'a Location) -> Self {
        Self { ns, root, links: 0 }
    }

    /// Gives the location of `path`. A relative path starts at `start`. If `follow` is `false`, a
    /// symbolic link as the last component is not followed.
    pub fn resolve(&mut self, start: &Location, path: &[u8], follow: bool) -> Result<Location> {
        let parent = self.resolve_parent(start, path)?;
        let at = match &parent.name[..] {
            b"." => parent.dir,
            b".." => self.up(&parent.dir),
            name => {
                let next = self.child(&parent.dir, name)?;
                if is_symlink(&next) && (follow || parent.trailing_slash) {
                    self.follow(&parent.dir, &next)?
                } else {
                    next
                }
            }
        };
        if parent.trailing_slash && !is_dir(&at) {
            return Err(Errno::ENOTDIR);
        }
        Ok(at)
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
        let mut at = if path[0] == b'/' { self.root.clone() } else { start.clone() };
        let trailing_slash = path.ends_with(b"/");
        let parts: Vec<&[u8]> = path.split(|&b| b == b'/').filter(|p| !p.is_empty()).collect();
        let Some((last, dirs)) = parts.split_last() else {
            return Ok(Parent { dir: at, name: Vec::from(&b"."[..]), trailing_slash: false });
        };
        for part in dirs {
            at = self.step(&at, part)?;
        }
        if !is_dir(&at) {
            return Err(Errno::ENOTDIR);
        }
        if last.len() > NAME_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        Ok(Parent { dir: at, name: last.to_vec(), trailing_slash })
    }

    /// Goes from the directory `at` to the component `part`, and follows a symbolic link.
    fn step(&mut self, at: &Location, part: &[u8]) -> Result<Location> {
        if !is_dir(at) {
            return Err(Errno::ENOTDIR);
        }
        match part {
            b"." => Ok(at.clone()),
            b".." => Ok(self.up(at)),
            name => {
                if name.len() > NAME_MAX {
                    return Err(Errno::ENAMETOOLONG);
                }
                let next = self.child(at, name)?;
                if is_symlink(&next) { self.follow(at, &next) } else { Ok(next) }
            }
        }
    }

    /// Follows the symbolic link `link` in the directory `dir`. The result can be a link only
    /// if the target ends in a link that the walk does not follow.
    fn follow(&mut self, dir: &Location, link: &Location) -> Result<Location> {
        self.links += 1;
        if self.links > MAX_LINKS {
            return Err(Errno::ELOOP);
        }
        let target = link.inode().read_link()?;
        self.resolve(dir, &target, true)
    }

    /// The child `name` of the directory `at`, in the mount that is on top of it.
    fn child(&self, at: &Location, name: &[u8]) -> Result<Location> {
        let dentry = at.dentry.lookup(name)?;
        let mut next = Location { mount: at.mount.clone(), dentry };
        while let Some(mount) = self.ns.mounted_on(&next) {
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
                Some(below) => at = below.clone(),
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
                        at = below.clone();
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
