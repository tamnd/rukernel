//! The table of binfmt_misc, as fs/binfmt_misc.c of Linux: the formats of programs that an
//! interpreter runs, by a magic number or by the extension of the name.
//!
//! A write of `:name:type:offset:magic:mask:interpreter:flags` to the file `register` adds a
//! format. An exec of a file that is not a program of this machine and not a script then finds
//! the format, and runs the interpreter with the path of the file as its first argument. The
//! file system that shows the table is in rk-fs-sys.
//!
//! The flags `O` and `C` give the interpreter an open file of the program on Linux. This kernel
//! keeps and shows them, but the interpreter gets only the path.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use rk_abi::Errno;
use rk_frame::sync::SpinLock;

use crate::inode::Result;

/// The size of the start of a file that the magic number can be in, `BINPRM_BUF_SIZE` of Linux.
pub const BUF_SIZE: usize = 256;

/// The longest text that `register` takes, `MAX_REGISTER_LENGTH` of Linux.
const MAX_REGISTER_LENGTH: usize = 1920;

/// The flag `P`: the interpreter gets the old `argv[0]` after the path of the file.
pub const PRESERVE_ARGV0: u8 = 1;
/// The flag `O`: the interpreter gets an open file of the program.
pub const OPEN_BINARY: u8 = 2;
/// The flag `C`: the credentials come from the program. It sets `O` too.
pub const CREDENTIALS: u8 = 4;
/// The flag `F`: the kernel opens the interpreter at the time of the register.
pub const FIX_BINARY: u8 = 8;

/// How a format finds its files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Match {
    /// The bytes at `offset`, after an AND with `mask`, are the same as `magic`.
    Magic {
        /// The offset of the magic bytes in the file.
        offset: usize,
        /// The magic bytes.
        magic: Vec<u8>,
        /// The mask, with the same length as `magic`.
        mask: Option<Vec<u8>>,
    },
    /// The name of the file ends with `.` and this extension.
    Extension(Vec<u8>),
}

/// A format of binfmt_misc.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Format {
    /// The name of the file of the format.
    pub name: String,
    /// The test that a file must pass.
    pub what: Match,
    /// The path of the interpreter.
    pub interpreter: Vec<u8>,
    /// `PRESERVE_ARGV0`, `OPEN_BINARY`, `CREDENTIALS` and `FIX_BINARY`.
    pub flags: u8,
    /// A disabled format does not run files.
    pub enabled: bool,
}

/// The formats, the newest first, as Linux adds a format at the head of its list.
static FORMATS: SpinLock<Vec<Format>> = SpinLock::new(Vec::new());
/// The state of the file `status`.
static ENABLED: AtomicBool = AtomicBool::new(true);

/// Reads the bytes up to the next `del`, and gives them and the rest after `del`. A `\xHH`
/// sequence in the field does not end it, as `scanarg` of Linux.
fn field(s: &[u8], del: u8, hex: bool) -> Option<(&[u8], &[u8])> {
    let mut i = 0;
    while i < s.len() {
        if hex && s[i] == b'\\' && s.get(i + 1) == Some(&b'x') {
            let ok = s.get(i + 2..i + 4).is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit));
            if !ok {
                return None;
            }
            i += 4;
            continue;
        }
        if s[i] == del {
            return Some((&s[..i], &s[i + 1..]));
        }
        i += 1;
    }
    None
}

/// Changes each `\xHH` to its byte, as `string_unescape_inplace` with `UNESCAPE_HEX` of Linux.
fn unescape(s: &[u8]) -> Vec<u8> {
    let hex = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'\\' && s.get(i + 1) == Some(&b'x') && i + 3 < s.len() {
            out.push((hex(s[i + 2]) << 4) | hex(s[i + 3]));
            i += 4;
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    out
}

/// Reads a format from the text of a write to `register`, as `create_entry` of Linux.
///
/// # Errors
///
/// Gives `EINVAL` for a text that is not in the format.
pub fn parse(text: &[u8]) -> Result<Format> {
    if text.len() < 11 || text.len() > MAX_REGISTER_LENGTH {
        return Err(Errno::EINVAL);
    }
    let del = text[0];
    // The last field can end at the end of the text, as Linux adds a delimiter there.
    let mut owned = text[1..].to_vec();
    owned.push(del);
    let s = &owned[..];
    let (name, s) = field(s, del, false).ok_or(Errno::EINVAL)?;
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
        return Err(Errno::EINVAL);
    }
    let name = String::from(core::str::from_utf8(name).map_err(|_| Errno::EINVAL)?);
    let (kind, s) = match s {
        [k @ (b'E' | b'M'), d, rest @ ..] if *d == del => (*k, rest),
        _ => return Err(Errno::EINVAL),
    };
    let (what, s) = if kind == b'M' {
        let (offset, s) = field(s, del, false).ok_or(Errno::EINVAL)?;
        let offset = if offset.is_empty() {
            0
        } else {
            let t = core::str::from_utf8(offset).map_err(|_| Errno::EINVAL)?;
            t.parse::<usize>().map_err(|_| Errno::EINVAL)?
        };
        let (magic, s) = field(s, del, true).ok_or(Errno::EINVAL)?;
        let magic = unescape(magic);
        if magic.is_empty() || offset.checked_add(magic.len()).is_none_or(|e| e > BUF_SIZE) {
            return Err(Errno::EINVAL);
        }
        let (mask, s) = field(s, del, true).ok_or(Errno::EINVAL)?;
        let mask = if mask.is_empty() {
            None
        } else {
            let mask = unescape(mask);
            if mask.len() != magic.len() {
                return Err(Errno::EINVAL);
            }
            Some(mask)
        };
        // The magic keeps only the bits of the mask, as Linux keeps it.
        let magic = match &mask {
            Some(m) => magic.iter().zip(m).map(|(a, b)| a & b).collect(),
            None => magic,
        };
        (Match::Magic { offset, magic, mask }, s)
    } else {
        let (offset, s) = field(s, del, false).ok_or(Errno::EINVAL)?;
        let (ext, s) = field(s, del, false).ok_or(Errno::EINVAL)?;
        let (mask, s) = field(s, del, false).ok_or(Errno::EINVAL)?;
        if !offset.is_empty() || !mask.is_empty() || ext.is_empty() || ext.contains(&b'/') {
            return Err(Errno::EINVAL);
        }
        (Match::Extension(ext.to_vec()), s)
    };
    let (interpreter, s) = field(s, del, false).ok_or(Errno::EINVAL)?;
    if interpreter.is_empty() {
        return Err(Errno::EINVAL);
    }
    // The flags end at the first byte that is not a flag. Then only a new line can come, and
    // the delimiter that this function added.
    let mut flags = 0;
    let mut rest = s;
    while let [c, tail @ ..] = rest {
        flags |= match c {
            b'P' => PRESERVE_ARGV0,
            b'O' => OPEN_BINARY,
            b'C' => CREDENTIALS | OPEN_BINARY,
            b'F' => FIX_BINARY,
            _ => break,
        };
        rest = tail;
    }
    let rest = rest.strip_prefix(b"\n").unwrap_or(rest);
    if rest != [del] {
        return Err(Errno::EINVAL);
    }
    Ok(Format { name, what, interpreter: interpreter.to_vec(), flags, enabled: true })
}

/// Adds the format of the text `text`, as `bm_register_write` of Linux.
///
/// # Errors
///
/// Gives `EINVAL` for a bad text and `EEXIST` if a format has the name already.
pub fn register(text: &[u8]) -> Result<()> {
    let f = parse(text)?;
    let mut formats = FORMATS.lock();
    if formats.iter().any(|g| g.name == f.name) {
        return Err(Errno::EEXIST);
    }
    formats.insert(0, f);
    Ok(())
}

/// The names of the formats, the oldest first, in the order of the files of Linux.
#[must_use]
pub fn names() -> Vec<String> {
    FORMATS.lock().iter().rev().map(|f| f.name.clone()).collect()
}

/// The format with the name `name`.
#[must_use]
pub fn get(name: &str) -> Option<Format> {
    FORMATS.lock().iter().find(|f| f.name == name).cloned()
}

/// Reads the text of a write to `status` or to the file of a format, as `parse_command` of
/// Linux: `0` stops, `1` starts and `-1` removes.
fn command(text: &[u8]) -> Result<i8> {
    if text.len() > 3 {
        return Err(Errno::EINVAL);
    }
    match text.strip_suffix(b"\n").unwrap_or(text) {
        b"0" => Ok(0),
        b"1" => Ok(1),
        b"-1" => Ok(-1),
        _ => Err(Errno::EINVAL),
    }
}

/// Does a write to `status`: `0` and `1` stop and start all formats, and `-1` removes all.
///
/// # Errors
///
/// Gives `EINVAL` for another text.
pub fn write_status(text: &[u8]) -> Result<()> {
    match command(text)? {
        -1 => FORMATS.lock().clear(),
        c => ENABLED.store(c == 1, Ordering::Relaxed),
    }
    Ok(())
}

/// The text of `status`.
#[must_use]
pub fn status() -> &'static [u8] {
    if ENABLED.load(Ordering::Relaxed) { b"enabled\n" } else { b"disabled\n" }
}

/// Does a write to the file of the format `name`: `0` and `1` stop and start it, and `-1`
/// removes it.
///
/// # Errors
///
/// Gives `EINVAL` for another text and `ENOENT` if the format is gone.
pub fn write_format(name: &str, text: &[u8]) -> Result<()> {
    let c = command(text)?;
    let mut formats = FORMATS.lock();
    let i = formats.iter().position(|f| f.name == name).ok_or(Errno::ENOENT)?;
    if c == -1 {
        formats.remove(i);
    } else {
        formats[i].enabled = c == 1;
    }
    Ok(())
}

/// The text of the file of the format `f`, as `entry_status` of Linux.
#[must_use]
pub fn show(f: &Format) -> Vec<u8> {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let mut out = format!(
        "{}\ninterpreter {}\nflags: ",
        if f.enabled { "enabled" } else { "disabled" },
        String::from_utf8_lossy(&f.interpreter)
    );
    for (bit, c) in
        [(PRESERVE_ARGV0, 'P'), (CREDENTIALS, 'C'), (OPEN_BINARY, 'O'), (FIX_BINARY, 'F')]
    {
        if f.flags & bit != 0 {
            out.push(c);
        }
    }
    out.push('\n');
    match &f.what {
        Match::Extension(ext) => {
            out.push_str(&format!("extension .{}\n", String::from_utf8_lossy(ext)))
        }
        Match::Magic { offset, magic, mask } => {
            out.push_str(&format!("offset {offset}\nmagic {}\n", hex(magic)));
            if let Some(mask) = mask {
                out.push_str(&format!("mask {}\n", hex(mask)));
            }
        }
    }
    out.into_bytes()
}

/// Finds the format of the file with the path `path` whose first bytes are `head`, as
/// `check_file` of Linux. Gives the interpreter and the flags. `head` has zeros after the end of
/// a short file.
#[must_use]
pub fn find(head: &[u8], path: &[u8]) -> Option<(Vec<u8>, u8)> {
    if !ENABLED.load(Ordering::Relaxed) {
        return None;
    }
    let formats = FORMATS.lock();
    let f = formats.iter().filter(|f| f.enabled).find(|f| match &f.what {
        Match::Extension(ext) => {
            path.iter().rposition(|&c| c == b'.').is_some_and(|i| &path[i + 1..] == ext.as_slice())
        }
        Match::Magic { offset, magic, mask } => magic.iter().enumerate().all(|(j, &m)| {
            let b = head.get(offset + j).copied().unwrap_or(0);
            (b ^ m) & mask.as_ref().map_or(0xff, |k| k[j]) == 0
        }),
    })?;
    Some((f.interpreter.clone(), f.flags))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_magic_format_parses_as_linux() {
        let f =
            parse(b":qemu-arm:M::\\x7fELF\\x01:\\xff\\xff\\xff\\xff\\xfe:/usr/bin/qemu-arm:PF\n")
                .unwrap();
        assert_eq!(f.name, "qemu-arm");
        assert_eq!(
            f.what,
            Match::Magic {
                offset: 0,
                magic: b"\x7fELF\x00".to_vec(),
                mask: Some(b"\xff\xff\xff\xff\xfe".to_vec())
            }
        );
        assert_eq!(f.interpreter, b"/usr/bin/qemu-arm");
        assert_eq!(f.flags, PRESERVE_ARGV0 | FIX_BINARY);
        assert_eq!(
            show(&f),
            b"enabled\ninterpreter /usr/bin/qemu-arm\nflags: PF\noffset 0\nmagic 7f454c4600\nmask fffffffffe\n"
        );
    }

    #[test]
    fn an_extension_format_parses_as_linux() {
        let f = parse(b"|jar|E||jar||/usr/bin/jexec|C").unwrap();
        assert_eq!(f.what, Match::Extension(b"jar".to_vec()));
        assert_eq!(f.flags, CREDENTIALS | OPEN_BINARY);
        assert_eq!(show(&f), b"enabled\ninterpreter /usr/bin/jexec\nflags: CO\nextension .jar\n");
    }

    #[test]
    fn a_bad_text_gives_einval() {
        for t in [
            &b":x:M::ab"[..],
            b":.:M::ab::/bin/sh:",
            b":a/b:M::ab::/bin/sh:",
            b":x:Q::ab::/bin/sh:",
            b":x:M::::/bin/sh:",
            b":x:M::ab:a:/bin/sh:",
            b":x:M::ab:::",
            b":x:E:1:jar::/bin/sh:",
            b":x:M:250:abcdefgh::/bin/sh:",
            b":x:M::ab::/bin/sh:Z",
            b":x:M::\\xzz::/bin/sh:",
        ] {
            assert_eq!(parse(t), Err(Errno::EINVAL), "{}", String::from_utf8_lossy(t));
        }
    }

    #[test]
    fn find_uses_the_magic_the_mask_and_the_extension() {
        let magic = parse(b":m:M:2:\\x01\\x02:\\xff\\x0f:/bin/m:").unwrap();
        let ext = parse(b":e:E::py::/bin/py:P").unwrap();
        *FORMATS.lock() = alloc::vec![ext, magic];
        assert_eq!(find(b"xx\x01\xf2", b"/a/b"), Some((b"/bin/m".to_vec(), 0)));
        assert_eq!(find(b"xx\x01\x03", b"/a/b"), None);
        assert_eq!(find(b"", b"/a/b.py"), Some((b"/bin/py".to_vec(), PRESERVE_ARGV0)));
        assert_eq!(find(b"", b"/a.py/b"), None);
        write_format("e", b"0\n").unwrap();
        assert_eq!(find(b"", b"/a/b.py"), None);
        assert_eq!(get("e").map(|f| f.enabled), Some(false));
        write_status(b"0").unwrap();
        assert_eq!(find(b"xx\x01\xf2", b"/a/b"), None);
        assert_eq!(status(), b"disabled\n");
        write_status(b"1").unwrap();
        assert_eq!(write_status(b"2"), Err(Errno::EINVAL));
        assert_eq!(register(b":m:M::ab::/bin/x:"), Err(Errno::EEXIST));
        assert_eq!(names(), ["m", "e"]);
        write_format("m", b"-1").unwrap();
        assert_eq!(names(), ["e"]);
        write_status(b"-1").unwrap();
        assert!(names().is_empty());
    }
}
