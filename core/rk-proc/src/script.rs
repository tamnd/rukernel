//! The `#!` line of a script, as fs/binfmt_script.c reads it.

use alloc::vec::Vec;
use rk_abi::Errno;

/// Reads the interpreter and its optional argument from a `#!` line. The line must end with a
/// newline.
///
/// # Errors
///
/// Gives `ENOEXEC` if the line has no newline or no interpreter.
pub fn parse_script(head: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>), Errno> {
    let line = head.get(2..).ok_or(Errno::ENOEXEC)?;
    let end = line.iter().position(|&b| b == b'\n').ok_or(Errno::ENOEXEC)?;
    let line = &line[..end];
    let is_blank = |b: &u8| *b == b' ' || *b == b'\t';
    let start = line.iter().position(|b| !is_blank(b)).ok_or(Errno::ENOEXEC)?;
    let line = &line[start..];
    let name_end = line.iter().position(is_blank).unwrap_or(line.len());
    let interp = line[..name_end].to_vec();
    let rest = &line[name_end..];
    let arg = rest.iter().position(|b| !is_blank(b)).map(|s| {
        let rest = &rest[s..];
        let e = rest.iter().rposition(|b| !is_blank(b)).map_or(0, |e| e + 1);
        rest[..e].to_vec()
    });
    Ok((interp, arg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_lines() {
        assert_eq!(parse_script(b"#!/bin/sh\n"), Ok((b"/bin/sh".to_vec(), None)));
        assert_eq!(
            parse_script(b"#! /usr/bin/env  python3 -u \nprint()"),
            Ok((b"/usr/bin/env".to_vec(), Some(b"python3 -u".to_vec())))
        );
        assert_eq!(parse_script(b"#!\n"), Err(Errno::ENOEXEC));
        assert_eq!(parse_script(b"#!/bin/sh"), Err(Errno::ENOEXEC));
    }
}
