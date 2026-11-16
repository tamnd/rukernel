//! The options of a mount of procfs, as `proc_parse_param` in fs/proc/root.c of Linux.

use rk_abi::Errno;

/// `hidepid=off`: each process can see and read the directories of all processes.
pub const HIDEPID_OFF: u32 = 0;
/// `hidepid=noaccess`: a process cannot read the directory of a process that it cannot trace.
pub const HIDEPID_NO_ACCESS: u32 = 1;
/// `hidepid=invisible`: a process cannot see the directory of a process that it cannot trace.
pub const HIDEPID_INVISIBLE: u32 = 2;
/// `hidepid=ptraceable`: a process sees only the directories of the processes that it can
/// trace. The option `gid` has no effect then.
pub const HIDEPID_PTRACEABLE: u32 = 4;

/// The options of one mount, as `proc_fs_info` of Linux.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    /// The value of `hidepid`.
    pub hidepid: u32,
    /// `gid`: the members of this group can see all processes.
    pub gid: Option<u32>,
    /// `subset=pid`: the root shows only the directories of the processes, `self` and
    /// `thread-self`.
    pub pid_only: bool,
}

/// Reads the data of a mount of procfs. `hidepid` takes a number (0, 1, 2 or 4) or a name.
/// `subset` takes only `pid`. Another option has no effect, as for the other file systems of
/// rukernel.
///
/// # Errors
///
/// `EINVAL` for a bad value.
pub fn parse(data: &[u8]) -> Result<Options, Errno> {
    let mut o = Options::default();
    for opt in data.split(|&b| b == b',').filter(|o| !o.is_empty()) {
        let (key, value) = match opt.iter().position(|&b| b == b'=') {
            Some(i) => (&opt[..i], &opt[i + 1..]),
            None => (opt, &b""[..]),
        };
        match key {
            b"hidepid" => {
                o.hidepid = match value {
                    b"0" | b"off" => HIDEPID_OFF,
                    b"1" | b"noaccess" => HIDEPID_NO_ACCESS,
                    b"2" | b"invisible" => HIDEPID_INVISIBLE,
                    b"4" | b"ptraceable" => HIDEPID_PTRACEABLE,
                    _ => return Err(Errno::EINVAL),
                }
            }
            b"gid" => {
                let gid = core::str::from_utf8(value).ok().and_then(|v| v.parse().ok());
                o.gid = Some(gid.ok_or(Errno::EINVAL)?);
            }
            b"subset" => match value {
                b"pid" => o.pid_only = true,
                b"" => {}
                _ => return Err(Errno::EINVAL),
            },
            _ => {}
        }
    }
    Ok(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_options() {
        assert_eq!(parse(b""), Ok(Options::default()));
        let o = parse(b"hidepid=invisible,gid=5,subset=pid").unwrap();
        assert_eq!(o, Options { hidepid: HIDEPID_INVISIBLE, gid: Some(5), pid_only: true });
        assert_eq!(parse(b"hidepid=1").unwrap().hidepid, HIDEPID_NO_ACCESS);
        assert_eq!(parse(b"hidepid=ptraceable").unwrap().hidepid, HIDEPID_PTRACEABLE);
        assert_eq!(parse(b"hidepid=off,rw").unwrap(), Options::default());
    }

    #[test]
    fn bad_values_give_einval() {
        assert_eq!(parse(b"hidepid=3"), Err(Errno::EINVAL));
        assert_eq!(parse(b"hidepid=all"), Err(Errno::EINVAL));
        assert_eq!(parse(b"gid=x"), Err(Errno::EINVAL));
        assert_eq!(parse(b"subset=sys"), Err(Errno::EINVAL));
    }
}
