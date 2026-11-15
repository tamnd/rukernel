//! The `encrypted` type, as `security/keys/encrypted-keys/encrypted.c` of Linux.
//!
//! The kernel keeps the decrypted data of the key. A read gives the data encrypted with AES in
//! CBC mode and an HMAC with SHA-256, with keys that come from a master key. The master key is a
//! `user` key. The `trusted` type is not available, so a `trusted:` master key gives
//! `EOPNOTSUPP`, as Linux without `CONFIG_TRUSTED_KEYS`.
//!
//! The payload of `add_key` is a text:
//!
//! - `new [FORMAT] MASTER LEN [DATA]` makes a key with `LEN` random bytes, or with the bytes of
//!   the hexadecimal `DATA`, as Linux with `CONFIG_USER_DECRYPTED_DATA`.
//! - `load [FORMAT] MASTER LEN BLOB` makes a key from the text that a read gave.
//! - `update MASTER` changes the master key of a key, with `KEYCTL_UPDATE`.
//!
//! `FORMAT` is `default`, `ecryptfs` or `enc32`.

use super::{Caller, Kind, Prep, Search, random};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use rk_abi::Errno;
use rk_crypto::asym::hex;

/// The size of the digest of SHA-256, as `HASH_SIZE`.
const HASH_SIZE: usize = 32;
/// The size of the IV and of a block of AES.
const IV_SIZE: usize = 16;
/// The smallest length of the decrypted data, as `MIN_DATA_SIZE`.
const MIN_DATA: usize = 20;
/// The largest length of the decrypted data, as `MAX_DATA_SIZE`.
const MAX_DATA: usize = 4096;
/// The longest payload of `add_key` and `KEYCTL_UPDATE`.
const MAX_BLOB: usize = 32767;
/// The length of the data of the `enc32` format, as `KEY_ENC32_PAYLOAD_LEN`.
const ENC32_LEN: usize = 32;
/// The length of the data of the `ecryptfs` format, as `ECRYPTFS_MAX_KEY_BYTES`.
const ECRYPTFS_LEN: usize = 64;
/// The length of the description of an `ecryptfs` key, as `KEY_ECRYPTFS_DESC_LEN`.
const ECRYPTFS_DESC_LEN: usize = 16;
/// The size of `struct ecryptfs_auth_tok`, which an `ecryptfs` key keeps in place of its data.
const ECRYPTFS_AUTH_TOK: usize = 740;
/// The prefix of a `trusted` master key, as `KEY_TRUSTED_PREFIX`.
const TRUSTED_PREFIX: &[u8] = b"trusted:";
/// The prefix of a `user` master key, as `KEY_USER_PREFIX`.
const USER_PREFIX: &[u8] = b"user:";

/// The format of a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    /// `default`: the decrypted data only.
    Default,
    /// `ecryptfs`: the data of an eCryptfs authentication token.
    Ecryptfs,
    /// `enc32`: 32 bytes of data.
    Enc32,
}

impl Format {
    /// The format of the token `t`, as `key_format_tokens`.
    fn from_token(t: &[u8]) -> Option<Self> {
        match t {
            b"default" => Some(Format::Default),
            b"ecryptfs" => Some(Format::Ecryptfs),
            b"enc32" => Some(Format::Enc32),
            _ => None,
        }
    }

    /// The name of the format.
    fn name(self) -> &'static [u8] {
        match self {
            Format::Default => b"default",
            Format::Ecryptfs => b"ecryptfs",
            Format::Enc32 => b"enc32",
        }
    }
}

/// The payload of an `encrypted` key, as `struct encrypted_key_payload`.
#[derive(Clone)]
pub(super) struct Encrypted {
    format: Format,
    /// The type and the description of the master key, as `user:NAME`.
    master_desc: Vec<u8>,
    /// The length of the decrypted data, as the text of the payload.
    datalen: Vec<u8>,
    iv: [u8; IV_SIZE],
    /// The decrypted data.
    pub(super) data: Vec<u8>,
    /// The size of the data that the key keeps, as `payload_datalen`.
    payload_len: usize,
}

impl Encrypted {
    /// The length of the encrypted data: the data with zeros to a full block.
    fn enc_len(&self) -> usize {
        self.data.len().div_ceil(IV_SIZE) * IV_SIZE
    }

    /// The bytes that the HMAC covers, as the `datablob` of Linux: the format, the master key,
    /// the length, the IV and the encrypted data, each with a zero byte after it.
    fn blob(&self, encrypted: &[u8]) -> Vec<u8> {
        let mut b = Vec::with_capacity(self.blob_len());
        for part in [self.format.name(), &self.master_desc, &self.datalen, &self.iv] {
            b.extend_from_slice(part);
            b.push(0);
        }
        b.extend_from_slice(encrypted);
        b
    }

    /// The length of [`Encrypted::blob`], as `datablob_len`.
    fn blob_len(&self) -> usize {
        let fields = self.format.name().len() + self.master_desc.len() + self.datalen.len();
        fields + IV_SIZE + 4 + self.enc_len()
    }

    /// The bytes that the key takes in the quota, as the `key_payload_reserve` of
    /// `encrypted_key_alloc`. `/proc/keys` shows this value.
    pub(super) fn quota(&self) -> u32 {
        (self.payload_len + self.blob_len() + HASH_SIZE + 1) as u32
    }

    /// The length of the text of a read.
    fn text_len(&self) -> usize {
        self.blob_len() + IV_SIZE + 1 + self.enc_len() + HASH_SIZE * 2
    }
}

/// The next token of `rest`, as `strsep(&rest, " \t")`.
fn strsep<'a>(rest: &mut Option<&'a [u8]>) -> Option<&'a [u8]> {
    let s = rest.take()?;
    match s.iter().position(|&b| b == b' ' || b == b'\t') {
        Some(i) => {
            *rest = Some(&s[i + 1..]);
            Some(&s[..i])
        }
        None => Some(s),
    }
}

/// The tokens of a payload, as `datablob_parse`.
struct Parsed<'a> {
    format: Option<Format>,
    master_desc: &'a [u8],
    datalen: &'a [u8],
    /// The hexadecimal text of `load`.
    load: Option<&'a [u8]>,
    /// The hexadecimal data of `new`.
    data: Option<&'a [u8]>,
}

/// Parses a payload, as `datablob_parse`. `new` is true for a new key, which takes `new` and
/// `load`, and false for an update, which takes only `update`.
///
/// # Errors
///
/// Gives `EINVAL` for a bad payload.
fn parse(payload: &[u8], new: bool) -> Result<Parsed<'_>, Errno> {
    if payload.is_empty() || payload.len() > MAX_BLOB {
        return Err(Errno::EINVAL);
    }
    // Linux copies the payload into a string, which ends at the first zero byte.
    let text = &payload[..payload.iter().position(|&b| b == 0).unwrap_or(payload.len())];
    let mut rest = Some(text);
    let keyword = strsep(&mut rest).ok_or(Errno::EINVAL)?;
    let p = strsep(&mut rest).ok_or(Errno::EINVAL)?;
    let (format, master_desc) = match Format::from_token(p) {
        Some(f) => (Some(f), strsep(&mut rest)),
        None => (None, Some(p)),
    };
    let master_desc = master_desc.ok_or(Errno::EINVAL)?;
    valid_master_desc(master_desc, None)?;
    let mut parsed = Parsed { format, master_desc, datalen: b"", load: None, data: None };
    if new {
        parsed.datalen = strsep(&mut rest).ok_or(Errno::EINVAL)?;
    }
    match (keyword, new) {
        (b"new", true) => parsed.data = strsep(&mut rest),
        (b"load", true) => parsed.load = Some(strsep(&mut rest).ok_or(Errno::EINVAL)?),
        (b"update", false) => {}
        _ => return Err(Errno::EINVAL),
    }
    Ok(parsed)
}

/// Checks the name of a master key, as `valid_master_desc`: `trusted:NAME` or `user:NAME`. An
/// update cannot change the type of the master key `old`.
///
/// # Errors
///
/// Gives `EINVAL` for a bad name.
fn valid_master_desc(desc: &[u8], old: Option<&[u8]>) -> Result<(), Errno> {
    let prefix = [TRUSTED_PREFIX, USER_PREFIX]
        .into_iter()
        .find(|p| desc.starts_with(p))
        .ok_or(Errno::EINVAL)?;
    if desc.len() == prefix.len() || old.is_some_and(|o| !o.starts_with(prefix)) {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// Parses a decimal number as `kstrtol` with the base 10: a sign, and one newline at the end.
fn parse_long(text: &[u8]) -> Option<i64> {
    let text = text.strip_suffix(b"\n").unwrap_or(text);
    let (neg, digits) = match text.split_first() {
        Some((b'-', rest)) => (true, rest),
        Some((b'+', rest)) => (false, rest),
        _ => (false, text),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let v: i64 = core::str::from_utf8(digits).ok()?.parse().ok()?;
    Some(if neg { -v } else { v })
}

/// The bytes of the hexadecimal text `text`, as `hex2bin`.
///
/// # Errors
///
/// Gives `EINVAL` for a character that is not a hexadecimal digit.
fn unhex(text: &[u8]) -> Result<Vec<u8>, Errno> {
    if !text.len().is_multiple_of(2) {
        return Err(Errno::EINVAL);
    }
    let digit = |c: u8| (c as char).to_digit(16).ok_or(Errno::EINVAL);
    text.chunks(2).map(|p| Ok(((digit(p[0])? << 4) | digit(p[1])?) as u8)).collect()
}

/// The digest of `data` with the hash `name`, and the key `key` for an HMAC.
fn digest(name: &str, key: Option<&[u8]>, data: &[u8]) -> Result<[u8; HASH_SIZE], Errno> {
    let mut h = rk_crypto::alloc_hash(name)?;
    if let Some(k) = key {
        h.set_key(k)?;
    }
    h.init();
    h.update(data);
    let mut out = [0u8; HASH_SIZE];
    h.finish(&mut out);
    Ok(out)
}

/// A key from the master key, as `get_derived_key`: the SHA-256 of `AUTH_KEY` or `ENC_KEY`, a
/// zero byte and the master key, with zeros to 32 bytes.
fn derived_key(auth: bool, master: &[u8]) -> Result<[u8; HASH_SIZE], Errno> {
    let name: &[u8] = if auth { b"AUTH_KEY" } else { b"ENC_KEY" };
    let mut buf = vec![0u8; (b"AUTH_KEY".len() + 1 + master.len()).max(HASH_SIZE)];
    buf[..name.len()].copy_from_slice(name);
    buf[name.len() + 1..name.len() + 1 + master.len()].copy_from_slice(master);
    digest("sha256", None, &buf)
}

/// Encrypts or decrypts `data` in place with AES in CBC mode.
fn cbc(key: &[u8], iv: &[u8; IV_SIZE], data: &mut [u8], encrypt: bool) -> Result<(), Errno> {
    let mut c = rk_crypto::alloc_skcipher("cbc(aes)")?;
    c.set_key(key)?;
    let mut iv = *iv;
    if encrypt { c.encrypt(&mut iv, data) } else { c.decrypt(&mut iv, data) }
}

/// The payload of the master key `desc`, as `request_master_key`. A `user` master key is found
/// as `request_key` without callout information.
///
/// # Errors
///
/// Gives `EOPNOTSUPP` for a `trusted` master key, `EINVAL` for a bad name, `ENOKEY` if the key is
/// not there, or the error of the state of the key.
fn master_key(cx: &Caller<'_>, desc: &[u8]) -> Result<Vec<u8>, Errno> {
    if desc.starts_with(TRUSTED_PREFIX) {
        return Err(Errno::EOPNOTSUPP);
    }
    let name = desc.strip_prefix(USER_PREFIX).ok_or(Errno::EINVAL)?;
    let search = Search {
        cx,
        target: None,
        kind: Kind::User,
        desc: name,
        asym_id: None,
        state_check: true,
        skip_expired: true,
        check_perm: true,
    };
    let key = match search.in_process() {
        Ok(k) => k,
        Err(Errno::EAGAIN) => return Err(Errno::ENOKEY),
        Err(e) => return Err(e),
    };
    super::construct::result(&key)?;
    let s = key.state.lock();
    if s.revoked {
        return Err(Errno::EKEYREVOKED);
    }
    Ok(s.payload.clone())
}

/// Makes the payload of a new key with the description `desc` from the text `payload`, as
/// `encrypted_instantiate`.
///
/// # Errors
///
/// Gives `EINVAL` for a bad payload, a bad length, data that does not match the length, a bad
/// description of an `ecryptfs` key, or a text of `load` with a bad HMAC. A `load` also gives the
/// error of the master key.
pub(super) fn instantiate(cx: &Caller<'_>, desc: &[u8], payload: &[u8]) -> Result<Prep, Errno> {
    let p = parse(payload, true)?;
    let len = parse_long(p.datalen)
        .and_then(|v| usize::try_from(v).ok())
        .filter(|v| (MIN_DATA..=MAX_DATA).contains(v))
        .ok_or(Errno::EINVAL)?;
    if let Some(data) = p.data
        && (data.len() != len * 2 || !data.iter().all(u8::is_ascii_hexdigit))
    {
        return Err(Errno::EINVAL);
    }
    let mut payload_len = len;
    match p.format {
        Some(Format::Ecryptfs) if len != ECRYPTFS_LEN => return Err(Errno::EINVAL),
        Some(Format::Ecryptfs) => payload_len = ECRYPTFS_AUTH_TOK,
        Some(Format::Enc32) if len != ENC32_LEN => return Err(Errno::EINVAL),
        _ => {}
    }
    if p.format == Some(Format::Ecryptfs)
        && (desc.len() != ECRYPTFS_DESC_LEN || !desc.iter().all(u8::is_ascii_hexdigit))
    {
        return Err(Errno::EINVAL);
    }
    let mut enc = Encrypted {
        format: p.format.unwrap_or(Format::Default),
        master_desc: p.master_desc.to_vec(),
        datalen: p.datalen.to_vec(),
        iv: [0; IV_SIZE],
        data: vec![0; len],
        payload_len,
    };
    if let Some(text) = p.load {
        load(cx, &mut enc, p.format.is_some(), text)?;
    } else {
        for chunk in enc.iv.chunks_mut(8) {
            chunk.copy_from_slice(&random().to_ne_bytes()[..chunk.len()]);
        }
        match p.data {
            Some(data) => enc.data = unhex(data)?,
            None => {
                for chunk in enc.data.chunks_mut(8) {
                    chunk.copy_from_slice(&random().to_ne_bytes()[..chunk.len()]);
                }
            }
        }
    }
    Ok(Prep { quota: enc.quota(), enc: Some(Arc::new(enc)), ..Prep::default() })
}

/// Decrypts the text of `load` into `enc`, as `encrypted_key_decrypt`. Without a format in the
/// payload, the HMAC does not cover the format, as the keys of old versions of Linux.
///
/// # Errors
///
/// Gives `EINVAL` for a text of a bad length, a character that is not a hexadecimal digit, or a
/// bad HMAC, or the error of the master key.
fn load(cx: &Caller<'_>, enc: &mut Encrypted, has_format: bool, text: &[u8]) -> Result<(), Errno> {
    let enc_len = enc.enc_len();
    if text.len() != (IV_SIZE + 1 + enc_len + HASH_SIZE) * 2 {
        return Err(Errno::EINVAL);
    }
    // The byte after the IV is the zero byte of the blob, which Linux does not check.
    enc.iv.copy_from_slice(&unhex(&text[..IV_SIZE * 2])?);
    let rest = &text[IV_SIZE * 2 + 2..];
    let mut data = unhex(&rest[..enc_len * 2])?;
    let hmac = unhex(&rest[enc_len * 2..])?;
    let master = master_key(cx, &enc.master_desc)?;
    let blob = enc.blob(&data);
    let covered = if has_format { &blob[..] } else { &blob[enc.format.name().len() + 1..] };
    let auth = derived_key(true, &master)?;
    if digest("hmac(sha256)", Some(&auth), covered)? != hmac[..] {
        return Err(Errno::EINVAL);
    }
    cbc(&derived_key(false, &master)?, &enc.iv, &mut data, false)?;
    data.truncate(enc.data.len());
    enc.data = data;
    Ok(())
}

/// Changes the master key of `old` with the text `payload`, as `encrypted_update`. `old` is
/// `None` for a negative key.
///
/// # Errors
///
/// Gives `ENOKEY` for a negative key, or `EINVAL` for a bad payload or a master key of another
/// type.
pub(super) fn update(old: Option<&Encrypted>, payload: &[u8]) -> Result<Encrypted, Errno> {
    let old = old.ok_or(Errno::ENOKEY)?;
    let p = parse(payload, false)?;
    valid_master_desc(p.master_desc, Some(&old.master_desc))?;
    Ok(Encrypted { master_desc: p.master_desc.to_vec(), ..old.clone() })
}

/// The text of a read of the key, as `encrypted_read`: the format, the master key, the length,
/// and the hexadecimal IV, encrypted data and HMAC. Gives the length of the text and the text,
/// or only the length if `buflen` is too small.
///
/// # Errors
///
/// Gives the error of the master key.
pub(super) fn read(
    cx: &Caller<'_>,
    enc: &Encrypted,
    buflen: usize,
) -> Result<(usize, Vec<u8>), Errno> {
    let full = enc.text_len();
    if buflen < full {
        return Ok((full, Vec::new()));
    }
    let master = master_key(cx, &enc.master_desc)?;
    let mut data = enc.data.clone();
    data.resize(enc.enc_len(), 0);
    cbc(&derived_key(false, &master)?, &enc.iv, &mut data, true)?;
    let blob = enc.blob(&data);
    let hmac = digest("hmac(sha256)", Some(&derived_key(true, &master)?), &blob)?;
    let mut out = Vec::with_capacity(full);
    for part in [enc.format.name(), &enc.master_desc, &enc.datalen] {
        out.extend_from_slice(part);
        out.push(b' ');
    }
    out.extend_from_slice(&hex(&enc.iv));
    out.extend_from_slice(b"00");
    out.extend_from_slice(&hex(&data));
    out.extend_from_slice(&hex(&hmac));
    Ok((full, out))
}

#[cfg(test)]
mod tests {
    use super::{parse, parse_long, valid_master_desc};
    use rk_abi::Errno;

    #[test]
    fn payload_texts() {
        let p = parse(b"new enc32 user:m 32 ab\0cd", true).unwrap();
        assert_eq!(
            (p.master_desc, p.datalen, p.data),
            (&b"user:m"[..], &b"32"[..], Some(&b"ab"[..]))
        );
        let p = parse(b"load\tuser:m 20 00", true).unwrap();
        assert_eq!((p.format, p.load), (None, Some(&b"00"[..])));
        // A space at the end gives empty data.
        assert_eq!(parse(b"new user:m 20 ", true).unwrap().data, Some(&b""[..]));
        for bad in
            [&b""[..], b"new", b"new user:m", b"new default", b"new key:m 32", b"load user:m 32"]
        {
            assert_eq!(parse(bad, true).err(), Some(Errno::EINVAL), "{bad:?}");
        }
        assert_eq!(parse(b"update user:m", true).err(), Some(Errno::EINVAL));
        assert_eq!(parse(b"new user:m 32", false).err(), Some(Errno::EINVAL));
        assert!(parse(b"update default user:n", false).is_ok());
        assert_eq!(valid_master_desc(b"user:", None), Err(Errno::EINVAL));
        assert_eq!(valid_master_desc(b"user:n", Some(b"trusted:m")), Err(Errno::EINVAL));
        assert_eq!(parse_long(b"+32\n"), Some(32));
        assert_eq!(parse_long(b"3 2"), None);
    }
}
