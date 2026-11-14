//! A reader of ASN.1 in DER, as lib/asn1_decoder.c of Linux for the grammars of the asymmetric
//! keys. The reader takes the low tag numbers and the definite lengths. A bad encoding gives
//! `EBADMSG`.

use crate::Result;
use rk_abi::Errno;

/// The tag of a `BOOLEAN`.
pub const BOOL: u8 = 0x01;
/// The tag of an `INTEGER`.
pub const INT: u8 = 0x02;
/// The tag of a `BIT STRING`.
pub const BTS: u8 = 0x03;
/// The tag of an `OCTET STRING`.
pub const OTS: u8 = 0x04;
/// The tag of a `NULL`.
pub const NULL: u8 = 0x05;
/// The tag of an `OBJECT IDENTIFIER`.
pub const OID: u8 = 0x06;
/// The tag of a `SEQUENCE`.
pub const SEQ: u8 = 0x30;
/// The tag of a `SET`.
pub const SET: u8 = 0x31;
/// The tag of a `UTCTime`.
pub const UTC_TIME: u8 = 0x17;
/// The tag of a `GeneralizedTime`.
pub const GEN_TIME: u8 = 0x18;
/// The tag of the constructed context-specific element `[n]`.
pub const fn cont(n: u8) -> u8 {
    0xa0 | n
}
/// The tag of the primitive context-specific element `[n]`.
pub const fn cont_prim(n: u8) -> u8 {
    0x80 | n
}

/// One element: its tag, its content, and all its bytes with the header.
#[derive(Clone, Copy, Debug)]
pub struct Elem<'a> {
    /// The tag byte.
    pub tag: u8,
    /// The content after the header.
    pub value: &'a [u8],
    /// The header and the content.
    pub raw: &'a [u8],
}

impl<'a> Elem<'a> {
    /// A reader of the elements in the content of a constructed element.
    pub fn inner(&self) -> Der<'a> {
        Der::new(self.value)
    }
}

/// A reader of a sequence of DER elements.
#[derive(Clone, Copy, Debug)]
pub struct Der<'a> {
    data: &'a [u8],
}

impl<'a> Der<'a> {
    /// A reader of `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Der { data }
    }

    /// True if no bytes are left.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The tag of the next element, if there is one.
    pub fn peek(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// Reads the next element.
    ///
    /// # Errors
    ///
    /// Gives `EBADMSG` for no element, a tag of more than one byte, an indefinite length, or a
    /// length past the end of the data.
    pub fn read(&mut self) -> Result<Elem<'a>> {
        let d = self.data;
        let (&tag, rest) = d.split_first().ok_or(Errno::EBADMSG)?;
        if tag & 0x1f == 0x1f {
            return Err(Errno::EBADMSG);
        }
        let (&l0, rest) = rest.split_first().ok_or(Errno::EBADMSG)?;
        let (len, rest) = if l0 < 0x80 {
            (usize::from(l0), rest)
        } else {
            let n = usize::from(l0 & 0x7f);
            if n == 0 || n > 4 || rest.len() < n {
                return Err(Errno::EBADMSG);
            }
            let len = rest[..n].iter().fold(0usize, |a, &b| (a << 8) | usize::from(b));
            (len, &rest[n..])
        };
        if rest.len() < len {
            return Err(Errno::EBADMSG);
        }
        let hdr = d.len() - rest.len();
        let elem = Elem { tag, value: &rest[..len], raw: &d[..hdr + len] };
        self.data = &rest[len..];
        Ok(elem)
    }

    /// Reads the next element and checks its tag.
    ///
    /// # Errors
    ///
    /// Gives `EBADMSG` for a bad element or another tag.
    pub fn expect(&mut self, tag: u8) -> Result<Elem<'a>> {
        let e = self.read()?;
        if e.tag != tag {
            return Err(Errno::EBADMSG);
        }
        Ok(e)
    }

    /// Reads the next element if it has the tag `tag`.
    ///
    /// # Errors
    ///
    /// Gives `EBADMSG` for a bad element.
    pub fn optional(&mut self, tag: u8) -> Result<Option<Elem<'a>>> {
        if self.peek() == Some(tag) { self.read().map(Some) } else { Ok(None) }
    }
}

/// The largest input of the decoder of Linux.
pub const MAX_INPUT: usize = 65535;

/// Reads the first element of `data`, as the top of a grammar in `asn1_ber_decoder`. As Linux,
/// the bytes after the element are not checked.
///
/// # Errors
///
/// Gives `EMSGSIZE` if `data` is larger than [`MAX_INPUT`], or `EBADMSG` for a bad element or
/// another tag.
pub fn top(data: &[u8], tag: u8) -> Result<Elem<'_>> {
    if data.len() > MAX_INPUT {
        return Err(Errno::EMSGSIZE);
    }
    Der::new(data).expect(tag)
}

/// Checks that a reader has no bytes left, as the end of a constructed element.
///
/// # Errors
///
/// Gives `EBADMSG` if bytes are left.
pub fn end(d: &Der<'_>) -> Result<()> {
    if d.is_empty() { Ok(()) } else { Err(Errno::EBADMSG) }
}

/// The DER content of the object identifiers that the asymmetric keys use.
pub mod oid {
    /// 1.2.840.113549.1.1.1
    pub const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    /// 1.2.840.113549.1.1.5
    pub const SHA1_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
    /// 1.2.840.113549.1.1.11
    pub const SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    /// 1.2.840.113549.1.1.12
    pub const SHA384_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
    /// 1.2.840.113549.1.1.13
    pub const SHA512_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
    /// 1.2.840.113549.1.1.14
    pub const SHA224_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0e];
    /// 1.2.840.113549.1.9.1
    pub const EMAIL_ADDRESS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01];
    /// 2.5.4.3
    pub const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
    /// 2.5.4.10
    pub const ORGANIZATION_NAME: &[u8] = &[0x55, 0x04, 0x0a];
    /// 2.5.29.14
    pub const SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1d, 0x0e];
    /// 2.5.29.35
    pub const AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1d, 0x23];
    /// 2.5.29.15
    pub const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
    /// 2.5.29.19
    pub const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
}
