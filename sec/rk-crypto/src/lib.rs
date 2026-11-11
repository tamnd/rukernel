//! The crypto API of rukernel, as crypto/ of Linux.
//!
//! The crate has the algorithms that the `AF_ALG` sockets give to user space: the hashes SHA-1,
//! SHA-224, SHA-256, SHA-384 and SHA-512, the template `hmac`, the block cipher AES, and the
//! templates `ecb`, `cbc`, `ctr` and `xts` that make a cipher of any length from a block cipher.
//! The code is plain Rust with no architecture specific path, as the `-generic` drivers of
//! Linux.
//!
//! `alloc_hash`, `alloc_skcipher` and `alloc_cipher` find an algorithm from its name, as
//! `crypto_alloc_shash`, `crypto_alloc_skcipher` and `crypto_alloc_cipher` of Linux. A name is
//! the name of the algorithm (`sha256`) or of its driver (`sha256-generic`). A template takes
//! the name of its inner algorithm in parentheses (`cbc(aes)` or `cbc(aes-generic)`), and the
//! driver of an instance has the driver of the inner algorithm (`cbc(aes-generic)`). A name that
//! the crate does not have gives `ENOENT`.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod aes;
pub mod hmac;
pub mod modes;
pub mod sha1;
pub mod sha256;
pub mod sha512;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod testvec;

use alloc::boxed::Box;
use alloc::string::String;
use rk_abi::Errno;

/// The result of a crypto operation.
pub type Result<T> = core::result::Result<T, Errno>;

/// The longest name of an algorithm, with its last zero byte, as `CRYPTO_MAX_ALG_NAME`.
pub const MAX_ALG_NAME: usize = 128;

/// A hash, as `struct shash_alg` and a `struct shash_desc` of Linux. The value holds the key and
/// the state of one computation.
pub trait Hash: Send + Sync {
    /// The size of the digest in bytes.
    fn digest_size(&self) -> usize;
    /// The size of a block in bytes.
    fn block_size(&self) -> usize;
    /// The name of the algorithm, as `cra_name`.
    fn name(&self) -> String;
    /// The name of the driver, as `cra_driver_name`.
    fn driver_name(&self) -> String;
    /// True if the algorithm takes a key, as `crypto_shash_alg_has_setkey`.
    fn keyed(&self) -> bool {
        false
    }
    /// True if the algorithm needs a key and has none yet, as `CRYPTO_TFM_NEED_KEY`.
    fn needs_key(&self) -> bool {
        false
    }
    /// Sets the key. A hash with no key gives `ENOSYS`, as `shash_no_setkey` of Linux.
    fn set_key(&mut self, _key: &[u8]) -> Result<()> {
        Err(Errno::ENOSYS)
    }
    /// Starts a new computation.
    fn init(&mut self);
    /// Adds `data` to the computation.
    fn update(&mut self, data: &[u8]);
    /// Ends the computation and writes the digest to `out`, which has at least `digest_size`
    /// bytes. A new computation needs `init` first.
    fn finish(&mut self, out: &mut [u8]);
    /// A copy of the key and the state, as `crypto_shash_export` and `crypto_shash_import`.
    fn box_clone(&self) -> Box<dyn Hash>;
}

/// The size of the block of `Cipher`.
pub const BLOCK: usize = 16;

/// A block cipher with blocks of 16 bytes, as `struct cipher_alg` of Linux.
pub trait Cipher: Send + Sync {
    /// The name of the algorithm, as `cra_name`.
    fn name(&self) -> String;
    /// The name of the driver, as `cra_driver_name`.
    fn driver_name(&self) -> String;
    /// The shortest key in bytes.
    fn min_key_size(&self) -> usize;
    /// The longest key in bytes.
    fn max_key_size(&self) -> usize;
    /// Sets the key. A key of a bad size gives `EINVAL`.
    fn set_key(&mut self, key: &[u8]) -> Result<()>;
    /// Encrypts one block in place.
    fn encrypt(&self, block: &mut [u8; BLOCK]);
    /// Decrypts one block in place.
    fn decrypt(&self, block: &mut [u8; BLOCK]);
    /// A copy of the cipher with its key.
    fn box_clone(&self) -> Box<dyn Cipher>;
}

/// A cipher of data of any length, as `struct skcipher_alg` of Linux.
pub trait Skcipher: Send + Sync {
    /// The name of the algorithm, as `cra_name`.
    fn name(&self) -> String;
    /// The name of the driver, as `cra_driver_name`.
    fn driver_name(&self) -> String;
    /// The size of a block: the length of the data must be a multiple of it.
    fn block_size(&self) -> usize;
    /// The size of a step of the algorithm, as `crypto_skcipher_chunksize`. A stream cipher has
    /// a block of 1 byte and a larger step.
    fn chunk_size(&self) -> usize {
        self.block_size()
    }
    /// The size of the IV in bytes.
    fn iv_size(&self) -> usize;
    /// The shortest key in bytes.
    fn min_key_size(&self) -> usize;
    /// The longest key in bytes.
    fn max_key_size(&self) -> usize;
    /// Sets the key. A key of a bad size gives `EINVAL`.
    fn set_key(&mut self, key: &[u8]) -> Result<()>;
    /// True if the cipher has no key yet, as `CRYPTO_TFM_NEED_KEY`.
    fn needs_key(&self) -> bool;
    /// Encrypts `data` in place with the IV `iv`, which has `iv_size` bytes. `iv` gets the IV
    /// that continues the data, as the output IV of Linux. A length that is not a multiple of
    /// the block gives `EINVAL`.
    fn encrypt(&self, iv: &mut [u8], data: &mut [u8]) -> Result<()>;
    /// Decrypts `data` in place, as `encrypt`.
    fn decrypt(&self, iv: &mut [u8], data: &mut [u8]) -> Result<()>;
    /// A copy of the cipher with its key.
    fn box_clone(&self) -> Box<dyn Skcipher>;
}

/// Splits `name` into a template and its argument: `cbc(aes)` gives `("cbc", "aes")`.
fn template(name: &str) -> Option<(&str, &str)> {
    let open = name.find('(')?;
    let inner = name.strip_suffix(')')?.get(open + 1..)?;
    Some((&name[..open], inner))
}

/// Finds the hash `name`, as `crypto_alloc_shash` of Linux.
///
/// # Errors
///
/// Gives `ENOENT` if the crate does not have the algorithm.
pub fn alloc_hash(name: &str) -> Result<Box<dyn Hash>> {
    if let Some((tmpl, inner)) = template(name) {
        return match tmpl {
            "hmac" => Ok(Box::new(hmac::Hmac::new(alloc_hash(inner)?)?)),
            _ => Err(Errno::ENOENT),
        };
    }
    let hash: Box<dyn Hash> = match name {
        "sha1" | "sha1-generic" => Box::new(sha1::Sha1::new()),
        "sha224" | "sha224-generic" => Box::new(sha256::Sha256::new_224()),
        "sha256" | "sha256-generic" => Box::new(sha256::Sha256::new()),
        "sha384" | "sha384-generic" => Box::new(sha512::Sha512::new_384()),
        "sha512" | "sha512-generic" => Box::new(sha512::Sha512::new()),
        _ => return Err(Errno::ENOENT),
    };
    Ok(hash)
}

/// Finds the block cipher `name`, as `crypto_alloc_cipher` of Linux.
///
/// # Errors
///
/// Gives `ENOENT` if the crate does not have the algorithm.
pub fn alloc_cipher(name: &str) -> Result<Box<dyn Cipher>> {
    match name {
        "aes" | "aes-generic" => Ok(Box::new(aes::Aes::new())),
        _ => Err(Errno::ENOENT),
    }
}

/// Finds the cipher `name`, as `crypto_alloc_skcipher` of Linux. A block cipher alone is not a
/// cipher of this type: it needs a template, as `ecb(aes)`.
///
/// # Errors
///
/// Gives `ENOENT` if the crate does not have the algorithm.
pub fn alloc_skcipher(name: &str) -> Result<Box<dyn Skcipher>> {
    let (tmpl, inner) = template(name).ok_or(Errno::ENOENT)?;
    let mode = match tmpl {
        "ecb" => modes::Mode::Ecb,
        "cbc" => modes::Mode::Cbc,
        "ctr" => modes::Mode::Ctr,
        "xts" => modes::Mode::Xts,
        _ => return Err(Errno::ENOENT),
    };
    Ok(Box::new(modes::Block::new(mode, alloc_cipher(inner)?)))
}
