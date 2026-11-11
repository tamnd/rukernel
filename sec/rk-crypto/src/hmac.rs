//! The template `hmac`, per RFC 2104, as crypto/hmac.c of Linux.

use crate::{Hash, Result};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use rk_abi::Errno;

/// The HMAC of a hash: the hash of the key and the outer pad, and of the inner hash of the key,
/// the inner pad and the message.
pub struct Hmac {
    /// The hash after the block of the key and the inner pad.
    inner: Box<dyn Hash>,
    /// The hash after the block of the key and the outer pad.
    outer: Box<dyn Hash>,
    /// The state of the current computation.
    state: Box<dyn Hash>,
    /// True after `set_key`.
    keyed: bool,
}

impl Hmac {
    /// The HMAC of `hash`. A hash with a key, as an HMAC, gives `ENOENT`, as `hmac_create` of
    /// Linux refuses it.
    ///
    /// # Errors
    ///
    /// Gives `ENOENT` if `hash` cannot be the hash of an HMAC.
    pub fn new(hash: Box<dyn Hash>) -> Result<Self> {
        if hash.keyed() || hash.digest_size() > hash.block_size() {
            return Err(Errno::ENOENT);
        }
        Ok(Self { inner: hash.box_clone(), outer: hash.box_clone(), state: hash, keyed: false })
    }
}

impl Hash for Hmac {
    fn digest_size(&self) -> usize {
        self.state.digest_size()
    }

    fn block_size(&self) -> usize {
        self.state.block_size()
    }

    fn name(&self) -> String {
        format!("hmac({})", self.state.name())
    }

    fn driver_name(&self) -> String {
        format!("hmac({})", self.state.driver_name())
    }

    fn keyed(&self) -> bool {
        true
    }

    fn needs_key(&self) -> bool {
        !self.keyed
    }

    fn set_key(&mut self, key: &[u8]) -> Result<()> {
        let bs = self.block_size();
        let mut pad = vec![0u8; bs];
        if key.len() > bs {
            let mut h = self.state.box_clone();
            h.init();
            h.update(key);
            h.finish(&mut pad);
        } else {
            pad[..key.len()].copy_from_slice(key);
        }
        let mut ipad = pad.clone();
        ipad.iter_mut().for_each(|b| *b ^= 0x36);
        pad.iter_mut().for_each(|b| *b ^= 0x5c);
        self.inner.init();
        self.inner.update(&ipad);
        self.outer.init();
        self.outer.update(&pad);
        self.state = self.inner.box_clone();
        self.keyed = true;
        Ok(())
    }

    fn init(&mut self) {
        self.state = self.inner.box_clone();
    }

    fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    fn finish(&mut self, out: &mut [u8]) {
        let ds = self.digest_size();
        let mut digest = vec![0u8; ds];
        self.state.finish(&mut digest);
        let mut outer = self.outer.box_clone();
        outer.update(&digest);
        outer.finish(out);
    }

    fn box_clone(&self) -> Box<dyn Hash> {
        Box::new(Self {
            inner: self.inner.box_clone(),
            outer: self.outer.box_clone(),
            state: self.state.box_clone(),
            keyed: self.keyed,
        })
    }
}
