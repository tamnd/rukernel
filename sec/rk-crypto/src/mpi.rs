//! Unsigned integers of any size for RSA and Diffie-Hellman, as lib/crypto/mpi of Linux.
//!
//! An [`Mpi`] keeps its value in limbs of 64 bits, the low limb first, with no zero limb at the
//! top. The modular exponentiation uses the Montgomery form when the modulus is odd, as the
//! moduli of RSA and the primes of Diffie-Hellman are. An even modulus uses a slower reduction
//! bit by bit.

use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;

/// An unsigned integer, as `MPI` of Linux.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mpi {
    d: Vec<u64>,
}

impl Mpi {
    /// The value 0.
    pub fn zero() -> Self {
        Mpi { d: Vec::new() }
    }

    /// The value `v`.
    pub fn from_u64(v: u64) -> Self {
        let mut m = Mpi { d: vec![v] };
        m.norm();
        m
    }

    /// The value of the big-endian bytes `b`, as `mpi_read_raw_data`. Zero bytes at the start
    /// have no effect.
    pub fn from_be(b: &[u8]) -> Self {
        let mut d = vec![0u64; b.len().div_ceil(8)];
        for (i, &byte) in b.iter().rev().enumerate() {
            d[i / 8] |= u64::from(byte) << (8 * (i % 8));
        }
        let mut m = Mpi { d };
        m.norm();
        m
    }

    fn norm(&mut self) {
        while self.d.last() == Some(&0) {
            self.d.pop();
        }
    }

    /// True for the value 0.
    pub fn is_zero(&self) -> bool {
        self.d.is_empty()
    }

    /// True for an odd value.
    pub fn is_odd(&self) -> bool {
        self.d.first().is_some_and(|&w| w & 1 == 1)
    }

    /// The number of significant bits, as `mpi_get_nbits`.
    pub fn bits(&self) -> usize {
        match self.d.last() {
            None => 0,
            Some(&top) => self.d.len() * 64 - top.leading_zeros() as usize,
        }
    }

    /// The number of significant bytes, as `mpi_get_size`.
    pub fn byte_len(&self) -> usize {
        self.bits().div_ceil(8)
    }

    /// Bit `i`, where bit 0 is the least significant bit.
    pub fn bit(&self, i: usize) -> bool {
        self.d.get(i / 64).is_some_and(|&w| (w >> (i % 64)) & 1 == 1)
    }

    /// The value in big-endian bytes, with no zero byte at the start, as `mpi_get_buffer`.
    pub fn to_be(&self) -> Vec<u8> {
        self.to_be_padded(self.byte_len()).unwrap_or_default()
    }

    /// The value in `len` big-endian bytes, with zero bytes at the start, as
    /// `mpi_write_to_sgl`. Gives `None` if the value does not fit.
    pub fn to_be_padded(&self, len: usize) -> Option<Vec<u8>> {
        let n = self.byte_len();
        if n > len {
            return None;
        }
        let mut out = vec![0u8; len];
        for i in 0..n {
            out[len - 1 - i] = (self.d[i / 8] >> (8 * (i % 8))) as u8;
        }
        Some(out)
    }

    /// `self - 1`. Gives 0 for 0.
    pub fn sub_one(&self) -> Self {
        let mut r = self.clone();
        for w in &mut r.d {
            let (v, borrow) = w.overflowing_sub(1);
            *w = v;
            if !borrow {
                break;
            }
        }
        r.norm();
        r
    }

    /// `self mod m`, bit by bit. `m` must not be 0.
    pub fn rem(&self, m: &Mpi) -> Mpi {
        if m.is_zero() || self.cmp(m) == Ordering::Less {
            return if m.is_zero() { Mpi::zero() } else { self.clone() };
        }
        let mut r = vec![0u64; m.d.len() + 1];
        for i in (0..self.bits()).rev() {
            shl1(&mut r, self.bit(i));
            if cmp_limbs(&r, &m.d) != Ordering::Less {
                sub_in(&mut r, &m.d);
            }
        }
        let mut r = Mpi { d: r };
        r.norm();
        r
    }

    /// `self * other`.
    pub fn mul(&self, other: &Mpi) -> Mpi {
        let mut r = vec![0u64; self.d.len() + other.d.len()];
        for (i, &a) in self.d.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &b) in other.d.iter().enumerate() {
                let t = u128::from(a) * u128::from(b) + u128::from(r[i + j]) + carry;
                r[i + j] = t as u64;
                carry = t >> 64;
            }
            r[i + other.d.len()] = carry as u64;
        }
        let mut r = Mpi { d: r };
        r.norm();
        r
    }

    /// `self^exp mod m`, as `mpi_powm`. A modulus of 0 gives 0.
    pub fn pow_mod(&self, exp: &Mpi, m: &Mpi) -> Mpi {
        if m.is_zero() || *m == Mpi::from_u64(1) {
            return Mpi::zero();
        }
        let base = self.rem(m);
        if m.is_odd() {
            return Mont::new(m).pow(&base, exp);
        }
        let mut r = Mpi::from_u64(1);
        for i in (0..exp.bits()).rev() {
            r = r.mul(&r).rem(m);
            if exp.bit(i) {
                r = r.mul(&base).rem(m);
            }
        }
        r
    }
}

impl PartialOrd for Mpi {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Mpi {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_limbs(&self.d, &other.d)
    }
}

/// Compares two values in limbs, which can have zero limbs at the top.
fn cmp_limbs(a: &[u64], b: &[u64]) -> Ordering {
    let n = a.len().max(b.len());
    for i in (0..n).rev() {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x.cmp(&y);
        }
    }
    Ordering::Equal
}

/// `a = a * 2 + low`. The top bit goes out.
fn shl1(a: &mut [u64], low: bool) {
    let mut carry = u64::from(low);
    for w in a {
        let top = *w >> 63;
        *w = (*w << 1) | carry;
        carry = top;
    }
}

/// `a = a - b`, with `a >= b`.
fn sub_in(a: &mut [u64], b: &[u64]) {
    let mut borrow = false;
    for (i, w) in a.iter_mut().enumerate() {
        let y = b.get(i).copied().unwrap_or(0);
        let (v1, b1) = w.overflowing_sub(y);
        let (v2, b2) = v1.overflowing_sub(u64::from(borrow));
        *w = v2;
        borrow = b1 || b2;
    }
}

/// The Montgomery form of an odd modulus `m` with `n` limbs: values are `x * R mod m` with
/// `R = 2^(64n)`.
struct Mont<'a> {
    m: &'a [u64],
    /// `-m^-1 mod 2^64`.
    inv: u64,
    /// `R^2 mod m`.
    r2: Vec<u64>,
}

impl<'a> Mont<'a> {
    fn new(m: &'a Mpi) -> Self {
        let m0 = m.d[0];
        // Newton's iteration: each step doubles the correct low bits of the inverse.
        let mut x: u64 = 1;
        for _ in 0..6 {
            x = x.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(x)));
        }
        let n = m.d.len();
        let mut r = vec![0u64; n + 1];
        r[0] = 1;
        for _ in 0..128 * n {
            shl1(&mut r, false);
            if cmp_limbs(&r, &m.d) != Ordering::Less {
                sub_in(&mut r, &m.d);
            }
        }
        r.truncate(n);
        Mont { m: &m.d, inv: x.wrapping_neg(), r2: r }
    }

    /// `a * b / R mod m`, as the CIOS method. `a` and `b` have `n` limbs and are less than `m`.
    fn mul(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let n = self.m.len();
        let mut t = vec![0u64; n + 2];
        for &bi in b.iter().take(n) {
            let mut c = 0u128;
            for j in 0..n {
                let s = u128::from(t[j]) + u128::from(a[j]) * u128::from(bi) + c;
                t[j] = s as u64;
                c = s >> 64;
            }
            let s = u128::from(t[n]) + c;
            t[n] = s as u64;
            t[n + 1] = (s >> 64) as u64;
            let u = t[0].wrapping_mul(self.inv);
            let s = u128::from(t[0]) + u128::from(u) * u128::from(self.m[0]);
            let mut c = s >> 64;
            for j in 1..n {
                let s = u128::from(t[j]) + u128::from(u) * u128::from(self.m[j]) + c;
                t[j - 1] = s as u64;
                c = s >> 64;
            }
            let s = u128::from(t[n]) + c;
            t[n - 1] = s as u64;
            t[n] = t[n + 1] + (s >> 64) as u64;
        }
        t.truncate(n + 1);
        if cmp_limbs(&t, self.m) != Ordering::Less {
            sub_in(&mut t, self.m);
        }
        t.truncate(n);
        t
    }

    /// `base^exp mod m`, with `base < m`.
    fn pow(&self, base: &Mpi, exp: &Mpi) -> Mpi {
        let n = self.m.len();
        let mut b = base.d.clone();
        b.resize(n, 0);
        let b = self.mul(&b, &self.r2);
        let mut one = vec![0u64; n];
        one[0] = 1;
        let mut r = self.mul(&one, &self.r2);
        for i in (0..exp.bits()).rev() {
            r = self.mul(&r, &r);
            if exp.bit(i) {
                r = self.mul(&r, &b);
            }
        }
        let mut r = Mpi { d: self.mul(&r, &one) };
        r.norm();
        r
    }
}
