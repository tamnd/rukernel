//! Tracked numbers, kernel/bpf/tnum.c of Linux.
//!
//! A tnum tells which bits of a value the verifier knows. A bit with 0 in `mask` has the value of
//! the same bit in `value`. A bit with 1 in `mask` is unknown, and its bit in `value` is 0.

/// A tracked number, `struct tnum` of Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tnum {
    /// The known bits.
    pub value: u64,
    /// The unknown bits.
    pub mask: u64,
}

/// A number with no known bits, `tnum_unknown` of Linux.
pub const TNUM_UNKNOWN: Tnum = Tnum { value: 0, mask: u64::MAX };

// The methods keep the names of Linux, so they are not the operator traits.
#[allow(clippy::should_implement_trait)]
impl Tnum {
    /// A known number, `tnum_const` of Linux.
    pub const fn constant(value: u64) -> Self {
        Self { value, mask: 0 }
    }

    /// The tnum of all numbers from `min` to `max`, `tnum_range` of Linux.
    pub fn range(min: u64, max: u64) -> Self {
        let chi = min ^ max;
        let bits = 64 - chi.leading_zeros();
        // The bits above the highest bit that changes are known.
        if bits > 63 {
            return TNUM_UNKNOWN;
        }
        let delta = (1u64 << bits) - 1;
        Self { value: min & !delta, mask: delta }
    }

    /// Tells if all bits are known, `tnum_is_const` of Linux.
    pub fn is_const(self) -> bool {
        self.mask == 0
    }

    /// `tnum_lshift` of Linux.
    pub fn lshift(self, shift: u32) -> Self {
        Self { value: self.value << shift, mask: self.mask << shift }
    }

    /// `tnum_rshift` of Linux.
    pub fn rshift(self, shift: u32) -> Self {
        Self { value: self.value >> shift, mask: self.mask >> shift }
    }

    /// `tnum_arshift` of Linux. `bits` is 32 or 64.
    pub fn arshift(self, shift: u32, bits: u32) -> Self {
        if bits == 32 {
            Self {
                value: ((self.value as i32) >> shift) as u32 as u64,
                mask: ((self.mask as i32) >> shift) as u32 as u64,
            }
        } else {
            Self {
                value: ((self.value as i64) >> shift) as u64,
                mask: ((self.mask as i64) >> shift) as u64,
            }
        }
    }

    /// `tnum_add` of Linux.
    pub fn add(self, b: Self) -> Self {
        let sm = self.mask.wrapping_add(b.mask);
        let sv = self.value.wrapping_add(b.value);
        let sigma = sm.wrapping_add(sv);
        let chi = sigma ^ sv;
        let mu = chi | self.mask | b.mask;
        Self { value: sv & !mu, mask: mu }
    }

    /// `tnum_sub` of Linux.
    pub fn sub(self, b: Self) -> Self {
        let dv = self.value.wrapping_sub(b.value);
        let alpha = dv.wrapping_add(self.mask);
        let beta = dv.wrapping_sub(b.mask);
        let chi = alpha ^ beta;
        let mu = chi | self.mask | b.mask;
        Self { value: dv & !mu, mask: mu }
    }

    /// `tnum_neg` of Linux.
    pub fn neg(self) -> Self {
        Tnum::constant(0).sub(self)
    }

    /// `tnum_and` of Linux.
    pub fn and(self, b: Self) -> Self {
        let alpha = self.value | self.mask;
        let beta = b.value | b.mask;
        let v = self.value & b.value;
        Self { value: v, mask: alpha & beta & !v }
    }

    /// `tnum_or` of Linux.
    pub fn or(self, b: Self) -> Self {
        let v = self.value | b.value;
        let mu = self.mask | b.mask;
        Self { value: v, mask: mu & !v }
    }

    /// `tnum_xor` of Linux.
    pub fn xor(self, b: Self) -> Self {
        let v = self.value ^ b.value;
        let mu = self.mask | b.mask;
        Self { value: v & !mu, mask: mu }
    }

    /// `tnum_mul` of Linux.
    pub fn mul(self, b: Self) -> Self {
        let mut a = self;
        let mut b = b;
        let acc_v = a.value.wrapping_mul(b.value);
        let mut acc_m = Tnum::constant(0);
        while a.value != 0 || a.mask != 0 {
            if a.value & 1 != 0 {
                acc_m = acc_m.add(Tnum { value: 0, mask: b.mask });
            } else if a.mask & 1 != 0 {
                acc_m = acc_m.add(Tnum { value: 0, mask: b.value | b.mask });
            }
            a = a.rshift(1);
            b = b.lshift(1);
        }
        Tnum::constant(acc_v).add(acc_m)
    }

    /// Keeps the low `size` bytes, `tnum_cast` of Linux.
    pub fn cast(self, size: u32) -> Self {
        if size >= 8 {
            return self;
        }
        let keep = (1u64 << (size * 8)) - 1;
        Self { value: self.value & keep, mask: self.mask & keep }
    }

    /// The low 32 bits, `tnum_subreg` of Linux.
    pub fn subreg(self) -> Self {
        self.cast(4)
    }

    /// The smallest number that the tnum can be.
    pub fn min(self) -> u64 {
        self.value
    }

    /// The largest number that the tnum can be.
    pub fn max(self) -> u64 {
        self.value | self.mask
    }

    /// Tells if `self` and `b` can be the same number, as `tnum_intersect` that is not empty.
    pub fn can_equal(self, b: Self) -> bool {
        let mu = self.mask | b.mask;
        (self.value & !mu) == (b.value & !mu)
    }

    /// The tnum of the numbers that are in both, `tnum_intersect` of Linux.
    pub fn intersect(self, b: Self) -> Self {
        let v = self.value | b.value;
        let mu = self.mask & b.mask;
        Self { value: v & !mu, mask: mu }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_stay_constant() {
        let a = Tnum::constant(6);
        let b = Tnum::constant(3);
        assert_eq!(a.add(b), Tnum::constant(9));
        assert_eq!(a.sub(b), Tnum::constant(3));
        assert_eq!(a.and(b), Tnum::constant(2));
        assert_eq!(a.or(b), Tnum::constant(7));
        assert_eq!(a.xor(b), Tnum::constant(5));
        assert_eq!(a.mul(b), Tnum::constant(18));
        assert_eq!(a.lshift(2), Tnum::constant(24));
    }

    #[test]
    fn a_range_knows_the_high_bits() {
        let r = Tnum::range(0, 255);
        assert_eq!(r, Tnum { value: 0, mask: 255 });
        assert_eq!(r.max(), 255);
        assert_eq!(r.and(Tnum::constant(0xf)).max(), 0xf);
        assert_eq!(Tnum::range(0, u64::MAX), TNUM_UNKNOWN);
    }

    #[test]
    fn a_mask_with_and_limits_the_value() {
        let x = TNUM_UNKNOWN.and(Tnum::constant(7));
        assert_eq!(x.max(), 7);
        assert!(x.can_equal(Tnum::constant(5)));
        assert!(!x.can_equal(Tnum::constant(8)));
    }
}
