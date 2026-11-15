//! The extensible bitmap of SELinux, as security/selinux/ss/ebitmap.c of Linux.
//!
//! A bitmap keeps its bits in units of 64 bits. A unit has a start bit that is a multiple of 64,
//! and only the units with a bit that is set are kept, in the order of their start bits. The
//! policy uses bitmaps for the sets of types, roles and categories.

use crate::policydb::{Error, Reader};
use alloc::vec::Vec;

/// The number of bits in a unit.
const UNIT: u32 = 64;

/// A set of bit numbers.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Ebitmap {
    /// The units with a bit that is set, in the order of their start bits.
    units: Vec<(u32, u64)>,
}

impl Ebitmap {
    /// An empty bitmap.
    pub const fn new() -> Self {
        Self { units: Vec::new() }
    }

    /// Reads a bitmap of the binary policy, as `ebitmap_read` of Linux: the size of a unit (64),
    /// the high bit and the number of units, then for each unit its start bit and its 64 bits.
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let [mapunit, highbit, count] = r.u32s::<3>()?;
        if mapunit != UNIT {
            return Err(Error::Invalid("ebitmap map unit"));
        }
        let highbit = highbit.checked_add(UNIT - 1).ok_or(Error::Invalid("ebitmap high bit"))?;
        let highbit = highbit - highbit % UNIT;
        let mut units: Vec<(u32, u64)> = Vec::new();
        if highbit == 0 {
            return Ok(Self { units });
        }
        if count == 0 {
            return Err(Error::Invalid("ebitmap without units"));
        }
        for _ in 0..count {
            let start = r.u32()?;
            if start % UNIT != 0 || start > highbit - UNIT {
                return Err(Error::Invalid("ebitmap start bit"));
            }
            if units.last().is_some_and(|&(s, _)| start <= s) {
                return Err(Error::Invalid("ebitmap order"));
            }
            let map = r.u64()?;
            if map == 0 {
                return Err(Error::Invalid("ebitmap empty map"));
            }
            units.push((start, map));
        }
        Ok(Self { units })
    }

    /// Writes the bitmap in the format of the binary policy, as `ebitmap_write` of Linux.
    pub fn write(&self, out: &mut Vec<u8>) {
        let words = [UNIT, self.highbit(), self.units.len() as u32];
        for w in words {
            out.extend_from_slice(&w.to_le_bytes());
        }
        for &(start, map) in &self.units {
            out.extend_from_slice(&start.to_le_bytes());
            out.extend_from_slice(&map.to_le_bytes());
        }
    }

    /// Tells if the bit `bit` is set.
    pub fn get(&self, bit: u32) -> bool {
        let start = bit - bit % UNIT;
        match self.units.binary_search_by_key(&start, |u| u.0) {
            Ok(i) => self.units[i].1 & (1 << (bit % UNIT)) != 0,
            Err(_) => false,
        }
    }

    /// Sets or clears the bit `bit`.
    pub fn set(&mut self, bit: u32, value: bool) {
        let start = bit - bit % UNIT;
        let mask = 1u64 << (bit % UNIT);
        match self.units.binary_search_by_key(&start, |u| u.0) {
            Ok(i) => {
                if value {
                    self.units[i].1 |= mask;
                } else {
                    self.units[i].1 &= !mask;
                    if self.units[i].1 == 0 {
                        self.units.remove(i);
                    }
                }
            }
            Err(i) if value => self.units.insert(i, (start, mask)),
            Err(_) => {}
        }
    }

    /// The bit after the last unit, a multiple of 64, as the `highbit` of Linux.
    pub fn highbit(&self) -> u32 {
        self.units.last().map_or(0, |&(s, _)| s + UNIT)
    }

    /// Tells if no bit is set.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// The bits that are set, in increasing order.
    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.units.iter().flat_map(|&(start, map)| {
            (0..UNIT).filter(move |b| map & (1 << b) != 0).map(move |b| start + b)
        })
    }

    /// The number of bits that are set.
    pub fn len(&self) -> usize {
        self.units.iter().map(|u| u.1.count_ones() as usize).sum()
    }

    /// Tells if each bit of `other` is also set in `self`, as `ebitmap_contains` of Linux.
    pub fn contains(&self, other: &Self) -> bool {
        other.units.iter().all(|&(start, map)| {
            match self.units.binary_search_by_key(&start, |u| u.0) {
                Ok(i) => self.units[i].1 & map == map,
                Err(_) => false,
            }
        })
    }

    /// The bits that are set in both bitmaps, as `ebitmap_and` of Linux.
    pub fn and(&self, other: &Self) -> Self {
        let units = self
            .units
            .iter()
            .filter_map(|&(start, map)| {
                let i = other.units.binary_search_by_key(&start, |u| u.0).ok()?;
                let m = map & other.units[i].1;
                (m != 0).then_some((start, m))
            })
            .collect();
        Self { units }
    }

    /// Tells if a bit is set in both bitmaps.
    pub fn intersects(&self, other: &Self) -> bool {
        !self.and(other).is_empty()
    }

    /// Makes a bitmap from bit numbers.
    pub fn from_bits(bits: impl IntoIterator<Item = u32>) -> Self {
        let mut e = Self::new();
        for b in bits {
            e.set(b, true);
        }
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(words: &[u32], maps: &[(u32, u64)]) -> Vec<u8> {
        let mut out = Vec::new();
        for w in words {
            out.extend_from_slice(&w.to_le_bytes());
        }
        for (s, m) in maps {
            out.extend_from_slice(&s.to_le_bytes());
            out.extend_from_slice(&m.to_le_bytes());
        }
        out
    }

    #[test]
    fn a_bitmap_reads_and_writes_its_units() {
        let data = bytes(&[64, 192, 2], &[(0, 0b101), (128, 1 << 63)]);
        let e = Ebitmap::read(&mut Reader::new(&data)).unwrap();
        assert_eq!(e.iter().collect::<Vec<_>>(), [0, 2, 191]);
        assert!(e.get(191) && !e.get(1) && !e.get(500));
        assert_eq!(e.highbit(), 192);
        assert_eq!(e.len(), 3);
        let mut out = Vec::new();
        e.write(&mut out);
        assert_eq!(out, data);
    }

    #[test]
    fn a_bad_bitmap_is_an_error() {
        let bad = [
            bytes(&[32, 64, 1], &[(0, 1)]),
            bytes(&[64, 64, 0], &[]),
            bytes(&[64, 64, 1], &[(64, 1)]),
            bytes(&[64, 128, 2], &[(64, 1), (0, 1)]),
            bytes(&[64, 64, 1], &[(0, 0)]),
            bytes(&[64, 64, 1], &[]),
        ];
        for data in bad {
            assert!(Ebitmap::read(&mut Reader::new(&data)).is_err());
        }
        let empty = bytes(&[64, 0, 0], &[]);
        assert!(Ebitmap::read(&mut Reader::new(&empty)).unwrap().is_empty());
    }

    #[test]
    fn the_set_operations_work() {
        let mut a = Ebitmap::from_bits([1, 70, 200]);
        let b = Ebitmap::from_bits([70, 200]);
        assert!(a.contains(&b) && !b.contains(&a));
        assert_eq!(a.and(&Ebitmap::from_bits([1, 2])), Ebitmap::from_bits([1]));
        assert!(!b.intersects(&Ebitmap::from_bits([1])));
        a.set(1, false);
        assert_eq!(a, b);
        a.set(70, false);
        a.set(200, false);
        assert!(a.is_empty() && a.highbit() == 0);
    }
}
