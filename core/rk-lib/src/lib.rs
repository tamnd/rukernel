//! Safe helpers for the kernel crates of rukernel.
//!
//! This crate contains no `unsafe` code. Each helper reports an overflow and does not wrap.

#![no_std]
#![forbid(unsafe_code)]

/// Moves `value` up to the next multiple of `align`.
///
/// Gives `None` if `align` is not a power of two or if the result does not fit in `usize`.
pub const fn align_up(value: usize, align: usize) -> Option<usize> {
    if !align.is_power_of_two() {
        return None;
    }
    match value.checked_add(align - 1) {
        Some(v) => Some(v & !(align - 1)),
        None => None,
    }
}

/// Moves `value` down to the previous multiple of `align`.
///
/// Gives `None` if `align` is not a power of two.
pub const fn align_down(value: usize, align: usize) -> Option<usize> {
    if align.is_power_of_two() { Some(value & !(align - 1)) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align() {
        assert_eq!(align_up(0, 4096), Some(0));
        assert_eq!(align_up(1, 4096), Some(4096));
        assert_eq!(align_up(4096, 4096), Some(4096));
        assert_eq!(align_up(usize::MAX, 4096), None);
        assert_eq!(align_up(10, 3), None);
        assert_eq!(align_down(4097, 4096), Some(4096));
        assert_eq!(align_down(10, 0), None);
    }
}
