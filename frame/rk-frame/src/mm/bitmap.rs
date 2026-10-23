//! A bitmap of physical frames.
//!
//! A set bit is a free frame. A new bitmap has no set bits, so each frame is in use until the
//! memory map adds it. Thus a mistake in the memory map can lose memory, but it cannot give the
//! same frame two times.
//!
//! This is the frame allocator of R0. The buddy allocator and the per CPU lists come in R1 and R4,
//! per spec/07-memory.md.

/// A bitmap for `WORDS * 64` frames.
pub(crate) struct FrameBitmap<const WORDS: usize> {
    bits: [u64; WORDS],
    total: usize,
    free: usize,
    /// No free frame is below this word. A new bitmap has the value 0, so that the bitmap is all
    /// zeros and goes in the bss and not in the kernel image.
    hint: usize,
}

impl<const WORDS: usize> FrameBitmap<WORDS> {
    /// The number of frames that the bitmap can hold.
    pub(crate) const CAPACITY: usize = WORDS * 64;

    /// Makes a bitmap with no free frames.
    pub(crate) const fn new() -> Self {
        Self { bits: [0; WORDS], total: 0, free: 0, hint: 0 }
    }

    /// Marks the frames `start..end` free. Frames past the capacity are ignored. Gives the number
    /// of frames that changed.
    pub(crate) fn add_free(&mut self, start: usize, end: usize) -> usize {
        let end = end.min(Self::CAPACITY);
        let mut n = 0;
        for f in start..end {
            let (w, b) = (f / 64, f % 64);
            if self.bits[w] & (1 << b) == 0 {
                self.bits[w] |= 1 << b;
                n += 1;
            }
        }
        self.total += n;
        self.free += n;
        self.hint = self.hint.min(start / 64);
        n
    }

    /// Marks the free frames in `start..end` as used for all of the run time. Gives the number of
    /// frames that changed.
    pub(crate) fn reserve(&mut self, start: usize, end: usize) -> usize {
        let end = end.min(Self::CAPACITY);
        let mut n = 0;
        for f in start..end {
            let (w, b) = (f / 64, f % 64);
            if self.bits[w] & (1 << b) != 0 {
                self.bits[w] &= !(1 << b);
                n += 1;
            }
        }
        self.total -= n;
        self.free -= n;
        n
    }

    /// Takes the free frame with the lowest number.
    pub(crate) fn alloc(&mut self) -> Option<usize> {
        let w = (self.hint..WORDS).find(|&w| self.bits[w] != 0)?;
        let b = self.bits[w].trailing_zeros() as usize;
        self.bits[w] &= !(1 << b);
        self.free -= 1;
        self.hint = w;
        Some(w * 64 + b)
    }

    /// Gives back a frame that `alloc` gave.
    ///
    /// # Panics
    ///
    /// If the frame is free already. A double free is a bug that can give one frame to two owners.
    pub(crate) fn free(&mut self, frame: usize) {
        let (w, b) = (frame / 64, frame % 64);
        assert!(self.bits[w] & (1 << b) == 0, "frame {frame:#x} is free already");
        self.bits[w] |= 1 << b;
        self.free += 1;
        self.hint = self.hint.min(w);
    }

    /// The number of frames that the allocator manages.
    pub(crate) fn total(&self) -> usize {
        self.total
    }

    /// The number of free frames.
    pub(crate) fn free_count(&self) -> usize {
        self.free
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_bitmap_has_no_free_frames() {
        let mut bm = FrameBitmap::<4>::new();
        assert_eq!(bm.alloc(), None);
        assert_eq!(bm.total(), 0);
    }

    #[test]
    fn alloc_gives_the_lowest_free_frame() {
        let mut bm = FrameBitmap::<4>::new();
        assert_eq!(bm.add_free(100, 110), 10);
        assert_eq!(bm.add_free(10, 12), 2);
        assert_eq!(bm.alloc(), Some(10));
        assert_eq!(bm.alloc(), Some(11));
        assert_eq!(bm.alloc(), Some(100));
        assert_eq!(bm.free_count(), 9);
        bm.free(10);
        assert_eq!(bm.alloc(), Some(10));
    }

    #[test]
    fn reserve_removes_free_frames() {
        let mut bm = FrameBitmap::<4>::new();
        bm.add_free(0, 256);
        assert_eq!(bm.reserve(0, 16), 16);
        assert_eq!(bm.reserve(0, 16), 0);
        assert_eq!(bm.total(), 240);
        assert_eq!(bm.alloc(), Some(16));
    }

    #[test]
    fn frames_past_the_capacity_are_ignored() {
        let mut bm = FrameBitmap::<1>::new();
        assert_eq!(bm.add_free(60, 1000), 4);
        assert_eq!(bm.total(), 4);
    }

    #[test]
    fn overlapping_ranges_count_one_time() {
        let mut bm = FrameBitmap::<2>::new();
        bm.add_free(0, 64);
        assert_eq!(bm.add_free(32, 96), 32);
        assert_eq!(bm.total(), 96);
    }

    #[test]
    fn all_frames_can_be_taken_and_given_back() {
        let mut bm = FrameBitmap::<2>::new();
        bm.add_free(0, 128);
        for want in 0..128 {
            assert_eq!(bm.alloc(), Some(want));
        }
        assert_eq!(bm.alloc(), None);
        for f in (0..128).rev() {
            bm.free(f);
        }
        assert_eq!(bm.free_count(), 128);
    }

    #[test]
    #[should_panic(expected = "free already")]
    fn a_double_free_panics() {
        let mut bm = FrameBitmap::<1>::new();
        bm.add_free(0, 8);
        assert_eq!(bm.alloc(), Some(0));
        bm.free(0);
        bm.free(0);
    }
}
