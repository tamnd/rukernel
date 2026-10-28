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

    /// Takes `1 << order` free frames in a row, where the first frame number is a multiple of
    /// `1 << order`. The search starts at the top, so that the frames that `alloc` takes from the
    /// bottom do not break the runs. Gives the first frame.
    pub(crate) fn alloc_run(&mut self, order: u32) -> Option<usize> {
        if order < 6 {
            return self.alloc_short_run(order);
        }
        let words = (1usize << order) / 64;
        let run = (0..WORDS / words)
            .rev()
            .find(|&r| self.bits[r * words..(r + 1) * words].iter().all(|&w| w == u64::MAX))?;
        self.bits[run * words..(run + 1) * words].fill(0);
        self.free -= words * 64;
        Some(run * words * 64)
    }

    /// Takes `1 << order` free frames in a row, where the first frame number is a multiple of
    /// `1 << order` and `order` is less than 6, so the run is in one word. The search starts at
    /// the lowest free frame, as `alloc` does. Gives the first frame.
    pub(crate) fn alloc_small_run(&mut self, order: u32) -> Option<usize> {
        assert!(order < 6, "a run of order {order} is longer than a word");
        let n = 1usize << order;
        let mask = u64::MAX >> (64 - n);
        for w in self.hint..WORDS {
            let bits = self.bits[w];
            if bits == 0 {
                continue;
            }
            if let Some(shift) = (0..64).step_by(n).find(|&s| (bits >> s) & mask == mask) {
                self.bits[w] &= !(mask << shift);
                self.free -= n;
                return Some(w * 64 + shift);
            }
        }
        None
    }

    /// `alloc_run` for a run in one word.
    fn alloc_short_run(&mut self, order: u32) -> Option<usize> {
        let len = 1usize << order;
        let mask = if len == 64 { u64::MAX } else { (1u64 << len) - 1 };
        for w in (0..WORDS).rev() {
            let word = self.bits[w];
            if word == 0 {
                continue;
            }
            if let Some(at) = (0..64).step_by(len).rev().find(|&at| word >> at & mask == mask) {
                self.bits[w] &= !(mask << at);
                self.free -= len;
                return Some(w * 64 + at);
            }
        }
        None
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
    fn alloc_run_takes_an_aligned_free_run() {
        let mut bm = FrameBitmap::<32>::new();
        bm.add_free(100, 1100);
        // The run at 512 is the only aligned run of 512 free frames.
        assert_eq!(bm.alloc_run(9), Some(512));
        assert_eq!(bm.free_count(), 1000 - 512);
        assert_eq!(bm.alloc_run(9), None);
        for f in 512..1024 {
            bm.free(f);
        }
        assert_eq!(bm.free_count(), 1000);
        assert_eq!(bm.alloc(), Some(100));
    }

    #[test]
    fn alloc_small_run_takes_an_aligned_run_in_a_word() {
        let mut bm = FrameBitmap::<4>::new();
        bm.add_free(1, 10);
        bm.add_free(70, 80);
        // Frames 1 to 3 are free, but the first aligned run of 4 starts at 4.
        assert_eq!(bm.alloc_small_run(2), Some(4));
        assert_eq!(bm.alloc_small_run(2), Some(72));
        assert_eq!(bm.alloc_small_run(1), Some(2));
        assert_eq!(bm.alloc_small_run(3), None);
        assert_eq!(bm.free_count(), 19 - 10);
        assert_eq!(bm.alloc_small_run(0), Some(1));
        for f in 4..8 {
            bm.free(f);
        }
        assert_eq!(bm.alloc_small_run(2), Some(4));
    }

    #[test]
    fn alloc_run_takes_a_short_aligned_run() {
        let mut bm = FrameBitmap::<2>::new();
        bm.add_free(3, 40);
        // The highest aligned run of 16 free frames is at 16, and the next is lower.
        assert_eq!(bm.alloc_run(4), Some(16));
        assert_eq!(bm.alloc_run(4), None);
        assert_eq!(bm.alloc_run(2), Some(36));
        assert_eq!(bm.alloc_run(0), Some(35));
        assert_eq!(bm.free_count(), 37 - 16 - 4 - 1);
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
