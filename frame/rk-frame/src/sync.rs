//! Raw synchronization primitives.
//!
//! These are the lowest locks of the kernel, per spec/03-architecture.md section 3.5. The kernel
//! runs with interrupts off, so a lock does not turn interrupts off. The CPUs run kernel code at
//! the same time, so a lock can be held by another CPU.
//!
//! A CPU that spins on a lock does the TLB requests of the other CPUs while it waits. The CPU that
//! holds the lock can wait for such a request, for example after it changed a page table, and the
//! waiting CPU has interrupts off, so it would not see the interrupt of the request.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

/// A spin lock that protects a value of type `T`.
pub struct SpinLock<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: the lock gives one `&mut T` at a time, so a `SpinLock<T>` can be shared between CPUs
// when `T` can be sent between them.
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// Makes an unlocked lock.
    pub const fn new(value: T) -> Self {
        Self { locked: AtomicBool::new(false), value: UnsafeCell::new(value) }
    }

    /// Takes the lock. The CPU spins until the lock is free, and does the TLB requests of the
    /// other CPUs while it spins.
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                wait_hint();
            }
        }
        SpinLockGuard { lock: self }
    }

    /// Gives the value and drops the lock. The caller owns the lock, so no other CPU holds it.
    pub fn into_inner(self) -> T {
        self.value.into_inner()
    }

    /// Takes the lock if it is free.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| SpinLockGuard { lock: self })
    }
}

/// One step of a spin loop. On the kernel, the CPU also does the TLB requests of the other CPUs,
/// as the wait of `smp_call_function` of Linux does with interrupts on. Each spin loop of the
/// kernel must use it: the CPU that the loop waits for can wait for a TLB request of this CPU.
#[inline]
pub fn wait_hint() {
    #[cfg(all(target_os = "none", any(target_arch = "x86_64", target_arch = "aarch64")))]
    crate::arch::imp::smp::poll();
    core::hint::spin_loop();
}

/// The guard of a held `SpinLock`. The lock is released when the guard is dropped.
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard exists only while this CPU holds the lock.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard exists only while this CPU holds the lock, and `&mut self` makes sure
        // that there is one mutable reference.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

/// The state of a [`RwLock`] that a writer holds.
const WRITER: u32 = 1 << 31;
/// A writer waits. New readers wait until it had the lock, so a stream of readers cannot keep a
/// writer out.
const WRITER_WAITS: u32 = 1 << 30;

/// A spin lock that many readers or one writer can hold, as the `rwlock_t` of Linux. A writer that
/// waits stops new readers. A CPU that spins does the TLB requests of the other CPUs, as with
/// [`SpinLock`].
pub struct RwLock<T> {
    /// The number of readers in the low bits, and `WRITER` and `WRITER_WAITS`.
    state: AtomicU32,
    value: UnsafeCell<T>,
}

// SAFETY: a writer gets one `&mut T` with no readers, and readers get `&T` at the same time on
// different CPUs. Thus `T` must be `Send` for the writer and `Sync` for the readers.
unsafe impl<T: Send + Sync> Sync for RwLock<T> {}

impl<T> RwLock<T> {
    /// Makes an unlocked lock.
    pub const fn new(value: T) -> Self {
        Self { state: AtomicU32::new(0), value: UnsafeCell::new(value) }
    }

    /// Takes the lock for a read. The CPU spins while a writer holds the lock or waits for it.
    pub fn read(&self) -> ReadGuard<'_, T> {
        loop {
            let s = self.state.load(Ordering::Relaxed);
            if s & (WRITER | WRITER_WAITS) == 0
                && self
                    .state
                    .compare_exchange_weak(s, s + 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                return ReadGuard { lock: self };
            }
            wait_hint();
        }
    }

    /// Takes the lock for a write. The CPU spins until no reader and no writer holds the lock.
    pub fn write(&self) -> WriteGuard<'_, T> {
        loop {
            let s = self.state.load(Ordering::Relaxed);
            if s & !WRITER_WAITS == 0 {
                if self
                    .state
                    .compare_exchange_weak(s, WRITER, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return WriteGuard { lock: self };
                }
            } else if s & WRITER_WAITS == 0 {
                self.state.fetch_or(WRITER_WAITS, Ordering::Relaxed);
            }
            wait_hint();
        }
    }

    /// Takes the lock for a write if no reader and no writer holds it.
    pub fn try_write(&self) -> Option<WriteGuard<'_, T>> {
        let s = self.state.load(Ordering::Relaxed);
        (s & !WRITER_WAITS == 0)
            .then(|| self.state.compare_exchange(s, WRITER, Ordering::Acquire, Ordering::Relaxed))
            .and_then(Result::ok)
            .map(|_| WriteGuard { lock: self })
    }
}

/// The guard of a [`RwLock`] that a reader holds.
pub struct ReadGuard<'a, T> {
    lock: &'a RwLock<T>,
}

impl<T> Deref for ReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard exists only while no writer holds the lock.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> Drop for ReadGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.state.fetch_sub(1, Ordering::Release);
    }
}

/// The guard of a [`RwLock`] that a writer holds.
pub struct WriteGuard<'a, T> {
    lock: &'a RwLock<T>,
}

impl<T> Deref for WriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard exists only while this CPU holds the lock and no reader holds it.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for WriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as for `deref`, and `&mut self` makes sure that there is one mutable reference.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for WriteGuard<'_, T> {
    fn drop(&mut self) {
        // Another writer can have set `WRITER_WAITS`, and it stays.
        self.lock.state.fetch_and(!WRITER, Ordering::Release);
    }
}

const EMPTY: u8 = 0;
const RUNNING: u8 = 1;
const DONE: u8 = 2;

/// A value that is set one time and then only read.
pub struct Once<T> {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: the value is written one time before `DONE` is published with release ordering, and then
// it is only read. Thus a `&Once<T>` can be shared when `T` can be shared and sent.
unsafe impl<T: Send + Sync> Sync for Once<T> {}

impl<T> Once<T> {
    /// Makes an empty value.
    pub const fn new() -> Self {
        Self { state: AtomicU8::new(EMPTY), value: UnsafeCell::new(MaybeUninit::uninit()) }
    }

    /// Sets the value with `f` if it is empty, and gives the value. A second caller waits until
    /// the first caller finishes.
    pub fn call_once(&self, f: impl FnOnce() -> T) -> &T {
        if self.state.compare_exchange(EMPTY, RUNNING, Ordering::Acquire, Ordering::Acquire).is_ok()
        {
            // SAFETY: only the caller that moved the state from EMPTY to RUNNING writes the value,
            // and no reader reads it before the state is DONE.
            unsafe { (*self.value.get()).write(f()) };
            self.state.store(DONE, Ordering::Release);
        }
        while self.state.load(Ordering::Acquire) != DONE {
            wait_hint();
        }
        // SAFETY: the state is DONE.
        unsafe { self.value_ref() }
    }

    /// Gives the value if it is set.
    pub fn get(&self) -> Option<&T> {
        if self.state.load(Ordering::Acquire) == DONE {
            // SAFETY: the state is DONE.
            Some(unsafe { self.value_ref() })
        } else {
            None
        }
    }
}

impl<T> Once<T> {
    /// Gives the value.
    ///
    /// # Safety
    ///
    /// The state must be DONE. Then the value is initialized and is never written again.
    unsafe fn value_ref(&self) -> &T {
        // SAFETY: the caller makes sure that no writer exists, so a shared reference is valid.
        let slot = unsafe { &*self.value.get() };
        // SAFETY: the caller makes sure that the value is initialized.
        unsafe { slot.assume_init_ref() }
    }
}

impl<T> Default for Once<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_gives_one_guard_at_a_time() {
        let lock = SpinLock::new(1);
        let mut guard = lock.lock();
        *guard += 1;
        assert!(lock.try_lock().is_none());
        drop(guard);
        assert_eq!(*lock.lock(), 2);
    }

    #[test]
    fn rwlock_gives_many_readers_or_one_writer() {
        let lock = RwLock::new(1);
        let a = lock.read();
        let b = lock.read();
        assert_eq!(*a + *b, 2);
        assert!(lock.try_write().is_none());
        drop((a, b));
        let mut w = lock.try_write().unwrap_or_else(|| panic!("the lock is free"));
        *w = 3;
        assert!(lock.try_write().is_none());
        drop(w);
        assert_eq!(*lock.read(), 3);
    }

    #[test]
    fn a_waiting_writer_stops_new_readers() {
        let lock = RwLock::new(0);
        let r = lock.read();
        lock.state.fetch_or(WRITER_WAITS, Ordering::Relaxed);
        // A new reader would spin now. The writer gets the lock when the reader goes.
        assert_eq!(lock.state.load(Ordering::Relaxed) & !WRITER_WAITS, 1);
        drop(r);
        let w = lock.write();
        assert_eq!(lock.state.load(Ordering::Relaxed), WRITER);
        drop(w);
        assert_eq!(lock.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn rwlock_counts_on_threads() {
        extern crate std;
        let lock = std::sync::Arc::new(RwLock::new(0u64));
        let threads: std::vec::Vec<_> = (0..4)
            .map(|i| {
                let lock = lock.clone();
                std::thread::spawn(move || {
                    for _ in 0..2000 {
                        if i % 2 == 0 {
                            *lock.write() += 1;
                        } else {
                            let v = *lock.read();
                            assert!(v <= 4000);
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap_or_else(|_| panic!("a thread failed"));
        }
        assert_eq!(*lock.read(), 4000);
    }

    #[test]
    fn once_sets_the_value_one_time() {
        let once = Once::new();
        assert!(once.get().is_none());
        assert_eq!(*once.call_once(|| 7), 7);
        assert_eq!(*once.call_once(|| 8), 7);
        assert_eq!(once.get(), Some(&7));
    }
}
